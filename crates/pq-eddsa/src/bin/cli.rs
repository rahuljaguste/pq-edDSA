//! Prove and verify the `R_det` and `R_rand` relations.
//!
//! Argument layout matches SoundnessLabs/PQChain so the two can be compared directly,
//! which is also why `--relation` defaults to `det`.

use anyhow::{Context, Result, bail};
use binius_frontend::CircuitBuilder;
use binius_verifier::transcript::{ProverTranscript, VerifierTranscript};
use clap::{Parser, Subcommand};
use pq_eddsa::{
    circuit::{PqEddsaCircuit, PublicInputs, Relation, public_words},
    config::{Challenger, DEFAULT_SECURITY_BITS, ProofConfig},
};

/// Help text differs by build, because the soundness claim does. Interpolating the
/// constant is not possible in a `#[command]` attribute, so the two are written out.
#[cfg(not(feature = "wide"))]
const LONG_ABOUT: &str = "Prove EdDSA key ownership from a seed, in zero knowledge.\n\n\
    UNAUDITED RESEARCH PROOF OF CONCEPT. Carries 96-bit classical soundness and ~48-bit \
    quantum, below the ~128 you should want in production, and its zero-knowledge \
    property has not been audited. Use throwaway keys only.\n\n\
    --seed puts the key on the command line, where your shell records it in history. \
    Prefer --seed-file, or `--seed-file -` to read it from stdin.";

#[cfg(feature = "wide")]
const LONG_ABOUT: &str = "Prove EdDSA key ownership from a seed, in zero knowledge.\n\n\
    UNAUDITED RESEARCH PROOF OF CONCEPT, built with --features wide: GF(2^256) \
    challenges and SHA-512 commitments, from an unmerged fork of Binius64. The query \
    target defaults to 240, which is where logUp* binds: the achieved level is ~240 \
    classical and ~120 quantum, and asking for more only costs proof size. That figure rests on unaudited work; the narrow build \
    rests on a constant in upstream. Use throwaway keys only.\n\n\
    --seed puts the key on the command line, where your shell records it in history. \
    Prefer --seed-file, or `--seed-file -` to read it from stdin.";

#[derive(Parser)]
#[command(
    name = "pq-eddsa",
    about = "Prove EdDSA key ownership from a seed, in zero knowledge",
    long_about = LONG_ABOUT
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

/// Which form of the relation to prove. `det` matches PQChain and is used for benchmark
/// parity; `rand` is the relation the paper's Theorem 2 is proved over.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum RelationArg {
    Det,
    Rand,
}

impl From<RelationArg> for Relation {
    fn from(r: RelationArg) -> Self {
        match r {
            RelationArg::Det => Relation::Det,
            RelationArg::Rand => Relation::Rand,
        }
    }
}

impl RelationArg {
    /// The `--relation` value that reproduces this choice, for the hints below.
    fn as_flag(self) -> &'static str {
        match self {
            RelationArg::Det => "det",
            RelationArg::Rand => "rand",
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a proof.
    Prove {
        /// 32-byte seed, hex. PRIVATE — the proof never reveals it, but passing it here
        /// puts it in your shell history. Prefer --seed-file.
        #[arg(
            long,
            conflicts_with = "seed_file",
            required_unless_present = "seed_file"
        )]
        seed: Option<String>,
        /// Read the 32-byte hex seed from a file, or from stdin with `-`. Keeps the seed
        /// out of argv, and so out of shell history and `ps`.
        #[arg(long)]
        seed_file: Option<String>,
        /// 32-byte message, hex. Defaults to all zeros.
        #[arg(long)]
        msg: Option<String>,
        /// Where to write the proof.
        #[arg(long)]
        out: Option<String>,
        #[arg(long, default_value_t = 1)]
        log_inv_rate: usize,
        /// FRI query-phase target in bits. Spike branch only; upstream hardcodes 96.
        #[arg(long, default_value_t = pq_eddsa::config::DEFAULT_SECURITY_BITS)]
        security_bits: usize,
        /// Relation to prove. `rand` randomises hx with a fresh secret, which is what
        /// the paper's security proof requires; `det` matches PQChain.
        #[arg(long, value_enum, default_value = "det")]
        relation: RelationArg,
    },
    /// Verify a proof against public inputs.
    Verify {
        #[arg(long)]
        proof: String,
        #[arg(long)]
        pk: String,
        #[arg(long)]
        msg: Option<String>,
        #[arg(long)]
        hx: String,
        #[arg(long, default_value_t = 1)]
        log_inv_rate: usize,
        /// Must match what the proof was produced under.
        #[arg(long, default_value_t = pq_eddsa::config::DEFAULT_SECURITY_BITS)]
        security_bits: usize,
        /// Must match the relation the proof was produced under.
        #[arg(long, value_enum, default_value = "det")]
        relation: RelationArg,
    },
    /// Print circuit statistics without proving.
    Stat {
        #[arg(long, value_enum, default_value = "det")]
        relation: RelationArg,
    },
}

fn parse_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    // Trim before decoding: a seed read from a file arrives with a trailing newline, and
    // a pasted one often carries stray whitespace.
    let raw = hex::decode(s.trim().trim_start_matches("0x"))
        .with_context(|| format!("{what} is not valid hex"))?;
    if raw.len() != N {
        bail!("{what} must be {N} bytes, got {}", raw.len());
    }
    Ok(raw.try_into().unwrap())
}

/// Which build produced or is checking a proof. A fourth setting that has to match and
/// that no flag can change, since the field, hash suite and challenger are chosen at
/// compile time.
fn build_name() -> &'static str {
    if pq_eddsa::config::IS_WIDE {
        "wide"
    } else {
        "narrow"
    }
}

/// The exact command that verifies the proof just written.
///
/// A proof file is raw transcript bytes and records none of the settings it was made
/// under. Get any of them wrong at verification time and the failure is the one a forged
/// proof gives — `--relation rand` proved and checked as `det` is indistinguishable from
/// a flipped bit in `pk`. Printing the command next to the file is the cheapest place to
/// keep them together.
///
/// # Deliberately not a self-describing proof envelope
///
/// This puts the settings *beside* the file rather than *in* it, so separating the two
/// still loses them. Judged not worth closing: a proof made with the defaults verifies
/// from a bare `--proof --pk --hx` with no metadata at all, prove and verify usually
/// happen minutes apart in one session, and nothing here is a protocol, so proof files
/// have no reason to travel. The one path that did cross a tool boundary by default is
/// the browser demo, which proves `rand` while this CLI defaults to `det` — covered by
/// this hint and by the equivalent one in `web/main.js`.
///
/// If that changes and an envelope is added, two things are worth keeping:
///
/// - **Compare the stored settings against the caller's, never adopt them.** The prover
///   writes the file, so adopting means the prover picks which statement gets checked: a
///   proof of `R_det` labelled `det` would satisfy a caller who asked for `R_rand`, and a
///   stored `security_bits` of 96 would silently downgrade a caller who asked for 240.
/// - **Leave the public inputs out.** Comparing them is harmless but redundant, since the
///   caller supplies the statement anyway; storing them invites a later "simplification"
///   that reads `pk` from the file, which is exactly the substitution the comment in
///   `Cmd::Verify` exists to prevent.
fn verify_command(
    path: &str,
    pi: &PublicInputs,
    relation: RelationArg,
    log_inv_rate: usize,
    security_bits: usize,
) -> String {
    format!(
        "verify --proof {} --pk {} --msg {} --hx {} --relation {} \
         --log-inv-rate {log_inv_rate} --security-bits {security_bits}",
        shell_quote(path),
        hex::encode(pi.pk),
        hex::encode(pi.msg),
        hex::encode(pi.hx),
        relation.as_flag(),
    )
}

/// Quote a path for a POSIX shell, so `--out "my proofs/p.bin"` still yields a command
/// that survives a paste. Interpolated raw it splits into `--proof my` plus a stray
/// `proofs/p.bin`, and the hint fails on the one thing it exists to get right.
///
/// Single quotes, which are literal for everything except `'` itself. Applied only when
/// the path needs it: quoting an ordinary filename would be noise on every line.
fn shell_quote(path: &str) -> String {
    let safe = |b: u8| b.is_ascii_alphanumeric() || b"._-/=:+,@".contains(&b);
    if !path.is_empty() && path.bytes().all(safe) {
        return path.to_string();
    }
    format!("'{}'", path.replace('\'', r"'\''"))
}

/// Resolve `--seed` / `--seed-file` into hex. Clap guarantees exactly one is present.
fn read_seed(seed: Option<String>, seed_file: Option<String>) -> Result<String> {
    match (seed, seed_file) {
        (Some(hex), None) => Ok(hex),
        (None, Some(path)) if path == "-" => {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                .context("reading seed from stdin")?;
            Ok(buf)
        }
        (None, Some(path)) => {
            std::fs::read_to_string(&path).with_context(|| format!("reading seed from {path}"))
        }
        // Unreachable via the CLI: `conflicts_with` and `required_unless_present` make
        // these states unrepresentable. Reported rather than panicked on so a future
        // change to those attributes fails loudly instead of aborting.
        (Some(_), Some(_)) => bail!("give --seed or --seed-file, not both"),
        (None, None) => bail!("one of --seed or --seed-file is required"),
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Stat { relation } => {
            let b = CircuitBuilder::new();
            let _ = PqEddsaCircuit::build_with(&b, relation.into());
            let cs = b.build();
            let s = cs.constraint_system();
            println!("AND constraints:  {}", s.n_and_constraints());
            println!("IMUL constraints: {}", s.imul_constraints.len());
            println!("private wires:    {}", s.n_private);
            println!("query target:     {DEFAULT_SECURITY_BITS} bits (this build's default)");
            println!("relation:         {:?}", Relation::from(relation));
        }

        Cmd::Prove {
            seed,
            seed_file,
            msg,
            out,
            log_inv_rate,
            security_bits,
            relation,
        } => {
            let seed: [u8; 32] = parse_hex(&read_seed(seed, seed_file)?, "seed")?;
            let msg: [u8; 32] = match &msg {
                Some(m) => parse_hex(m, "msg")?,
                None => [0u8; 32],
            };
            let b = CircuitBuilder::new();
            let circuit = PqEddsaCircuit::build_with(&b, relation.into());
            let cs = b.build();
            let mut w = cs.new_witness_filler();

            // rx is sampled here and never leaves this process — it is witness, not
            // statement. Only hx is published.
            let rx = circuit.populate_randomised(&mut w, &seed, &msg)?;
            let pi = circuit.public_inputs_with_rx(&seed, &msg, &rx);

            // Fail fast and readably rather than emitting an unprovable system.
            let rx_ref = matches!(Relation::from(relation), Relation::Rand).then_some(&rx);
            PqEddsaCircuit::check_relation_with_rx(&seed, &msg, rx_ref, &pi)
                .context("witness does not satisfy the relation")?;
            cs.populate_wire_witness(&mut w)
                .map_err(|e| anyhow::anyhow!("witness population failed: {e:?}"))?;
            let witness = w.into_value_vec();

            let cfg = ProofConfig {
                log_inv_rate,
                security_bits,
            };
            let (_verifier, prover) = cfg.setup(cs.constraint_system().clone())?;

            let mut rng_seed = [0u8; 32];
            getrandom::fill(&mut rng_seed)?;
            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(rng_seed);
            let mut tr = ProverTranscript::new(Challenger::default());
            let t = std::time::Instant::now();
            prover
                .prove(&witness, &mut rng, &mut tr)
                .map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;
            let proof = tr.finalize();
            eprintln!(
                "proved in {} ms, {} bytes, {security_bits}-bit query target, {} build",
                t.elapsed().as_millis(),
                proof.len(),
                build_name()
            );

            println!("pk  {}", hex::encode(pi.pk));
            println!("msg {}", hex::encode(pi.msg));
            println!("hx  {}", hex::encode(pi.hx));

            match out {
                Some(path) => {
                    std::fs::write(&path, &proof)?;
                    eprintln!("proof written to {path}");
                    eprintln!(
                        "{}",
                        verify_command(&path, &pi, relation, log_inv_rate, security_bits)
                    );
                }
                // Proving is the whole cost of this command and the bytes go out of scope
                // here. Worth a line: `--out` is easy to leave off, and with it absent
                // every other line of output is identical to a run that kept the proof.
                None => eprintln!("proof discarded — pass --out <path> to keep it"),
            }
        }

        Cmd::Verify {
            proof,
            pk,
            msg,
            hx,
            log_inv_rate,
            security_bits,
            relation,
        } => {
            let pi = PublicInputs {
                pk: parse_hex(&pk, "pk")?,
                msg: match &msg {
                    Some(m) => parse_hex(m, "msg")?,
                    None => [0u8; 32],
                },
                hx: parse_hex(&hx, "hx")?,
            };
            let proof = std::fs::read(&proof).context("reading proof")?;

            let b = CircuitBuilder::new();
            let circuit = PqEddsaCircuit::build_with(&b, relation.into());
            let cs = b.build();

            // Reconstruct the public words from public data alone — never from a
            // prover-supplied blob, which would let a valid proof of a *different*
            // statement be accepted as a proof of this one.
            let public = public_words(&cs, &circuit, &pi);

            let cfg = ProofConfig {
                log_inv_rate,
                security_bits,
            };
            let verifier = cfg.setup_verifier(cs.constraint_system().clone())?;
            let mut vt = VerifierTranscript::new(Challenger::default(), proof);
            let t = std::time::Instant::now();
            // Four settings have to match the `prove` run and the proof file records none
            // of them, so a forgotten flag fails exactly like a tampered statement —
            // `OuterVerification(IPChannel(InvalidAssert))` either way. Report what this
            // run assumed, or the user has no way to tell the two apart.
            verifier.verify(&public, &mut vt).map_err(|e| {
                anyhow::anyhow!(
                    "verification FAILED: {e:?}\n\
                     checked as: --relation {} --log-inv-rate {log_inv_rate} \
                     --security-bits {security_bits}, {} build.\n\
                     A proof made under different settings fails identically to a forged \
                     one. Confirm these match the prove run before concluding the proof \
                     is bad.",
                    relation.as_flag(),
                    build_name()
                )
            })?;
            vt.finalize()
                .map_err(|e| anyhow::anyhow!("transcript finalize: {e:?}"))?;
            println!("OK — verified in {} ms", t.elapsed().as_millis());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    /// A seed read from a file arrives with a trailing newline; without trimming, the
    /// --seed-file path would reject every seed anyone actually stores in a file.
    #[test]
    fn parse_hex_tolerates_surrounding_whitespace() {
        let want: [u8; 32] = parse_hex(SEED_HEX, "seed").unwrap();
        assert_eq!(
            parse_hex::<32>(&format!("{SEED_HEX}\n"), "seed").unwrap(),
            want
        );
        assert_eq!(
            parse_hex::<32>(&format!("  {SEED_HEX}  \n"), "seed").unwrap(),
            want
        );
        assert_eq!(
            parse_hex::<32>(&format!("0x{SEED_HEX}\n"), "seed").unwrap(),
            want
        );
    }

    #[test]
    fn parse_hex_still_rejects_bad_input() {
        assert!(parse_hex::<32>("nothex", "seed").is_err());
        assert!(
            parse_hex::<32>(&SEED_HEX[..62], "seed").is_err(),
            "short seed accepted"
        );
        assert!(
            parse_hex::<32>(&format!("{SEED_HEX}ff"), "seed").is_err(),
            "long seed accepted"
        );
        // Internal whitespace is not whitespace to trim; it is a malformed seed.
        assert!(parse_hex::<32>("9d61 b19d", "seed").is_err());
    }

    #[test]
    fn read_seed_prefers_the_explicit_hex() {
        assert_eq!(read_seed(Some(SEED_HEX.into()), None).unwrap(), SEED_HEX);
    }

    #[test]
    fn read_seed_reads_a_file() {
        let path = std::env::temp_dir().join("pq-eddsa-cli-seed-test.hex");
        std::fs::write(&path, format!("{SEED_HEX}\n")).unwrap();
        let got = read_seed(None, Some(path.to_string_lossy().into_owned())).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(
            parse_hex::<32>(&got, "seed").unwrap(),
            parse_hex::<32>(SEED_HEX, "seed").unwrap()
        );
    }

    #[test]
    fn read_seed_reports_a_missing_file_rather_than_panicking() {
        let r = read_seed(None, Some("/nonexistent/pq-eddsa/seed".into()));
        assert!(r.is_err());
        assert!(format!("{:#}", r.unwrap_err()).contains("reading seed from"));
    }

    /// The hint `prove` prints is copy-pasteable only if these are the strings clap
    /// accepts. Both are derived from the variant names, so renaming a variant would
    /// otherwise leave every printed hint quietly unparseable.
    #[test]
    fn relation_flags_are_the_ones_clap_accepts() {
        for r in [RelationArg::Det, RelationArg::Rand] {
            let accepted = clap::ValueEnum::to_possible_value(&r).unwrap();
            assert_eq!(r.as_flag(), accepted.get_name());
        }
    }

    /// Quoting is what makes the printed command survive a path a shell would split.
    /// Checked separately because the round-trip test below splits on whitespace, which
    /// is the very assumption that breaks here -- it cannot catch this and must not be
    /// read as if it could.
    #[test]
    fn paths_a_shell_would_split_are_quoted() {
        assert_eq!(shell_quote("proof.bin"), "proof.bin");
        assert_eq!(shell_quote("out/dir/p-1_2.bin"), "out/dir/p-1_2.bin");
        assert_eq!(shell_quote("my proofs/p.bin"), "'my proofs/p.bin'");
        // A quote in the path closes the quoting and would let the rest run as shell
        // words. `'\''` is the POSIX way back in.
        assert_eq!(shell_quote("it's.bin"), r"'it'\''s.bin'");
        assert_eq!(shell_quote(""), "''");
    }

    /// A proof file records none of the settings it was made under, so this command is
    /// the only thing carrying them. Round-trip it through the parser: a dropped flag or
    /// a wrong field would otherwise surface only when someone pasted it, and the
    /// resulting failure looks like a bad proof rather than a bad hint.
    ///
    /// Whitespace-split, so it covers the settings rather than the quoting; paths that a
    /// shell would split are [`paths_a_shell_would_split_are_quoted`]'s job.
    #[test]
    fn the_printed_verify_command_parses_back_to_the_same_settings() {
        let pi = PublicInputs {
            pk: [1u8; 32],
            msg: [2u8; 32],
            hx: [3u8; 64],
        };
        let cmd = verify_command("p.bin", &pi, RelationArg::Rand, 2, 112);
        let argv = std::iter::once("pq-eddsa").chain(cmd.split_whitespace());
        let Cmd::Verify {
            proof,
            pk,
            msg,
            hx,
            log_inv_rate,
            security_bits,
            relation,
        } = Cli::try_parse_from(argv)
            .expect("printed command does not parse")
            .cmd
        else {
            panic!("printed command is not a verify invocation");
        };
        assert_eq!(proof, "p.bin");
        assert_eq!(parse_hex::<32>(&pk, "pk").unwrap(), pi.pk);
        // `--msg` matters most: it defaults to all zeros when omitted, so leaving it out
        // of the hint would produce a command that verifies a different statement.
        assert_eq!(
            parse_hex::<32>(&msg.expect("--msg missing"), "msg").unwrap(),
            pi.msg
        );
        assert_eq!(parse_hex::<64>(&hx, "hx").unwrap(), pi.hx);
        assert_eq!(log_inv_rate, 2);
        assert_eq!(security_bits, 112);
        assert_eq!(relation.as_flag(), "rand");
    }

    /// Clap makes these unrepresentable; the arms exist so a future change to the
    /// attributes surfaces as an error rather than a panic.
    #[test]
    fn read_seed_rejects_neither_and_both() {
        assert!(read_seed(None, None).is_err());
        assert!(read_seed(Some(SEED_HEX.into()), Some("f".into())).is_err());
    }
}
