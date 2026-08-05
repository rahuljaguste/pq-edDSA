//! Prove and verify the `R_det` and `R_rand` relations.
//!
//! Argument layout matches SoundnessLabs/PQChain so the two can be compared directly,
//! which is also why `--relation` defaults to `det`.

use anyhow::{Context, Result, bail};
use binius_frontend::CircuitBuilder;
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
};
use clap::{Parser, Subcommand};
use pq_eddsa::{
    circuit::{PqEddsaCircuit, PublicInputs, Relation, public_words},
    config::{ProofConfig, SECURITY_BITS},
};

#[derive(Parser)]
#[command(
    name = "pq-eddsa",
    about = "Prove EdDSA key ownership from a seed, in zero knowledge",
    long_about = "Prove EdDSA key ownership from a seed, in zero knowledge.\n\n\
        UNAUDITED RESEARCH PROOF OF CONCEPT. Carries 96-bit classical soundness, below \
        the ~128 bits you should want in production, and its zero-knowledge property has \
        not been audited. Use throwaway keys only.\n\n\
        --seed puts the key on the command line, where your shell records it in history. \
        Prefer --seed-file, or `--seed-file -` to read it from stdin."
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
        #[arg(long, default_value_t = pq_eddsa::config::SECURITY_BITS)]
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
        #[arg(long, default_value_t = pq_eddsa::config::SECURITY_BITS)]
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
            println!("soundness:        {SECURITY_BITS} bits classical (default target)");
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

            let cfg = ProofConfig { log_inv_rate, security_bits };
            let (_verifier, prover) = cfg.setup(cs.constraint_system().clone())?;

            let mut rng_seed = [0u8; 32];
            getrandom::fill(&mut rng_seed)?;
            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(rng_seed);
            let mut tr = ProverTranscript::new(StdChallenger::default());
            let t = std::time::Instant::now();
            prover
                .prove(&witness, &mut rng, &mut tr)
                .map_err(|e| anyhow::anyhow!("prove: {e:?}"))?;
            let proof = tr.finalize();
            eprintln!(
                "proved in {} ms, {} bytes, {security_bits}-bit query target",
                t.elapsed().as_millis(),
                proof.len()
            );

            println!("pk  {}", hex::encode(pi.pk));
            println!("msg {}", hex::encode(pi.msg));
            println!("hx  {}", hex::encode(pi.hx));
            if let Some(path) = out {
                std::fs::write(&path, &proof)?;
                eprintln!("proof written to {path}");
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

            let cfg = ProofConfig { log_inv_rate, security_bits };
            let verifier = cfg.setup_verifier(cs.constraint_system().clone())?;
            let mut vt = VerifierTranscript::new(StdChallenger::default(), proof);
            let t = std::time::Instant::now();
            verifier
                .verify(&public, &mut vt)
                .map_err(|e| anyhow::anyhow!("verification FAILED: {e:?}"))?;
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

    /// Clap makes these unrepresentable; the arms exist so a future change to the
    /// attributes surfaces as an error rather than a panic.
    #[test]
    fn read_seed_rejects_neither_and_both() {
        assert!(read_seed(None, None).is_err());
        assert!(read_seed(Some(SEED_HEX.into()), Some("f".into())).is_err());
    }
}
