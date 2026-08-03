//! Prove and verify the `R_det` relation.
//!
//! Argument layout matches SoundnessLabs/PQChain so the two can be compared directly.

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
#[command(name = "pq-eddsa", about = "Prove EdDSA key ownership from a seed, in zero knowledge")]
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
        /// 32-byte seed, hex. PRIVATE — never leaves this process.
        #[arg(long)]
        seed: String,
        /// 32-byte message, hex. Defaults to all zeros.
        #[arg(long)]
        msg: Option<String>,
        /// Where to write the proof.
        #[arg(long)]
        out: Option<String>,
        #[arg(long, default_value_t = 1)]
        log_inv_rate: usize,
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
    let raw = hex::decode(s.trim_start_matches("0x"))
        .with_context(|| format!("{what} is not valid hex"))?;
    if raw.len() != N {
        bail!("{what} must be {N} bytes, got {}", raw.len());
    }
    Ok(raw.try_into().unwrap())
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
            println!("soundness:        {SECURITY_BITS} bits classical");
            println!("relation:         {:?}", Relation::from(relation));
        }

        Cmd::Prove { seed, msg, out, log_inv_rate, relation } => {
            let seed: [u8; 32] = parse_hex(&seed, "seed")?;
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

            let cfg = ProofConfig { log_inv_rate };
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
                "proved in {} ms, {} bytes, {SECURITY_BITS}-bit soundness",
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

        Cmd::Verify { proof, pk, msg, hx, log_inv_rate, relation } => {
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

            let cfg = ProofConfig { log_inv_rate };
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
