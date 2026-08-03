//! Full-circuit measurement. Run with `--ignored`.
//!
//! Methodology, which the README must reproduce: the first run of a process measures
//! ~1.6x slow from warm-up and is discarded. PQChain averages over 100 runs, so comparing
//! a cold number against its steady-state figure would silently favour us.

use binius_core::verify::verify_constraints;
use binius_frontend::CircuitBuilder;
use binius_hash::{Blake3HashSuite, sha256::Sha256HashSuite};
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};
use pq_eddsa::circuit::PqEddsaCircuit;



const RUNS: usize = 10;

#[test]
#[ignore = "measurement; run with --ignored"]
fn measure_full_circuit() {
    run::<Sha256HashSuite>("SHA-256");
}

#[test]
#[ignore = "measurement; run with --ignored"]
fn measure_hash_suites() {
    run::<Sha256HashSuite>("SHA-256");
    run::<Blake3HashSuite>("Blake3");
}

/// Same comparison, reversed. If the two orders disagree, the measurement is being
/// distorted by whatever runs first rather than by the suites themselves.
#[test]
#[ignore = "measurement; run with --ignored"]
fn measure_hash_suites_reversed() {
    run::<Blake3HashSuite>("Blake3");
    run::<Sha256HashSuite>("SHA-256");
}

fn run<S>(suite_name: &str)
where
    S: binius_hash::binary_merkle_tree::HashSuite + Clone,
    digest::Output<S::LeafHash>: binius_utils::SerializeBytes + binius_utils::DeserializeBytes,
{
    let seed: [u8; 32] = hex::decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .unwrap()
    .try_into()
    .unwrap();
    let msg = [0u8; 32];

    let t_build = std::time::Instant::now();
    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let build_ms = t_build.elapsed().as_millis();

    let (n_and, n_imul, n_priv) = {
        let s = cs.constraint_system();
        (s.n_and_constraints(), s.imul_constraints.len(), s.n_private)
    };

    let mut w = cs.new_witness_filler();
    circuit.populate(&mut w, &seed, &msg).unwrap();
    cs.populate_wire_witness(&mut w).unwrap();
    let witness = w.into_value_vec();
    verify_constraints(cs.constraint_system(), &witness).unwrap();

    let t_setup = std::time::Instant::now();
    let verifier = ZKVerifier::<S>::setup(cs.constraint_system().clone(), 1).unwrap();
    let prover = ZKProver::<OptimalPackedB128, S>::setup(&verifier).unwrap();
    let setup_ms = t_setup.elapsed().as_millis();

    let mut seed_bytes = [0u8; 32];
    getrandom::fill(&mut seed_bytes).unwrap();

    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_size = 0usize;

    for run in 0..=RUNS {
        let t = std::time::Instant::now();
        let mut tr = ProverTranscript::new(StdChallenger::default());
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(seed_bytes);
        prover.prove(&witness, &mut rng, &mut tr).unwrap();
        let proof = tr.finalize();
        let p_el = t.elapsed().as_millis();

        let t2 = std::time::Instant::now();
        let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.clone());
        verifier.verify(witness.public(), &mut vt).unwrap();
        vt.finalize().unwrap();
        let v_el = t2.elapsed().as_millis();

        // Discard run 0: warm-up.
        if run > 0 {
            prove_ms.push(p_el);
            verify_ms.push(v_el);
            proof_size = proof.len();
        }
    }

    let mean = |v: &[u128]| v.iter().sum::<u128>() as f64 / v.len() as f64;
    let min = |v: &[u128]| *v.iter().min().unwrap();
    let max = |v: &[u128]| *v.iter().max().unwrap();

    println!("\n=== PQ-EdDSA R_det, full circuit — {suite_name} Merkle ===");
    println!("host:            Apple M1 Pro (8 cores), single-threaded");
    println!("soundness:       96 bits classical (upstream SECURITY_BITS)");
    println!("config:          ZK path, log_inv_rate = 1, SHA-256 Merkle");
    println!();
    println!("AND constraints: {n_and}");
    println!("IMUL constraints:{n_imul}");
    println!("private wires:   {n_priv}");
    println!();
    println!("circuit build:   {build_ms} ms");
    println!("prover setup:    {setup_ms} ms");
    println!(
        "prove:           {:.1} ms  (min {}, max {}, n={})",
        mean(&prove_ms), min(&prove_ms), max(&prove_ms), prove_ms.len()
    );
    println!(
        "verify:          {:.1} ms  (min {}, max {}, n={})",
        mean(&verify_ms), min(&verify_ms), max(&verify_ms), verify_ms.len()
    );
    println!("proof size:      {} bytes ({} KiB)", proof_size, proof_size / 1024);
    println!();
    println!("PQChain (Ligetron, M4 Pro 12-core, ~128-bit soundness, avg of 100):");
    println!("  prove 6200 ms | verify 2300 ms | proof 5.4 MB | 4,924,225 constraints");
    println!();
}
