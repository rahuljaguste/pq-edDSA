//! Task 0, Step 1-2: does binius64's ZK path work on wasm32 at all?
//!
//! The circuit here is deliberately trivial — a chain of AND constraints. Its timing
//! is a *floor*, not a prediction of what the real Ed25519 circuit will cost. The only
//! questions being answered are:
//!
//! 1. Does the dependency graph compile for `wasm32-unknown-unknown`?
//! 2. Does entropy work there? (The ZK path needs it for blinding.)
//! 3. Does a proof produced in the browser actually verify?

use binius_core::constraint_system::ValueVec;
use binius_frontend::{CircuitBuilder, Wire};
use binius_hash::sha256::Sha256HashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};

type Suite = Sha256HashSuite;

/// Number of AND constraints in the smoke circuit.
const N_ANDS: usize = 64;

/// Prove and verify a trivial AND-chain circuit. Returns the proof size in bytes.
///
/// This is the whole smoke test: if it returns `Ok`, the wasm path works.
pub fn prove_and_verify() -> Result<usize, String> {
    // Built inline rather than in a helper so the circuit type never has to be named —
    // one less path to guess wrong.
    let b = CircuitBuilder::new();
    let inputs: Vec<Wire> = (0..N_ANDS).map(|_| b.add_witness()).collect();
    let out = b.add_inout();

    let mut acc = inputs[0];
    for w in inputs.iter().skip(1) {
        acc = b.band(acc, *w);
    }
    b.assert_eq("smoke", acc, out);
    let cs = b.build();

    let mut w = cs.new_witness_filler();
    // All ones AND'd together is all ones; any fixed pattern would do.
    for wire in &inputs {
        w[*wire] = binius_core::word::Word(u64::MAX);
    }
    w[out] = binius_core::word::Word(u64::MAX);
    cs.populate_wire_witness(&mut w).map_err(|e| format!("witness: {e:?}"))?;
    let witness: ValueVec = w.into_value_vec();

    let verifier = ZKVerifier::<Suite>::setup(cs.constraint_system().clone(), 1)
        .map_err(|e| format!("verifier setup: {e:?}"))?;
    let prover = ZKProver::<OptimalPackedB128, Suite>::setup(&verifier)
        .map_err(|e| format!("prover setup: {e:?}"))?;

    let mut transcript = ProverTranscript::new(StdChallenger::default());
    // Seed from the OS/JS entropy source rather than `rand::rng()`, which needs the
    // `thread_rng` feature binius64 does not enable. This also puts the entropy path
    // on the critical route: on wasm32 it goes through the JS crypto API, and a
    // failure there is a distinct failure mode from the graph not compiling.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("entropy: {e:?}"))?;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(seed);
    prover
        .prove(&witness, &mut rng, &mut transcript)
        .map_err(|e| format!("prove: {e:?}"))?;
    let proof = transcript.finalize();
    let size = proof.len();

    let mut vt = VerifierTranscript::new(StdChallenger::default(), proof);
    verifier
        .verify(witness.public(), &mut vt)
        .map_err(|e| format!("verify: {e:?}"))?;
    vt.finalize().map_err(|e| format!("finalize: {e:?}"))?;

    Ok(size)
}

/// Confirm entropy is reachable. On wasm32 this exercises the JS crypto path,
/// which is a distinct failure mode from the rest of the graph not compiling.
pub fn entropy_works() -> bool {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).is_ok() && buf.iter().any(|&x| x != 0)
}

#[cfg(target_arch = "wasm32")]
mod wasm_exports {
    use super::*;

    /// Exported for the browser harness. Returns proof size, or 0 on failure.
    #[unsafe(no_mangle)]
    pub extern "C" fn smoke_prove_verify() -> u32 {
        match prove_and_verify() {
            Ok(n) => n as u32,
            Err(_) => 0,
        }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn smoke_entropy() -> u32 {
        if entropy_works() { 1 } else { 0 }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// Native baseline. If this fails the spike is testing nothing.
    #[test]
    fn native_prove_verify_works() {
        let size = prove_and_verify().expect("native prove/verify");
        assert!(size > 0);
        println!("native proof size: {size} bytes");
    }

    #[test]
    fn native_entropy_works() {
        assert!(entropy_works());
    }
}
