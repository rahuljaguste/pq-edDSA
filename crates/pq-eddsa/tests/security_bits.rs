//! The `security_bits` query target: what it changes, and what it does not.
//!
//! SPIKE BRANCH ONLY. Upstream hardcodes the target and exposes no override; these tests
//! exist because the branch patches in a fork carrying `setup_with_security_bits`.
//!
//! Without them the parameter has no coverage at all, which is how the `stat` subcommand
//! and the wasm bindings both came to report 96 bits while running the wide
//! configuration.

use binius_frontend::CircuitBuilder;
use binius_verifier::transcript::{ProverTranscript, VerifierTranscript};
use pq_eddsa::{
    circuit::{PqEddsaCircuit, PublicInputs, public_words},
    config::{Challenger, DEFAULT_SECURITY_BITS, ProofConfig},
};

const SEED: [u8; 32] = [0x42; 32];
const MSG: [u8; 32] = [0u8; 32];

/// Prove at `security_bits`, returning the proof and the statement.
fn prove_at(security_bits: usize) -> (Vec<u8>, PublicInputs) {
    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let mut w = cs.new_witness_filler();
    circuit.populate(&mut w, &SEED, &MSG);
    cs.populate_wire_witness(&mut w).expect("witness");
    let witness = w.into_value_vec();

    let cfg = ProofConfig {
        log_inv_rate: 1,
        security_bits,
    };
    let (_v, prover) = cfg.setup(cs.constraint_system().clone()).expect("setup");
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed([7u8; 32]);
    let mut tr = ProverTranscript::new(Challenger::default());
    prover.prove(&witness, &mut rng, &mut tr).expect("prove");
    (tr.finalize(), PqEddsaCircuit::public_inputs(&SEED, &MSG))
}

/// Returns whether the verifier *accepted*, panicking if it could not be built.
///
/// Distinguishing the two matters: folding a setup failure into `false` would let
/// `a_proof_does_not_verify_under_a_different_target` pass vacuously if a future fork
/// revision started rejecting the mismatched target at setup instead of at verification.
/// The test would then be asserting nothing while still going green.
fn verify_at(proof: &[u8], pi: &PublicInputs, security_bits: usize) -> bool {
    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let public = public_words(&cs, &circuit, pi);
    let cfg = ProofConfig {
        log_inv_rate: 1,
        security_bits,
    };
    let verifier = cfg
        .setup_verifier(cs.constraint_system().clone())
        .unwrap_or_else(|e| panic!("verifier setup failed at {security_bits} bits: {e}"));
    let mut vt = VerifierTranscript::new(Challenger::default(), proof.to_vec());
    verifier.verify(&public, &mut vt).is_ok() && vt.finalize().is_ok()
}

/// The target is part of the statement's parameters, not a hint. A verifier using a
/// different budget must reject, or the parameter would be unauthenticated and a prover
/// could claim any level it liked.
#[test]
fn a_proof_does_not_verify_under_a_different_target() {
    let (proof, pi) = prove_at(DEFAULT_SECURITY_BITS);
    assert!(
        verify_at(&proof, &pi, DEFAULT_SECURITY_BITS),
        "own target rejected"
    );
    assert!(
        !verify_at(&proof, &pi, DEFAULT_SECURITY_BITS + 16),
        "accepted under a higher target than it was produced at"
    );
}

/// Raising the target must cost proof bytes. If it did not, the parameter would not be
/// buying queries and the whole measurement on this branch would be meaningless.
///
/// Raises *up to* the default rather than past it. Going above would land over the cap on
/// the wide build, where the default is already the binding level, and would then be
/// testing the same thing as `over_requesting_is_accepted_silently_and_is_not_free`
/// instead of a genuine raise.
#[test]
fn raising_the_target_grows_the_proof() {
    let below = DEFAULT_SECURITY_BITS - 16;
    let (lo, _) = prove_at(below);
    let (hi, _) = prove_at(DEFAULT_SECURITY_BITS);
    assert!(
        hi.len() > lo.len(),
        "raising the target from {} to {} did not grow the proof ({} vs {} bytes)",
        below,
        DEFAULT_SECURITY_BITS,
        lo.len(),
        hi.len()
    );
}

/// The documented footgun, pinned so it is a known property rather than a surprise.
///
/// logUp\* contributes a fixed `2^16/|F|`, so the narrow field cannot exceed ~112 bits and
/// the wide one ~240 however large the query budget. Asking for more is accepted, costs
/// real proof size, and buys nothing. If a future version starts rejecting it, this test
/// fails and the behaviour change gets noticed.
#[test]
fn over_requesting_is_accepted_silently_and_is_not_free() {
    let (base, _) = prove_at(DEFAULT_SECURITY_BITS);
    let absurd = DEFAULT_SECURITY_BITS + 128;
    let (over, _) = prove_at(absurd);
    assert!(
        over.len() > base.len(),
        "over-requesting was free, so it is no longer a footgun worth warning about"
    );
}
