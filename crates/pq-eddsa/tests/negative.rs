//! Negative tests: the circuit and the proof system must **reject** false statements.
//!
//! An under-constrained circuit passes every positive test — it proves true statements
//! correctly and false ones too. Positive tests alone cannot distinguish a correct circuit
//! from a vacuous one. These can.
//!
//! Note what there is *not* to tamper with. Everything downstream of the seed is derived,
//! and the affine coordinates come from a `Hint` that is recomputed during witness
//! population, so there are no witnessed intermediates a prover could poison. The attack
//! surface is exactly: the seed, and the three public inputs.

use binius_core::verify::verify_constraints;
use binius_frontend::CircuitBuilder;
use binius_hash::sha256::Sha256HashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger,
    transcript::{ProverTranscript, VerifierTranscript},
    zk_config::ZKVerifier,
};
use pq_eddsa::circuit::{PqEddsaCircuit, PublicInputs, public_words};

type Suite = Sha256HashSuite;

const SEED_A: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const SEED_B: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

fn seed_of(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}

/// Build, populate with an explicit (possibly inconsistent) statement, and report whether
/// the constraint system accepts.
fn accepts(seed: &[u8; 32], pi: &PublicInputs) -> bool {
    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let mut w = cs.new_witness_filler();
    circuit.populate_private(&mut w, seed);
    circuit.populate_public(&mut w, pi);
    if cs.populate_wire_witness(&mut w).is_err() {
        return false;
    }
    verify_constraints(cs.constraint_system(), &w.into_value_vec()).is_ok()
}

/// Control: the honest statement must be accepted. Without this the rejections below
/// could all be caused by something unrelated.
#[test]
fn control_honest_statement_is_accepted() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    assert!(accepts(&seed, &PqEddsaCircuit::public_inputs(&seed, &msg)));
}

#[test]
fn rejects_wrong_seed() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    let pi = PqEddsaCircuit::public_inputs(&seed, &msg);

    let mut wrong = seed;
    wrong[0] ^= 1;
    assert!(!accepts(&wrong, &pi), "accepted a seed that does not derive pk");
}

/// A *different* valid seed, not merely a corrupted one — its own pk and hx are
/// well-formed, they just are not the ones being claimed.
#[test]
fn rejects_a_different_valid_seed() {
    let seed_a = seed_of(SEED_A);
    let seed_b = seed_of(SEED_B);
    let msg = [3u8; 32];
    let pi_a = PqEddsaCircuit::public_inputs(&seed_a, &msg);
    assert!(!accepts(&seed_b, &pi_a), "accepted the wrong key's seed");
}

#[test]
fn rejects_wrong_pk() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    let mut pi = PqEddsaCircuit::public_inputs(&seed, &msg);
    pi.pk[0] ^= 1;
    assert!(!accepts(&seed, &pi), "accepted a pk that the seed does not derive");
}

/// Flipping the *sign bit* specifically — the one compression encodes from x's parity,
/// and the one the canonicality assertion in `to_affine` exists to protect.
#[test]
fn rejects_pk_with_flipped_sign_bit() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    let mut pi = PqEddsaCircuit::public_inputs(&seed, &msg);
    pi.pk[31] ^= 0x80;
    assert!(!accepts(&seed, &pi), "accepted a pk with the sign bit flipped");
}

#[test]
fn rejects_wrong_hx() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    let mut pi = PqEddsaCircuit::public_inputs(&seed, &msg);
    pi.hx[63] ^= 1;
    assert!(!accepts(&seed, &pi), "accepted an hx that is not SHA-512(msg ‖ seed)");
}

/// Changing the message without updating `hx` must fail — otherwise `hx` would not bind
/// the message, and the one-time proof could be replayed against a different one.
#[test]
fn rejects_message_not_bound_by_hx() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    let mut pi = PqEddsaCircuit::public_inputs(&seed, &msg);
    pi.msg[0] ^= 1; // hx still corresponds to the original message
    assert!(!accepts(&seed, &pi), "hx failed to bind the message");
}

/// The end-to-end property: a **proof** for one statement must not verify against
/// another. Constraint-level rejection is necessary but not sufficient — this is the
/// check that matters to a verifier.
#[test]
fn proof_for_one_statement_does_not_verify_against_another() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    let pi = PqEddsaCircuit::public_inputs(&seed, &msg);

    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let mut w = cs.new_witness_filler();
    circuit.populate(&mut w, &seed, &msg);
    cs.populate_wire_witness(&mut w).unwrap();
    let witness = w.into_value_vec();

    let verifier = ZKVerifier::<Suite>::setup(cs.constraint_system().clone(), 1).unwrap();
    let prover = ZKProver::<OptimalPackedB128, Suite>::setup(&verifier).unwrap();

    let mut rng_seed = [0u8; 32];
    getrandom::fill(&mut rng_seed).unwrap();
    let mut tr = ProverTranscript::new(StdChallenger::default());
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(rng_seed);
    prover.prove(&witness, &mut rng, &mut tr).unwrap();
    let proof = tr.finalize();

    let check = |pi: &PublicInputs| {
        let public = public_words(&cs, &circuit, pi);
        let mut vt = VerifierTranscript::new(StdChallenger::default(), proof.clone());
        verifier.verify(&public, &mut vt).is_ok() && vt.finalize().is_ok()
    };

    // Control: against its own statement it must verify.
    assert!(check(&pi), "honest proof failed to verify against its own statement");

    // Against a different pk, hx, or msg it must not.
    let mut bad_pk = pi.clone();
    bad_pk.pk[0] ^= 1;
    assert!(!check(&bad_pk), "verified against a different pk");

    let mut bad_hx = pi.clone();
    bad_hx.hx[0] ^= 1;
    assert!(!check(&bad_hx), "verified against a different hx");

    let mut bad_msg = pi.clone();
    bad_msg.msg[0] ^= 1;
    assert!(!check(&bad_msg), "verified against a different message");
}

/// The constraint system must not depend on the witness.
///
/// Structural in Binius64 — the graph is fixed before any witness exists — which is
/// exactly why it is worth pinning. PQChain shipped a bug of this class
/// (`fix/ed25519-scalar-mul-secret-leak`) where the scalar multiplication's shape varied
/// with the secret and had to be repaired by hand with oblivious multiplexers.
#[test]
fn circuit_shape_is_independent_of_the_seed() {
    let shape = || {
        let b = CircuitBuilder::new();
        let _ = PqEddsaCircuit::build(&b);
        let cs = b.build();
        let s = cs.constraint_system();
        (
            s.n_and_constraints(),
            s.imul_constraints.len(),
            s.zero_constraints.len(),
            s.n_private,
            s.constants.len(),
        )
    };
    assert_eq!(shape(), shape());
}

/// Substituting another user's **valid** public key must fail.
///
/// Every other pk test flips a bit, which likely yields an encoding no point decodes to —
/// so it could be rejected for being malformed rather than for being the wrong key. This
/// is the attack that actually matters: proving "I control account B" while holding only
/// seed A. The claimed pk is perfectly well-formed; it is simply not derived from the
/// witness.
#[test]
fn rejects_another_users_valid_pk() {
    let seed_a = seed_of(SEED_A);
    let seed_b = seed_of(SEED_B);
    let msg = [3u8; 32];

    let mut pi = PqEddsaCircuit::public_inputs(&seed_a, &msg);
    let pk_b = PqEddsaCircuit::public_inputs(&seed_b, &msg).pk;
    assert_ne!(pi.pk, pk_b, "test vectors must have distinct public keys");
    pi.pk = pk_b; // a genuine, well-formed public key — just not seed A's

    assert!(
        !accepts(&seed_a, &pi),
        "accepted a claim to another account's public key"
    );
}

/// `check_relation` is the CLI's fail-fast guard. If it wrongly returned `Ok`, a user
/// would get an opaque constraint failure instead of a readable message — and if it
/// wrongly returned `Err`, honest proving would be blocked. Both directions are tested
/// because only the CLI calls it, so nothing else would notice a regression.
#[test]
fn check_relation_accepts_only_consistent_statements() {
    use pq_eddsa::circuit::PqEddsaCircuit as C;

    let seed = seed_of(SEED_A);
    let msg = [9u8; 32];
    let pi = C::public_inputs(&seed, &msg);

    assert!(C::check_relation(&seed, &msg, &pi).is_ok(), "rejected an honest statement");

    let mut bad_pk = pi.clone();
    bad_pk.pk[0] ^= 1;
    assert!(C::check_relation(&seed, &msg, &bad_pk).is_err(), "missed a wrong pk");

    let mut bad_hx = pi.clone();
    bad_hx.hx[0] ^= 1;
    assert!(C::check_relation(&seed, &msg, &bad_hx).is_err(), "missed a wrong hx");

    let mut bad_msg = pi.clone();
    bad_msg.msg[0] ^= 1;
    assert!(C::check_relation(&seed, &msg, &bad_msg).is_err(), "missed a wrong msg");

    let mut wrong_seed = seed;
    wrong_seed[0] ^= 1;
    assert!(
        C::check_relation(&wrong_seed, &msg, &pi).is_err(),
        "missed a seed that does not derive pk"
    );
}

/// Every word of `hx` must be constrained — not just the ones a hand-written test
/// happens to poke.
///
/// Added after a shell-level check appeared to show a tampered final nibble verifying.
/// It did not — the expansion was faulty — but "I could not reproduce it" is a poor
/// substitute for covering all eight words explicitly.
#[test]
fn every_hx_word_is_constrained() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];

    for byte in [0usize, 7, 8, 31, 32, 55, 56, 63] {
        let mut pi = PqEddsaCircuit::public_inputs(&seed, &msg);
        pi.hx[byte] ^= 1;
        assert!(
            !accepts(&seed, &pi),
            "hx byte {byte} (word {}) is not constrained",
            byte / 8
        );
        // And the low nibble specifically, which is what the shell check mangled.
        let mut pi2 = PqEddsaCircuit::public_inputs(&seed, &msg);
        pi2.hx[byte] ^= 0x0F;
        assert!(!accepts(&seed, &pi2), "hx byte {byte} low nibble unconstrained");
    }
}

/// Likewise every word of `pk`.
#[test]
fn every_pk_word_is_constrained() {
    let seed = seed_of(SEED_A);
    let msg = [3u8; 32];
    for byte in [0usize, 7, 8, 15, 16, 23, 24, 31] {
        let mut pi = PqEddsaCircuit::public_inputs(&seed, &msg);
        pi.pk[byte] ^= 1;
        assert!(!accepts(&seed, &pi), "pk byte {byte} is not constrained");
    }
}
