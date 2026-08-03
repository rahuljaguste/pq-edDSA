//! Tests for `R_rand` (paper Eq. 1) — the relation Theorem 2 is actually proved over.

use binius_core::verify::verify_constraints;
use binius_frontend::CircuitBuilder;
use pq_eddsa::circuit::{PqEddsaCircuit, Relation, derive_hx};

const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn seed_of(h: &str) -> [u8; 32] {
    hex::decode(h).unwrap().try_into().unwrap()
}

fn accepts(relation: Relation, seed: &[u8; 32], msg: &[u8; 32], rx: &[u8; 32]) -> bool {
    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build_with(&b, relation);
    let cs = b.build();
    let mut w = cs.new_witness_filler();
    circuit.populate_with_rx(&mut w, seed, msg, rx);
    if cs.populate_wire_witness(&mut w).is_err() {
        return false;
    }
    verify_constraints(cs.constraint_system(), &w.into_value_vec()).is_ok()
}

/// The randomised relation must be satisfiable.
#[test]
fn rand_relation_is_satisfiable() {
    let seed = seed_of(SEED);
    assert!(accepts(Relation::Rand, &seed, &[7u8; 32], &[0x5Au8; 32]));
}

/// **The property that motivates the whole mode.** Under `Rand`, the same `(seed, msg)`
/// must produce a *different* `hx` for different `rx`.
///
/// Under `Det` it cannot: `hx` is a deterministic function of `(msg, seed)`, so anyone
/// holding the public `msg` and `hx` can test candidate seeds offline. That is precisely
/// what `rx` exists to prevent, and it is why Theorem 2 is stated over Eq. 1.
#[test]
fn rx_randomises_hx() {
    let seed = seed_of(SEED);
    let msg = [7u8; 32];

    let det_a = derive_hx(&seed, &msg, None);
    let det_b = derive_hx(&seed, &msg, None);
    assert_eq!(det_a, det_b, "Det must be deterministic");

    let rand_a = derive_hx(&seed, &msg, Some(&[1u8; 32]));
    let rand_b = derive_hx(&seed, &msg, Some(&[2u8; 32]));
    assert_ne!(rand_a, rand_b, "rx failed to randomise hx");
    assert_ne!(rand_a, det_a, "Rand hx must differ from Det hx");
}

/// `rx` must genuinely enter the hash: a proof made with one `rx` must not satisfy the
/// statement implied by another.
#[test]
fn wrong_rx_is_rejected() {
    let seed = seed_of(SEED);
    let msg = [7u8; 32];
    let rx = [0x11u8; 32];

    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build_with(&b, Relation::Rand);
    let cs = b.build();
    let mut w = cs.new_witness_filler();

    // Public inputs pinned to `rx`, but the witness carries a different one.
    circuit.populate_public(&mut w, &circuit.public_inputs_with_rx(&seed, &msg, &rx));
    let mut other = rx;
    other[0] ^= 1;
    circuit.populate_private_with_rx(&mut w, &seed, &other);

    assert!(
        cs.populate_wire_witness(&mut w).is_err(),
        "accepted a witness whose rx does not produce the claimed hx"
    );
}

/// The two relations are genuinely different circuits, and a statement for one must not
/// satisfy the other.
#[test]
fn relations_are_distinct() {
    let seed = seed_of(SEED);
    let msg = [7u8; 32];
    let rx = [0x5Au8; 32];

    let shape = |r: Relation| {
        let b = CircuitBuilder::new();
        let _ = PqEddsaCircuit::build_with(&b, r);
        let cs = b.build();
        let s = cs.constraint_system();
        (s.n_and_constraints(), s.n_private)
    };
    assert_ne!(shape(Relation::Det), shape(Relation::Rand), "shapes must differ");

    // A Det statement (hx without rx) must not satisfy the Rand circuit.
    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build_with(&b, Relation::Rand);
    let cs = b.build();
    let mut w = cs.new_witness_filler();
    circuit.populate_public(&mut w, &PqEddsaCircuit::public_inputs(&seed, &msg));
    circuit.populate_private_with_rx(&mut w, &seed, &rx);
    assert!(
        cs.populate_wire_witness(&mut w).is_err(),
        "Rand circuit accepted a Det statement"
    );
}

/// `Rand` must cost essentially nothing — `msg ‖ seed ‖ rx` is 96 bytes, still one
/// SHA-512 block. If this regresses, the extra compression the design spec projected has
/// crept in.
#[test]
fn rand_costs_almost_nothing() {
    let count = |r: Relation| {
        let b = CircuitBuilder::new();
        let _ = PqEddsaCircuit::build_with(&b, r);
        let cs = b.build();
        let s = cs.constraint_system();
        (s.n_and_constraints(), s.imul_constraints.len())
    };
    let (det_and, det_imul) = count(Relation::Det);
    let (rand_and, rand_imul) = count(Relation::Rand);

    println!("  Det  {det_and} AND, {det_imul} IMUL");
    println!("  Rand {rand_and} AND, {rand_imul} IMUL  (+{} AND)", rand_and - det_and);

    assert_eq!(det_imul, rand_imul, "Rand must add no multiplications");
    assert!(
        rand_and - det_and < 1_000,
        "Rand added {} AND; expected well under 1,000 — has it gained a SHA-512 block?",
        rand_and - det_and
    );
}
