//! End-to-end tests for the `R_det` circuit against RFC 8032.

use binius_core::verify::verify_constraints;
use binius_frontend::CircuitBuilder;
use pq_eddsa::circuit::{PqEddsaCircuit, derive_hx, derive_pk};

/// RFC 8032 section 7.1 seed/public-key pairs.
const VECTORS: &[(&str, &str)] = &[
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ),
    (
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    ),
    (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    ),
];

fn seed_of(hexed: &str) -> [u8; 32] {
    hex::decode(hexed).unwrap().try_into().unwrap()
}

/// The host-side derivation must reproduce every published public key.
///
/// Checked before the circuit tests: if this is wrong, every circuit test that compares
/// against it would agree with a wrong answer.
#[test]
fn host_derivation_matches_rfc8032() {
    for (seed_hex, pk_hex) in VECTORS {
        let seed = seed_of(seed_hex);
        assert_eq!(
            hex::encode(derive_pk(&seed)),
            *pk_hex,
            "seed {seed_hex}"
        );
    }
}

/// …and must agree with `ed25519-dalek`, an independent implementation.
#[test]
fn host_derivation_matches_dalek() {
    for (seed_hex, _) in VECTORS {
        let seed = seed_of(seed_hex);
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(derive_pk(&seed), sk.verifying_key().to_bytes(), "seed {seed_hex}");
    }
}

/// The circuit must be satisfiable for every RFC vector.
#[test]
fn circuit_proves_rfc8032_vectors() {
    for (seed_hex, pk_hex) in VECTORS {
        let seed = seed_of(seed_hex);
        let msg = [0u8; 32];

        let b = CircuitBuilder::new();
        let circuit = PqEddsaCircuit::build(&b);
        let cs = b.build();
        let mut w = cs.new_witness_filler();
        circuit.populate(&mut w, &seed, &msg);
        cs.populate_wire_witness(&mut w)
            .unwrap_or_else(|e| panic!("unsatisfiable for seed {seed_hex}: {e:?}"));

        // Read the public-key wires back and confirm they hold the RFC's value.
        let got: Vec<u64> = circuit.pk.iter().map(|p| w[*p].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        let want = hex::decode(pk_hex).unwrap();
        for i in 0..4 {
            let mut e = [0u8; 8];
            e.copy_from_slice(&want[8 * i..8 * i + 8]);
            assert_eq!(got[i], u64::from_le_bytes(e), "seed {seed_hex} pk word {i}");
        }
    }
}

/// A non-zero message, so `hx` is not exercised only on all-zero input.
#[test]
fn circuit_proves_with_a_nonzero_message() {
    let seed = seed_of(VECTORS[0].0);
    let mut msg = [0u8; 32];
    for (i, byte) in msg.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(7).wrapping_add(1);
    }

    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let mut w = cs.new_witness_filler();
    circuit.populate(&mut w, &seed, &msg);
    cs.populate_wire_witness(&mut w).unwrap();
    verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
}

/// `hx` must genuinely depend on the message and the seed, not be structurally fixed.
#[test]
fn hx_depends_on_both_inputs() {
    let s1 = seed_of(VECTORS[0].0);
    let s2 = seed_of(VECTORS[1].0);
    let m1 = [0u8; 32];
    let m2 = [1u8; 32];
    assert_ne!(derive_hx(&s1, &m1), derive_hx(&s1, &m2), "hx ignored the message");
    assert_ne!(derive_hx(&s1, &m1), derive_hx(&s2, &m1), "hx ignored the seed");
}

/// The verifier's reconstruction of the public section must match the prover's exactly.
///
/// If it does not, verification fails even on an honest proof — which is precisely the
/// bug this test was written after hitting.
#[test]
fn verifier_reconstructs_the_same_public_words() {
    use pq_eddsa::circuit::public_words;

    let seed = seed_of(VECTORS[0].0);
    let msg = [7u8; 32];
    let pi = PqEddsaCircuit::public_inputs(&seed, &msg);

    let b = CircuitBuilder::new();
    let circuit = PqEddsaCircuit::build(&b);
    let cs = b.build();

    // Prover: full population, which fills constants as a side effect.
    let mut w = cs.new_witness_filler();
    circuit.populate(&mut w, &seed, &msg);
    cs.populate_wire_witness(&mut w).unwrap();
    let prover_public = w.into_value_vec().public().to_vec();

    // Verifier: public data only.
    let verifier_public = public_words(&cs, &circuit, &pi);

    assert_eq!(
        prover_public, verifier_public,
        "verifier cannot reconstruct the prover's public input"
    );
}
