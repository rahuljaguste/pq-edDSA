//! Task 0, Step 3: the blinding positive control.
//!
//! Question: at `n_dummy_constraints = 0`, is a zero-knowledge leak *detectable*?
//! If not, any null result Task 8 produces at other values would show only that the
//! detector does not work — so this must be answered before Task 8 depends on it.
//!
//! Design. Zero-knowledge means the proof distribution is independent of which
//! satisfying witness was used. So: pick a statement with two distinct witnesses,
//! generate many proofs for each with fresh randomness, and compare byte-wise.
//!
//! A byte position that is constant *within* each group but *differs between* groups
//! is a deterministic leak of witness data. A position constant and equal across both
//! groups is just proof structure, not a leak.
//!
//! The statement `a & b == 0` has many witnesses; `(MAX, 0)` and `(0, MAX)` both
//! satisfy it and the public input is identical.

use binius_core::{constraint_system::ValueVec, word::Word};
use binius_frontend::CircuitBuilder;
use binius_hash::sha256::Sha256HashSuite;
use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
use binius_verifier::{
    config::StdChallenger, transcript::ProverTranscript, zk_config::ZKVerifier,
};

type Suite = Sha256HashSuite;

/// Proofs generated per witness. Enough that a byte staying constant across all of
/// them is not plausibly coincidence: a uniformly random byte would repeat 24 times
/// with probability 256^-23.
const N_PROOFS: usize = 24;

/// Number of private wire pairs. Configurable because the first run used 2, which is
/// pathologically small next to `n_dummy_wires = 232` — a leak seen there might be an
/// artifact of the padding being almost entirely dummy wires rather than a real defect.
fn circuit_width() -> usize {
    std::env::var("SPIKE_WIDTH").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn proof_for(witness_variant: bool, rng_seed: u64) -> Vec<u8> {
    let width = circuit_width();
    let b = CircuitBuilder::new();
    let c = b.add_inout();

    let mut wires = Vec::new();
    for _ in 0..width {
        let a = b.add_witness();
        let bb = b.add_witness();
        let and = b.band(a, bb);
        b.assert_eq("and", and, c);
        wires.push((a, bb));
    }
    let cs = b.build();

    let mut w = cs.new_witness_filler();
    // Every pair satisfies a & b == 0, with identical public input in both groups.
    for (a, bb) in &wires {
        if witness_variant {
            w[*a] = Word(u64::MAX);
            w[*bb] = Word(0);
        } else {
            w[*a] = Word(0);
            w[*bb] = Word(u64::MAX);
        }
    }
    w[c] = Word(0);
    cs.populate_wire_witness(&mut w).expect("witness");
    let witness: ValueVec = w.into_value_vec();

    let verifier = ZKVerifier::<Suite>::setup(cs.constraint_system().clone(), 1).expect("verifier");
    let prover = ZKProver::<OptimalPackedB128, Suite>::setup(&verifier).expect("prover");

    let mut transcript = ProverTranscript::new(StdChallenger::default());
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(rng_seed);
    prover.prove(&witness, &mut rng, &mut transcript).expect("prove");
    transcript.finalize()
}

fn main() {
    let n_dummy = std::env::var("BINIUS_SPIKE_N_DUMMY_CONSTRAINTS")
        .unwrap_or_else(|_| "2".into());
    println!("n_dummy_constraints = {n_dummy}, {N_PROOFS} proofs per witness");

    // Fresh randomness per proof; the two groups use disjoint seed ranges.
    let group_a: Vec<Vec<u8>> = (0..N_PROOFS).map(|i| proof_for(true, i as u64)).collect();
    let group_b: Vec<Vec<u8>> =
        (0..N_PROOFS).map(|i| proof_for(false, 1000 + i as u64)).collect();

    let len = group_a[0].len().min(group_b[0].len());
    println!("proof length: {} bytes", group_a[0].len());

    let mut const_within_both = 0usize;
    let mut leaking = 0usize;
    let mut first_leaks = Vec::new();

    for i in 0..len {
        let a0 = group_a[0][i];
        let b0 = group_b[0][i];
        let a_const = group_a.iter().all(|p| p[i] == a0);
        let b_const = group_b.iter().all(|p| p[i] == b0);
        if a_const && b_const {
            const_within_both += 1;
            if a0 != b0 {
                leaking += 1;
                if first_leaks.len() < 8 {
                    first_leaks.push((i, a0, b0));
                }
            }
        }
    }

    println!("byte positions constant within BOTH groups: {const_within_both}");
    println!("  ...of those, DIFFERING between groups (leak): {leaking}");
    if leaking > 0 {
        println!("  first few: {first_leaks:?}");
        println!("\nVERDICT: leak DETECTED. The detector works at this setting.");
    } else {
        println!("\nVERDICT: no leak detected by this method at this setting.");
    }
}
