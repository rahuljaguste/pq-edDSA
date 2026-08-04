//! What SHA-512 actually costs in this system.
//!
//! The README uses a per-compression-block AND count as evidence that a 64-bit-word
//! proving system suits this relation. That number should come from a measurement in the
//! repository rather than from an assertion in the README, so it is measured here.
//!
//! It was wrong before this test existed: the README quoted 1,830 AND "per compression
//! block", which is the cost of *two* blocks.

use binius_circuits::sha512::sha512_fixed;
use binius_frontend::{CircuitBuilder, Wire};

/// AND constraints for hashing `n_words` 64-bit words with `sha512_fixed`.
///
/// The digest is asserted against public wires rather than dropped. An unused digest is
/// dead code, the builder removes the entire hash, and the measurement reads zero.
fn and_for(n_words: usize) -> usize {
    let b = CircuitBuilder::new();
    let input: Vec<Wire> = (0..n_words).map(|_| b.add_witness()).collect();
    let digest = sha512_fixed(&b, &input, n_words * 8);
    for (i, d) in digest.iter().enumerate() {
        let out = b.add_inout();
        b.assert_eq(format!("digest{i}"), *d, out);
    }
    b.build().constraint_system().n_and_constraints()
}

/// SHA-512 pads with one byte plus a 16-byte length into a 128-byte block, so 111 bytes
/// is the largest single-block message and 112 already needs two.
#[test]
fn cost_is_per_block_not_per_byte() {
    let b64 = and_for(8); // 64 bytes: msg ‖ seed. One block.
    let b96 = and_for(12); // 96 bytes: msg ‖ seed ‖ rx. Still one block.
    let b112 = and_for(14); // 112 bytes: spills into a second block.

    // Within a block, growing the message costs only its extra input wires.
    assert!(
        b96 - b64 < 50,
        "two single-block messages differ by {}, which is not block-priced",
        b96 - b64
    );
    // Crossing the boundary costs a whole compression.
    assert!(
        b112 - b96 > 800,
        "crossing into a second block cost only {}",
        b112 - b96
    );
}

#[test]
fn per_block_and_count() {
    let one = and_for(4); // 32 bytes: the seed.
    let two = and_for(16); // 128 bytes: padding forces a second block.
    let marginal = two - one;
    println!("SHA-512: {one} AND for one block, {two} for two, {marginal} marginal");

    // Guards the figures the README quotes. Wide enough to survive a builder change that
    // shifts fixed overhead, tight enough to catch a real regression or a mislabelling.
    assert!(
        (890..=950).contains(&one),
        "one-block SHA-512 is {one} AND, outside the range the README quotes"
    );
    assert!(
        (880..=950).contains(&marginal),
        "marginal AND per additional block is {marginal}, outside the README's range"
    );
}

/// Both hashes in this relation are single-block, which is why SHA-512 is a rounding
/// error next to the scalar multiplication. If a future change pushes either into a
/// second block, that is worth noticing.
#[test]
fn both_hashes_in_this_relation_are_single_block() {
    let seed_only = and_for(4); // SHA-512(seed), 32 bytes
    let det = and_for(8); // SHA-512(msg ‖ seed), 64 bytes
    let rand = and_for(12); // SHA-512(msg ‖ seed ‖ rx), 96 bytes
    for (name, n) in [("seed", seed_only), ("R_det hx", det), ("R_rand hx", rand)] {
        assert!(
            n < 1_000,
            "{name} costs {n} AND, so it is no longer single-block"
        );
    }
}
