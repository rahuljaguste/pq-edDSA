//! Pins the circuit's size.
//!
//! Not a performance guard — a **correctness guard for a measured constant**.
//!
//! `config::RECOMMENDED_N_DUMMY_CONSTRAINTS` was chosen by measuring where raising the ZK
//! blinding stops being free. That cliff sits
//! at 2,133 for *this* circuit, because blinding pads the outer Spartan system whose size
//! this circuit determines. If the circuit changes materially the cliff moves, and 2,048
//! could silently stop being free — or a much higher value could become available.
//!
//! Nothing else would detect that, so this test does.

use binius_frontend::CircuitBuilder;
use pq_eddsa::{circuit::PqEddsaCircuit, config::RECOMMENDED_N_DUMMY_CONSTRAINTS};

/// Measured 2026-08-03 at comb window 6, after signed-digit recoding.
const EXPECTED_AND: usize = 57_314;
const EXPECTED_IMUL: usize = 7_428;
const EXPECTED_PRIVATE: usize = 69_598;

/// Allow small drift without failing on every incidental change.
const TOLERANCE: f64 = 0.05;

fn within(actual: usize, expected: usize) -> bool {
    let lo = (expected as f64 * (1.0 - TOLERANCE)) as usize;
    let hi = (expected as f64 * (1.0 + TOLERANCE)) as usize;
    (lo..=hi).contains(&actual)
}

#[test]
fn circuit_size_matches_the_blinding_measurement() {
    let b = CircuitBuilder::new();
    let _ = PqEddsaCircuit::build(&b);
    let cs = b.build();
    let s = cs.constraint_system();
    let (and, imul, private) = (s.n_and_constraints(), s.imul_constraints.len(), s.n_private);

    let advice = format!(
        "\n\nCircuit size changed: AND {and} (was {EXPECTED_AND}), \
         IMUL {imul} (was {EXPECTED_IMUL}), private {private} (was {EXPECTED_PRIVATE}).\n\
         The free ceiling for n_dummy_constraints was measured at 2,133 for the current size, \
         and RECOMMENDED_N_DUMMY_CONSTRAINTS = {RECOMMENDED_N_DUMMY_CONSTRAINTS} was chosen \
         to sit inside it.\n\
         Re-run the blinding measurement before trusting that value, then update these constants.\n"
    );

    assert!(within(and, EXPECTED_AND), "{advice}");
    assert!(within(imul, EXPECTED_IMUL), "{advice}");
    assert!(within(private, EXPECTED_PRIVATE), "{advice}");
}

/// The recommendation must stay inside the measured cliff.
///
/// Trivially true today, but it makes the relationship explicit: if someone raises the
/// constant without re-measuring, this fails.
#[test]
fn recommended_blinding_is_inside_the_measured_cliff() {
    /// Measured in the blinding work on the **narrow** build: 2,133 is free, 2,134 is
    /// not. The wide build raises the FRI query count from 232 to 579, which eats into the
    /// same blinding budget, so this ceiling is not known to hold there. See
    /// `config::RECOMMENDED_N_DUMMY_CONSTRAINTS`.
    ///
    /// Notably insensitive to circuit size: an 18% reduction in AND constraints and 15%
    /// in private wires moved this by exactly one. The cliff is set by the outer Spartan
    /// system crossing a padding boundary, and that system's size is dominated by the
    /// protocol's own shape — round count, query budget — rather than by the width of the
    /// circuit being verified. It would move materially if `log_inv_rate` or the security
    /// level changed.
    const MEASURED_CLIFF: usize = 2_133;
    // A compile-time check: raising the constant past the measured cliff should fail the
    // build, not wait for someone to run the tests.
    const _: () = assert!(RECOMMENDED_N_DUMMY_CONSTRAINTS <= MEASURED_CLIFF);
}
