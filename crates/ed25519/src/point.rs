//! Ed25519 points in extended twisted-Edwards coordinates.
//!
//! A point is `(X, Y, Z, T)` with affine value `(X/Z, Y/Z)` and `T = XY/Z`. The curve is
//! `-x^2 + y^2 = 1 + d x^2 y^2`, i.e. `a = -1`, which admits the fastest complete
//! addition formulas.
//!
//! # Completeness
//!
//! Addition here uses the Hisil–Wong–Carter–Dawson mixed formula (`madd-2008-hwcd-3`)
//! against a precomputed "niels" point `(Y+X, Y-X, 2dT)`. It is **complete**: correct for
//! equal inputs, for the identity, and for every other pair. There are therefore no
//! exceptional cases, no equality tests, and no branches anywhere in this module.
//!
//! That is a structural advantage over the short-Weierstrass case. binius64's
//! `Secp256k1::add_incomplete` handles the point at infinity but rejects equal inputs,
//! and its MSM documents a residual "vanishingly low" collision probability. Nothing
//! analogous is needed here — the completeness is a property of the formula, not an
//! assumption about inputs.
//!
//! # Field representation
//!
//! Coordinates are `[0, 2p)` representatives (see [`crate::field`]). Since the formulas
//! contain no equality tests, no canonicalisation is required anywhere in this module.

use binius_circuits::bignum::BigUint;
use binius_frontend::CircuitBuilder;

use crate::field::Fp;

/// A point in extended coordinates `(X, Y, Z, T)`.
#[derive(Clone)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
    pub z: BigUint,
    pub t: BigUint,
}

/// A precomputed point in niels form `(Y+X, Y-X, 2dT)`.
///
/// The comb tables hold these as circuit constants, which is why the representation is
/// chosen for the *adder's* convenience rather than the producer's.
#[derive(Clone)]
pub struct Niels {
    pub y_plus_x: BigUint,
    pub y_minus_x: BigUint,
    pub t2d: BigUint,
}

impl Point {
    /// The identity `(0, 1)`, i.e. `(X, Y, Z, T) = (0, 1, 1, 0)`.
    pub fn identity(b: &CircuitBuilder, f: &Fp) -> Self {
        let zero = f.constant(b, &num_bigint::BigUint::from(0u32));
        let one = f.constant(b, &num_bigint::BigUint::from(1u32));
        Point { x: zero.clone(), y: one.clone(), z: one, t: zero }
    }

    /// Mixed addition against a niels-form point: seven field multiplications.
    ///
    /// ```text
    /// A = (Y1 - X1) · y_minus_x      E = B - A      X3 = E · F
    /// B = (Y1 + X1) · y_plus_x       F = D - C      Y3 = G · H
    /// C = T1 · t2d                   G = D + C      T3 = E · H
    /// D = Z1 + Z1                    H = B + A      Z3 = F · G
    /// ```
    pub fn add_niels(&self, b: &CircuitBuilder, f: &Fp, other: &Niels) -> Self {
        let a = f.mul(b, &f.sub(b, &self.y, &self.x), &other.y_minus_x);
        let bb = f.mul(b, &f.add(b, &self.y, &self.x), &other.y_plus_x);
        let c = f.mul(b, &self.t, &other.t2d);
        let d = f.add(b, &self.z, &self.z);

        let e = f.sub(b, &bb, &a);
        let ff = f.sub(b, &d, &c);
        let g = f.add(b, &d, &c);
        let h = f.add(b, &bb, &a);

        Point {
            x: f.mul(b, &e, &ff),
            y: f.mul(b, &g, &h),
            t: f.mul(b, &e, &h),
            z: f.mul(b, &ff, &g),
        }
    }

    /// The niels form of the identity: `(1, 1, 0)`.
    ///
    /// Table entry zero in every comb window, so the digit-zero case needs no special
    /// handling — the formula absorbs it.
    pub fn niels_identity(b: &CircuitBuilder, f: &Fp) -> Niels {
        let zero = f.constant(b, &num_bigint::BigUint::from(0u32));
        let one = f.constant(b, &num_bigint::BigUint::from(1u32));
        Niels { y_plus_x: one.clone(), y_minus_x: one, t2d: zero }
    }
}

#[cfg(test)]
mod tests {
    use binius_core::verify::verify_constraints;
    use binius_frontend::CircuitBuilder;
    use num_bigint::BigUint as NB;

    use super::*;
    use crate::{
        consts::p_bigint,
        host::{Affine, add_affine, basepoint, identity as host_identity, to_niels},
    };

    /// Build `pt` as a circuit constant in extended coordinates from an affine point.
    fn const_point(b: &CircuitBuilder, f: &Fp, pt: &Affine) -> Point {
        let p = p_bigint();
        let (x, y) = pt;
        Point {
            x: f.constant(b, x),
            y: f.constant(b, y),
            z: f.constant(b, &NB::from(1u32)),
            t: f.constant(b, &((x * y) % &p)),
        }
    }

    fn const_niels(b: &CircuitBuilder, f: &Fp, pt: &Affine) -> Niels {
        let (ypx, ymx, t2d) = to_niels(pt);
        Niels {
            y_plus_x: f.constant(b, &ypx),
            y_minus_x: f.constant(b, &ymx),
            t2d: f.constant(b, &t2d),
        }
    }

    /// Assert in-circuit that `lhs + rhs` equals `expected`, comparing projectively:
    /// `X3 ≡ x_expected · Z3` and `Y3 ≡ y_expected · Z3 (mod p)`.
    ///
    /// Cross-multiplying avoids an inversion and is exactly how the affine conversion in
    /// `compress` will pin its result, so this exercises the same relation.
    fn assert_sum_is(lhs: &Affine, rhs: &Affine, expected: &Affine) {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);

        let p1 = const_point(&b, &f, lhs);
        let n2 = const_niels(&b, &f, rhs);
        let sum = p1.add_niels(&b, &f, &n2);

        let xe = f.constant(&b, &expected.0);
        let ye = f.constant(&b, &expected.1);
        f.assert_congruent(&b, "x", &sum.x, &f.mul(&b, &xe, &sum.z));
        f.assert_congruent(&b, "y", &sum.y, &f.mul(&b, &ye, &sum.z));

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        cs.populate_wire_witness(&mut w).expect("constraints unsatisfiable");
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
    }

    /// G + G, against the dalek-anchored host reference.
    #[test]
    fn add_matches_reference_doubling() {
        let g = basepoint();
        let expected = add_affine(&g, &g);
        assert_sum_is(&g, &g, &expected);
    }

    /// Adding the identity must be a no-op. This is what makes the comb's zero-digit
    /// table entry safe without a special case.
    #[test]
    fn adding_identity_is_noop() {
        let g = basepoint();
        assert_sum_is(&g, &host_identity(), &g);
    }

    /// Identity + identity is still the identity — the degenerate case where both
    /// operands are the neutral element.
    #[test]
    fn identity_plus_identity_is_identity() {
        let id = host_identity();
        assert_sum_is(&id, &id, &id);
    }

    /// Distinct points, distinct multiples, and repeated doubling — the paths a scalar
    /// multiplication actually exercises.
    #[test]
    fn add_matches_reference_across_multiples() {
        let g = basepoint();
        let mut acc = g.clone();
        let mut multiples = vec![g.clone()];
        for _ in 0..8 {
            acc = add_affine(&acc, &g);
            multiples.push(acc.clone());
        }

        // kG + G for a range of k.
        for m in &multiples {
            let expected = add_affine(m, &g);
            assert_sum_is(m, &g, &expected);
        }
        // And a few sums of two distinct non-trivial multiples.
        for (i, j) in [(0usize, 3usize), (1, 5), (2, 8), (4, 4)] {
            let expected = add_affine(&multiples[i], &multiples[j]);
            assert_sum_is(&multiples[i], &multiples[j], &expected);
        }
    }

    /// A wrong expected value must be rejected — otherwise the checks above are vacuous.
    #[test]
    fn assert_sum_rejects_wrong_result() {
        let g = basepoint();
        let wrong = add_affine(&g, &g); // 2G, but we claim it is G + identity
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);

        let p1 = const_point(&b, &f, &g);
        let n2 = const_niels(&b, &f, &host_identity());
        let sum = p1.add_niels(&b, &f, &n2);

        let xe = f.constant(&b, &wrong.0);
        f.assert_congruent(&b, "x", &sum.x, &f.mul(&b, &xe, &sum.z));

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        assert!(
            cs.populate_wire_witness(&mut w).is_err(),
            "accepted a wrong sum"
        );
    }
}

#[cfg(test)]
mod witness_tests {
    use binius_core::verify::verify_constraints;
    use binius_frontend::CircuitBuilder;
    use num_bigint::BigUint as NB;

    use super::*;
    use crate::{
        consts::{N_LIMBS, p_bigint},
        field::Fp,
        host::{add_affine, basepoint, to_niels},
    };

    fn to_limbs(v: &NB) -> [u64; N_LIMBS] {
        let mut out = [0u64; N_LIMBS];
        for (i, d) in v.iter_u64_digits().enumerate() {
            out[i] = d;
        }
        out
    }

    /// The same check as `add_matches_reference_doubling`, but with the accumulator
    /// supplied as a **witness** rather than a constant.
    ///
    /// Every other test in this module builds its points from `f.constant(..)`, which
    /// binius64 may fold at build time — so those tests could in principle pass without
    /// the addition constraints ever being exercised on non-constant data. In the real
    /// circuit the accumulator is witness-derived, so this is the representative case.
    #[test]
    fn add_works_on_witness_points() {
        let p = p_bigint();
        let g = basepoint();
        let expected = add_affine(&g, &g);

        let b = CircuitBuilder::new();
        let f = Fp::new(&b);

        // Accumulator as witness; the table entry stays constant, as it is in the comb.
        let px = BigUint::new_witness(&b, N_LIMBS);
        let py = BigUint::new_witness(&b, N_LIMBS);
        let pz = BigUint::new_witness(&b, N_LIMBS);
        let pt = BigUint::new_witness(&b, N_LIMBS);
        let point = Point { x: px.clone(), y: py.clone(), z: pz.clone(), t: pt.clone() };

        let (ypx, ymx, t2d) = to_niels(&g);
        let niels = Niels {
            y_plus_x: f.constant(&b, &ypx),
            y_minus_x: f.constant(&b, &ymx),
            t2d: f.constant(&b, &t2d),
        };

        let sum = point.add_niels(&b, &f, &niels);
        let xe = f.constant(&b, &expected.0);
        let ye = f.constant(&b, &expected.1);
        f.assert_congruent(&b, "x", &sum.x, &f.mul(&b, &xe, &sum.z));
        f.assert_congruent(&b, "y", &sum.y, &f.mul(&b, &ye, &sum.z));

        let cs = b.build();
        // The addition must produce real constraints rather than folding to nothing.
        // Without this the test could pass vacuously on a constant-folded circuit.
        let n_and = cs.constraint_system().n_and_constraints();
        let n_imul = cs.constraint_system().imul_constraints.len();
        assert!(
            n_and > 100 && n_imul > 50,
            "circuit folded away ({n_and} AND, {n_imul} IMUL); test would be vacuous"
        );

        let mut w = cs.new_witness_filler();
        px.populate_limbs(&mut w, &to_limbs(&g.0));
        py.populate_limbs(&mut w, &to_limbs(&g.1));
        pz.populate_limbs(&mut w, &to_limbs(&NB::from(1u32)));
        pt.populate_limbs(&mut w, &to_limbs(&((&g.0 * &g.1) % &p)));
        cs.populate_wire_witness(&mut w).expect("constraints unsatisfiable");
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
    }

    /// A tampered accumulator coordinate must be rejected.
    #[test]
    fn witness_addition_rejects_tampered_input() {
        let p = p_bigint();
        let g = basepoint();
        let expected = add_affine(&g, &g);

        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let px = BigUint::new_witness(&b, N_LIMBS);
        let py = BigUint::new_witness(&b, N_LIMBS);
        let pz = BigUint::new_witness(&b, N_LIMBS);
        let pt = BigUint::new_witness(&b, N_LIMBS);
        let point = Point { x: px.clone(), y: py.clone(), z: pz.clone(), t: pt.clone() };

        let (ypx, ymx, t2d) = to_niels(&g);
        let niels = Niels {
            y_plus_x: f.constant(&b, &ypx),
            y_minus_x: f.constant(&b, &ymx),
            t2d: f.constant(&b, &t2d),
        };
        let sum = point.add_niels(&b, &f, &niels);
        let xe = f.constant(&b, &expected.0);
        f.assert_congruent(&b, "x", &sum.x, &f.mul(&b, &xe, &sum.z));

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        let mut bad = to_limbs(&g.0);
        bad[0] ^= 1; // flip one bit of the x-coordinate
        px.populate_limbs(&mut w, &bad);
        py.populate_limbs(&mut w, &to_limbs(&g.1));
        pz.populate_limbs(&mut w, &to_limbs(&NB::from(1u32)));
        pt.populate_limbs(&mut w, &to_limbs(&((&g.0 * &g.1) % &p)));

        assert!(
            cs.populate_wire_witness(&mut w).is_err(),
            "accepted a tampered accumulator"
        );
    }
}

#[cfg(test)]
mod cost {
    use binius_core::constraint_system::ConstraintSystem;
    use binius_frontend::CircuitBuilder;

    use super::*;
    use crate::{consts::N_LIMBS, field::Fp, host::{basepoint, to_niels}};

    /// Build a chain of `n` mixed additions and return `(AND, IMUL)`.
    fn cost_of_chain(n: usize) -> (usize, usize) {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let mut pt = Point {
            x: BigUint::new_witness(&b, N_LIMBS),
            y: BigUint::new_witness(&b, N_LIMBS),
            z: BigUint::new_witness(&b, N_LIMBS),
            t: BigUint::new_witness(&b, N_LIMBS),
        };
        let (ypx, ymx, t2d) = to_niels(&basepoint());
        let niels = Niels {
            y_plus_x: f.constant(&b, &ypx),
            y_minus_x: f.constant(&b, &ymx),
            t2d: f.constant(&b, &t2d),
        };
        for _ in 0..n {
            pt = pt.add_niels(&b, &f, &niels);
        }
        let cs = b.build();
        let sys: &ConstraintSystem = cs.constraint_system();
        (sys.n_and_constraints(), sys.imul_constraints.len())
    }

    /// Report the marginal cost of one mixed addition.
    ///
    /// Taking a difference between chain lengths cancels the fixed setup, so this is the
    /// true per-addition cost rather than an amortised one. Recorded rather than
    /// asserted against a target: it is the measurement Task 4's projection rests on.
    #[test]
    fn report_add_niels_cost() {
        let (a1, m1) = cost_of_chain(1);
        let (a2, m2) = cost_of_chain(2);
        let (and, imul) = (a2 - a1, m2 - m1);
        println!("one add_niels: {and} AND, {imul} IMUL");
        println!("64 windows:    {} AND, {} IMUL", and * 64, imul * 64);

        // Guard against a silent regression, generously bounded.
        assert!(and < 1200, "addition cost regressed: {and} AND");
        assert!(imul < 250, "addition cost regressed: {imul} IMUL");
    }
}
