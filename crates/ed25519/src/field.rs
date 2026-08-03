//! `F_p` arithmetic for Ed25519, represented modulo `2p`.
//!
//! Every value is a representative in `[0, 2p)`; each residue class mod `p` has two,
//! `x` and `x + p`. The operations inherited from [`PseudoMersennePrimeField`] preserve
//! that range — `reduce_product` asserts `remainder < modulus` internally, so the
//! invariant is enforced by the library rather than assumed of callers.
//!
//! Canonicalise explicitly wherever a value's *bits* are read rather than only its
//! residue class: comparison against a public key, and x-parity for point compression.
//! Complete twisted-Edwards addition contains no equality tests, so those are the only
//! places in this crate that need it.
//!
//! # What must not be used
//!
//! [`PseudoMersennePrimeField::inverse`] and `::div` assume a **prime** modulus, and
//! `2p` is not prime. They are deliberately not re-exposed here. The one inversion the
//! circuit needs (`Z^-1` for extended→affine) is done as a hint plus a multiplication
//! check instead — see the `compress` module.
//!
//! [`PseudoMersennePrimeField`]: binius_circuits::bignum::PseudoMersennePrimeField

use binius_circuits::bignum::{
    BigUint, PseudoMersennePrimeField, assert_eq as biguint_assert_eq, biguint_lt, sub,
};
use binius_frontend::{CircuitBuilder, Wire};

use crate::consts::{N_LIMBS, TWO_P_PO2, TWO_P_SUBTRAHEND, p_bigint};

/// Ed25519's coordinate field, worked modulo `2p = 2^256 - 38`.
pub struct Fp {
    inner: PseudoMersennePrimeField,
    p: BigUint,
}

impl Fp {
    pub fn new(b: &CircuitBuilder) -> Self {
        let inner = PseudoMersennePrimeField::new(b, TWO_P_PO2, &[TWO_P_SUBTRAHEND]);
        assert_eq!(inner.limbs_len(), N_LIMBS);
        let p = BigUint::new_constant(b, &p_bigint()).zero_extend(b, N_LIMBS);
        Self { inner, p }
    }

    /// A circuit constant, zero-extended to the field's limb count.
    pub fn constant(&self, b: &CircuitBuilder, v: &num_bigint::BigUint) -> BigUint {
        BigUint::new_constant(b, v).zero_extend(b, N_LIMBS)
    }

    pub fn add(&self, b: &CircuitBuilder, x: &BigUint, y: &BigUint) -> BigUint {
        self.inner.add(b, x, y)
    }

    pub fn sub(&self, b: &CircuitBuilder, x: &BigUint, y: &BigUint) -> BigUint {
        self.inner.sub(b, x, y)
    }

    pub fn mul(&self, b: &CircuitBuilder, x: &BigUint, y: &BigUint) -> BigUint {
        self.inner.mul(b, x, y)
    }

    pub fn square(&self, b: &CircuitBuilder, x: &BigUint) -> BigUint {
        self.inner.square(b, x)
    }

    /// Map a representative in `[0, 2p)` to the unique one in `[0, p)`.
    ///
    /// Subtracts `p` exactly when `x >= p`. `zero_unless` gives a masked `p` so the
    /// subtraction is unconditional in circuit terms — no branch on a secret.
    pub fn canonicalize(&self, b: &CircuitBuilder, x: &BigUint) -> BigUint {
        let lt = biguint_lt(b, x, &self.p);
        let ge = b.bnot(lt);
        let amount = self.p.zero_unless(b, ge);
        sub(b, x, &amount)
    }

    /// Assert `x ≡ y (mod p)` for values held as `[0, 2p)` representatives.
    ///
    /// Plain limb equality is wrong here: `x` and `x + p` are the same residue but
    /// different bit patterns, so both sides must be canonicalised first.
    pub fn assert_congruent(&self, b: &CircuitBuilder, name: &str, x: &BigUint, y: &BigUint) {
        let xc = self.canonicalize(b, x);
        let yc = self.canonicalize(b, y);
        biguint_assert_eq(b, name, &xc, &yc);
    }

    /// MSB-boolean: is `x ≡ 0 (mod p)`? True for both representatives, `0` and `p`.
    pub fn is_zero_mod_p(&self, b: &CircuitBuilder, x: &BigUint) -> Wire {
        let xc = self.canonicalize(b, x);
        xc.is_zero(b)
    }
}

#[cfg(test)]
mod tests {
    use binius_circuits::bignum::BigUint;
    use binius_core::{verify::verify_constraints, word::Word};
    use binius_frontend::CircuitBuilder;
    use num_bigint::BigUint as NB;
    use proptest::{prelude::*, test_runner::TestCaseError};

    use super::*;
    use crate::consts::{N_LIMBS, p_bigint};

    fn to_limbs(v: &NB) -> [u64; N_LIMBS] {
        let mut out = [0u64; N_LIMBS];
        for (i, d) in v.iter_u64_digits().enumerate() {
            out[i] = d;
        }
        out
    }

    /// Canonicalising a representative in `[p, 2p)` must return the one in `[0, p)`.
    ///
    /// This is the whole point of the mod-2p representation: two representatives per
    /// residue, and anything reading a value's *bits* needs the canonical one.
    #[test]
    fn canonicalize_reduces_upper_representative() {
        let p = p_bigint();
        let x_val = &p + NB::from(7u32); // the non-canonical representative of 7

        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let out = f.canonicalize(&b, &x);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&x_val));
        cs.populate_wire_witness(&mut w).unwrap();
        // Read before `into_value_vec` consumes the filler.
        let got: Vec<Word> = out.limbs.iter().map(|l| w[*l]).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        for (i, g) in got.iter().enumerate() {
            let expected = if i == 0 { 7u64 } else { 0u64 };
            assert_eq!(*g, Word::from_u64(expected), "limb {i}");
        }
    }

    /// A value already in `[0, p)` must pass through unchanged.
    #[test]
    fn canonicalize_is_identity_below_p() {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let out = f.canonicalize(&b, &x);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&NB::from(12345u32)));
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<Word> = out.limbs.iter().map(|l| w[*l]).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        assert_eq!(got[0], Word::from_u64(12345));
        for g in &got[1..] {
            assert_eq!(*g, Word::from_u64(0));
        }
    }

    /// Draw a representative from all of `[0, 2p)`, deliberately including the upper
    /// half that a naive implementation never produces in testing but an adversarial
    /// witness can supply.
    fn arb_rep() -> impl Strategy<Value = NB> {
        proptest::array::uniform4(any::<u64>()).prop_map(|limbs| {
            let mut v = NB::from(0u32);
            for (i, l) in limbs.iter().enumerate() {
                v += NB::from(*l) << (64 * i as u32);
            }
            v % crate::consts::two_p_bigint()
        })
    }

    /// Run `op` in-circuit on two `[0, 2p)` representatives and check the canonicalised
    /// result against the reference computed mod `p`.
    ///
    /// This is the test that catches a missing canonicalisation; nothing else will.
    fn check_binop(
        x_val: &NB,
        y_val: &NB,
        expected: &NB,
        op: impl Fn(&Fp, &CircuitBuilder, &BigUint, &BigUint) -> BigUint,
    ) -> Result<(), TestCaseError> {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let y = BigUint::new_witness(&b, N_LIMBS);
        let out = f.canonicalize(&b, &op(&f, &b, &x, &y));

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(x_val));
        y.populate_limbs(&mut w, &to_limbs(y_val));
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<u64> = out.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        prop_assert_eq!(to_limbs(expected).to_vec(), got);
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn mul_agrees_mod_p(x in arb_rep(), y in arb_rep()) {
            let p = p_bigint();
            let expected = (&x * &y) % &p;
            check_binop(&x, &y, &expected, |f, b, a, c| f.mul(b, a, c))?;
        }

        #[test]
        fn add_agrees_mod_p(x in arb_rep(), y in arb_rep()) {
            let p = p_bigint();
            let expected = (&x + &y) % &p;
            check_binop(&x, &y, &expected, |f, b, a, c| f.add(b, a, c))?;
        }

        #[test]
        fn sub_agrees_mod_p(x in arb_rep(), y in arb_rep()) {
            let p = p_bigint();
            let two_p = crate::consts::two_p_bigint();
            // Reference: subtraction is mod 2p in circuit, then reduced mod p.
            let expected = ((&x + &two_p - &y) % &two_p) % &p;
            check_binop(&x, &y, &expected, |f, b, a, c| f.sub(b, a, c))?;
        }
    }

    /// Edge cases the random property tests will essentially never generate.
    ///
    /// `sub(x, y)` is implemented as `add(x, modulus - y)`, so `y = 0` feeds *exactly*
    /// the modulus into `add` — violating `add`'s documented precondition that both
    /// inputs are reduced. It is still correct, but only because the carry and the
    /// wrapping subtraction cancel: `sum = x + 2p` overflows past `2^256` exactly when
    /// `x >= 38`, and the wrapped subtraction borrows back by the same amount. That is
    /// a fragile-looking argument, so it gets explicit coverage rather than relying on
    /// a random draw hitting `y = 0`.
    #[test]
    fn sub_edge_cases_around_zero_and_modulus() {
        let p = p_bigint();
        let two_p = crate::consts::two_p_bigint();
        let cases: &[(NB, NB)] = &[
            (NB::from(0u32), NB::from(0u32)),
            (NB::from(5u32), NB::from(0u32)),   // x < 38: no carry
            (NB::from(100u32), NB::from(0u32)), // x >= 38: carry path
            (NB::from(37u32), NB::from(0u32)),  // boundary
            (NB::from(38u32), NB::from(0u32)),  // boundary
            (NB::from(0u32), NB::from(1u32)),   // wraps to 2p - 1
            (&p - NB::from(1u32), NB::from(0u32)),
            (p.clone(), NB::from(0u32)),
            (&two_p - NB::from(1u32), NB::from(0u32)),
            (NB::from(0u32), &two_p - NB::from(1u32)),
        ];

        for (x, y) in cases {
            let expected = ((x + &two_p - y) % &two_p) % &p;
            check_binop(x, y, &expected, |f, b, a, c| f.sub(b, a, c))
                .unwrap_or_else(|e| panic!("sub({x}, {y}) failed: {e:?}"));
        }
    }

    /// `add` with an operand at each end of the range, including values that force the
    /// single-carry path the implementation relies on.
    #[test]
    fn add_edge_cases_at_range_boundaries() {
        let p = p_bigint();
        let two_p = crate::consts::two_p_bigint();
        let max = &two_p - NB::from(1u32);
        let cases: &[(NB, NB)] = &[
            (NB::from(0u32), NB::from(0u32)),
            (max.clone(), max.clone()), // sum just under 2*modulus
            (max.clone(), NB::from(1u32)), // wraps to exactly 0
            (p.clone(), p.clone()),     // 2p, wraps to 0
            (&p - NB::from(1u32), NB::from(1u32)),
        ];

        for (x, y) in cases {
            let expected = ((x + y) % &two_p) % &p;
            check_binop(x, y, &expected, |f, b, a, c| f.add(b, a, c))
                .unwrap_or_else(|e| panic!("add({x}, {y}) failed: {e:?}"));
        }
    }

    /// `mul` at the range boundaries, where the product bound `< 4p^2 < 2^512` is tightest.
    #[test]
    fn mul_edge_cases_at_range_boundaries() {
        let p = p_bigint();
        let two_p = crate::consts::two_p_bigint();
        let max = &two_p - NB::from(1u32);
        let cases: &[(NB, NB)] = &[
            (NB::from(0u32), max.clone()),
            (NB::from(1u32), max.clone()),
            (max.clone(), max.clone()), // the tightest product
            (p.clone(), p.clone()),
            (p.clone(), NB::from(2u32)),
        ];

        for (x, y) in cases {
            let expected = (x * y) % &p;
            check_binop(x, y, &expected, |f, b, a, c| f.mul(b, a, c))
                .unwrap_or_else(|e| panic!("mul({x}, {y}) failed: {e:?}"));
        }
    }

    /// Both representatives of the same residue must compare congruent.
    #[test]
    fn assert_congruent_accepts_both_representatives() {
        let p = p_bigint();
        let lo = NB::from(42u32);
        let hi = &p + &lo;

        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let y = BigUint::new_witness(&b, N_LIMBS);
        f.assert_congruent(&b, "same_residue", &x, &y);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&lo));
        y.populate_limbs(&mut w, &to_limbs(&hi));
        cs.populate_wire_witness(&mut w).unwrap();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
    }

    /// Distinct residues must be rejected — otherwise the check is vacuous.
    #[test]
    fn assert_congruent_rejects_distinct_residues() {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let y = BigUint::new_witness(&b, N_LIMBS);
        f.assert_congruent(&b, "same_residue", &x, &y);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&NB::from(42u32)));
        y.populate_limbs(&mut w, &to_limbs(&NB::from(43u32)));
        let rejected = cs.populate_wire_witness(&mut w).is_err();
        assert!(rejected, "accepted two distinct residues");
    }

    /// `p` is a representative of zero, so `is_zero_mod_p` must accept it.
    #[test]
    fn is_zero_mod_p_accepts_p() {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let z = f.is_zero_mod_p(&b, &x);
        b.assert_true("is_zero", z);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&p_bigint()));
        cs.populate_wire_witness(&mut w).unwrap();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();
    }

    /// `p` itself is the non-canonical representative of zero.
    #[test]
    fn canonicalize_maps_p_to_zero() {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let x = BigUint::new_witness(&b, N_LIMBS);
        let out = f.canonicalize(&b, &x);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&p_bigint()));
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<Word> = out.limbs.iter().map(|l| w[*l]).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        for g in &got {
            assert_eq!(*g, Word::from_u64(0));
        }
    }
}

#[cfg(test)]
mod imul_breakdown {
    use binius_circuits::bignum::{BigUint, textbook_mul};
    use binius_frontend::CircuitBuilder;

    use super::*;
    use crate::consts::N_LIMBS;

    fn imul_of(f: impl Fn(&CircuitBuilder)) -> usize {
        let b = CircuitBuilder::new();
        f(&b);
        b.build().constraint_system().imul_constraints.len()
    }

    /// Where do the 24 IMUL per field multiplication go?
    #[test]
    fn report_imul_breakdown() {
        let base = imul_of(|b| {
            let _ = Fp::new(b);
            let _ = BigUint::new_witness(b, N_LIMBS);
            let _ = BigUint::new_witness(b, N_LIMBS);
        });
        let raw_product = imul_of(|b| {
            let x = BigUint::new_witness(b, N_LIMBS);
            let y = BigUint::new_witness(b, N_LIMBS);
            let _ = textbook_mul(b, &x, &y);
        });
        let full_mul = imul_of(|b| {
            let f = Fp::new(b);
            let x = BigUint::new_witness(b, N_LIMBS);
            let y = BigUint::new_witness(b, N_LIMBS);
            let _ = f.mul(b, &x, &y);
        });
        println!("\n  4x4 textbook product only : {raw_product} IMUL");
        println!("  full Fp::mul (with reduce): {} IMUL", full_mul - base);
        println!("  => modular reduction costs: {} IMUL", (full_mul - base) - raw_product);
        println!();
    }
}
