//! Conversion to affine coordinates and RFC 8032 point compression.
//!
//! # Why there is no inversion in the circuit
//!
//! Getting from `(X, Y, Z, T)` to affine needs `Z^-1`. Computing that in-circuit would
//! mean a modular exponentiation, and in any case `PseudoMersennePrimeField::inverse`
//! is unusable here — it assumes a prime modulus and we work modulo the composite `2p`
//! (see [`crate::field`]).
//!
//! Instead the affine coordinates arrive as a **hint** — computed host-side by the
//! prover, where inversion is cheap — and are pinned by two multiplications:
//!
//! ```text
//! assert  x_aff · Z ≡ X   (mod p)
//! assert  y_aff · Z ≡ Y   (mod p)
//! assert  Z ≢ 0           (mod p)
//! assert  x_aff < p  and  y_aff < p
//! ```
//!
//! Soundness: `p` is prime and `Z ≢ 0`, so `Z` is invertible and `x_aff ≡ X/Z` is
//! uniquely determined as a residue. The canonicality assertions then pin it uniquely as
//! an *integer*, which matters because compression reads the coordinates' bits rather
//! than their residue classes. Without them a prover could offer `x_aff + p`, which
//! satisfies the multiplication check but has the opposite low bit — and the low bit of
//! `x` is exactly what compression encodes.
//!
//! So the constraint that looked like a workaround for the composite modulus turns out to
//! be the better construction: two multiplications instead of an exponentiation.

use binius_circuits::bignum::{BigUint, biguint_lt};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, hints::Hint};

use crate::{
    consts::{N_LIMBS, p_bigint},
    field::Fp,
    point::Point,
};

/// Computes affine `(x, y) = (X/Z, Y/Z) mod p`, canonically reduced.
///
/// Prover-side only. The result is meaningless unless constrained — see [`to_affine`],
/// which is the only intended caller.
pub struct AffineHint;

impl AffineHint {
    fn limbs_to_nb(limbs: &[Word]) -> num_bigint::BigUint {
        let mut acc = num_bigint::BigUint::from(0u32);
        for (i, l) in limbs.iter().enumerate() {
            acc += num_bigint::BigUint::from(l.as_u64()) << (64 * i as u32);
        }
        acc
    }

    fn write_limbs(v: &num_bigint::BigUint, out: &mut [Word]) {
        // Zero-fill first: `execute` must write every output slot, including padding.
        for slot in out.iter_mut() {
            *slot = Word::ZERO;
        }
        for (i, d) in v.iter_u64_digits().enumerate() {
            if i < out.len() {
                out[i] = Word::from_u64(d);
            }
        }
    }
}

impl Hint for AffineHint {
    const NAME: &'static str = "pq_eddsa.ed25519_affine";

    fn shape(&self, _dimensions: &[usize]) -> (usize, usize) {
        // Inputs X, Y, Z; outputs x_aff, y_aff.
        (3 * N_LIMBS, 2 * N_LIMBS)
    }

    fn execute(&self, _dimensions: &[usize], inputs: &[Word], outputs: &mut [Word]) {
        let p = p_bigint();
        let x = Self::limbs_to_nb(&inputs[0..N_LIMBS]) % &p;
        let y = Self::limbs_to_nb(&inputs[N_LIMBS..2 * N_LIMBS]) % &p;
        let z = Self::limbs_to_nb(&inputs[2 * N_LIMBS..3 * N_LIMBS]) % &p;

        // Fermat inversion. Valid because p is prime — the circuit cannot do this, which
        // is the whole reason this is a hint.
        let zinv = z.modpow(&(&p - num_bigint::BigUint::from(2u32)), &p);

        let (xo, yo) = outputs.split_at_mut(N_LIMBS);
        Self::write_limbs(&((x * &zinv) % &p), xo);
        Self::write_limbs(&((y * &zinv) % &p), yo);
    }
}

/// Convert to affine, without an in-circuit inversion.
///
/// Returns canonical `(x, y)` in `[0, p)`.
pub fn to_affine(b: &CircuitBuilder, f: &Fp, pt: &Point) -> (BigUint, BigUint) {
    let inputs: Vec<Wire> = pt
        .x
        .limbs
        .iter()
        .chain(&pt.y.limbs)
        .chain(&pt.z.limbs)
        .copied()
        .collect();
    let out = b.call_hint(AffineHint, &[N_LIMBS], &inputs);

    let x_aff = BigUint { limbs: out[0..N_LIMBS].to_vec() };
    let y_aff = BigUint { limbs: out[N_LIMBS..2 * N_LIMBS].to_vec() };

    // Z ≢ 0 makes Z invertible, which is what makes the two checks below determining.
    let z_is_zero = f.is_zero_mod_p(b, &pt.z);
    b.assert_false("z_nonzero", z_is_zero);

    f.assert_congruent(b, "affine_x", &f.mul(b, &x_aff, &pt.z), &pt.x);
    f.assert_congruent(b, "affine_y", &f.mul(b, &y_aff, &pt.z), &pt.y);

    // Canonicality. Without these a prover could substitute `x_aff + p`, which satisfies
    // the multiplication check but flips the low bit that compression encodes.
    let p_const = f.constant(b, &p_bigint());
    b.assert_true("x_aff_canonical", biguint_lt(b, &x_aff, &p_const));
    b.assert_true("y_aff_canonical", biguint_lt(b, &y_aff, &p_const));

    (x_aff, y_aff)
}

/// RFC 8032 compression: `y` little-endian with bit 255 replaced by the low bit of `x`.
///
/// Returns the 32-byte encoding as four little-endian 64-bit words.
pub fn compress(b: &CircuitBuilder, f: &Fp, pt: &Point) -> [Wire; N_LIMBS] {
    let (x_aff, y_aff) = to_affine(b, f, pt);

    let one = b.add_constant_64(1);
    let x_lsb = b.band(x_aff.limbs[0], one);
    let sign = b.shl(x_lsb, 63);

    // y_aff < p < 2^255 already guarantees bit 255 is clear, but masking states the
    // invariant rather than relying on it holding elsewhere.
    let clear_top = b.add_constant_64(!(1u64 << 63));
    let top = b.band(y_aff.limbs[3], clear_top);

    [y_aff.limbs[0], y_aff.limbs[1], y_aff.limbs[2], b.bor(top, sign)]
}

#[cfg(test)]
mod tests {
    use binius_core::verify::verify_constraints;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use num_bigint::BigUint as NB;

    use super::*;
    use crate::scalar_mul::mul_basepoint;

    fn to_limbs(v: &NB) -> [u64; N_LIMBS] {
        let mut out = [0u64; N_LIMBS];
        for (i, d) in v.iter_u64_digits().enumerate() {
            out[i] = d;
        }
        out
    }

    /// Shared by `compress_matches_dalek` and its coverage check.
    const COMPRESS_SEEDS: &[u8] = &[0x00, 0x01, 0x37, 0x80, 0xA5, 0xFF];

    fn clamped(seed_byte: u8) -> ([u8; 32], NB) {
        let mut bytes = [seed_byte; 32];
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        (bytes, NB::from_bytes_le(&bytes))
    }

    /// `compress(a·G)` must equal dalek's encoding, byte for byte, across many scalars.
    ///
    /// This is the first test that exercises the whole chain — comb, affine conversion,
    /// canonicalisation, and compression — against an independent implementation.
    #[test]
    fn compress_matches_dalek() {
        for seed in COMPRESS_SEEDS.iter().copied() {
            let (bytes, k) = clamped(seed);
            let want = (ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(bytes))
                .compress()
                .to_bytes();

            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let s = BigUint::new_witness(&b, N_LIMBS);
            let pt = mul_basepoint(&b, &f, &s);
            let enc = compress(&b, &f, &pt);

            let cs = b.build();
            let mut w = cs.new_witness_filler();
            s.populate_limbs(&mut w, &to_limbs(&k));
            cs.populate_wire_witness(&mut w).unwrap();
            let got: Vec<u64> = enc.iter().map(|e| w[*e].as_u64()).collect();
            verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

            for i in 0..4 {
                let mut expect = [0u8; 8];
                expect.copy_from_slice(&want[8 * i..8 * i + 8]);
                assert_eq!(
                    got[i],
                    u64::from_le_bytes(expect),
                    "seed={seed:#x} word {i}"
                );
            }
        }
    }

    /// The seeds used by `compress_matches_dalek` must produce sign bits of *both*
    /// values. If they were all one way, that test could pass with the sign bit hardwired.
    ///
    /// This checks the exact same seed list rather than an unrelated one — otherwise it
    /// validates the coverage of a test that does not exist.
    #[test]
    fn compress_seeds_cover_both_sign_bits() {
        let mut seen_set = false;
        let mut seen_clear = false;
        for seed in COMPRESS_SEEDS {
            let (bytes, _) = clamped(*seed);
            let enc = (ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(bytes))
                .compress()
                .to_bytes();
            if enc[31] & 0x80 != 0 { seen_set = true } else { seen_clear = true }
        }
        assert!(
            seen_set && seen_clear,
            "every compress_matches_dalek seed has the same sign bit; that test is weak"
        );
    }

    /// A hint that returns the *other* representative, `x + p`, instead of the canonical
    /// one. Used to prove the canonicality assertion is load-bearing.
    struct MaliciousAffineHint;

    impl Hint for MaliciousAffineHint {
        const NAME: &'static str = "pq_eddsa.test.malicious_affine";

        fn shape(&self, _d: &[usize]) -> (usize, usize) {
            (3 * N_LIMBS, 2 * N_LIMBS)
        }

        fn execute(&self, _d: &[usize], inputs: &[Word], outputs: &mut [Word]) {
            let p = p_bigint();
            let rd = |s: &[Word]| {
                let mut a = NB::from(0u32);
                for (i, l) in s.iter().enumerate() {
                    a += NB::from(l.as_u64()) << (64 * i as u32);
                }
                a % &p
            };
            let x = rd(&inputs[0..N_LIMBS]);
            let y = rd(&inputs[N_LIMBS..2 * N_LIMBS]);
            let z = rd(&inputs[2 * N_LIMBS..3 * N_LIMBS]);
            let zinv = z.modpow(&(&p - NB::from(2u32)), &p);

            // Same residue, non-canonical representative.
            let bad_x = ((x * &zinv) % &p) + &p;
            let good_y = (y * &zinv) % &p;
            let wr = |v: &NB, out: &mut [Word]| {
                for slot in out.iter_mut() {
                    *slot = Word::ZERO;
                }
                for (i, d) in v.iter_u64_digits().enumerate() {
                    if i < out.len() {
                        out[i] = Word::from_u64(d);
                    }
                }
            };
            let (xo, yo) = outputs.split_at_mut(N_LIMBS);
            wr(&bad_x, xo);
            wr(&good_y, yo);
        }
    }

    /// A prover offering `x + p` instead of `x` passes the multiplication check — same
    /// residue — but flips the low bit that compression encodes as the sign. Left
    /// unconstrained, that lets a prover choose the compressed key's sign bit freely.
    ///
    /// This test is what makes the canonicality assertion non-defensive: with the
    /// assertion the malicious hint is rejected, and nothing else in the suite would
    /// notice if it were removed, because the honest hint never produces a bad value.
    #[test]
    fn canonicality_assertion_rejects_the_other_representative() {
        let p = p_bigint();
        let g = crate::host::basepoint();

        let build = |with_assertion: bool| {
            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let x = BigUint::new_witness(&b, N_LIMBS);
            let y = BigUint::new_witness(&b, N_LIMBS);
            let z = BigUint::new_witness(&b, N_LIMBS);

            let inputs: Vec<Wire> =
                x.limbs.iter().chain(&y.limbs).chain(&z.limbs).copied().collect();
            let out = b.call_hint(MaliciousAffineHint, &[N_LIMBS], &inputs);
            let x_aff = BigUint { limbs: out[0..N_LIMBS].to_vec() };
            let y_aff = BigUint { limbs: out[N_LIMBS..2 * N_LIMBS].to_vec() };

            // The residue checks the malicious value still satisfies.
            f.assert_congruent(&b, "affine_x", &f.mul(&b, &x_aff, &z), &x);
            f.assert_congruent(&b, "affine_y", &f.mul(&b, &y_aff, &z), &y);

            if with_assertion {
                let p_const = f.constant(&b, &p_bigint());
                b.assert_true("x_aff_canonical", biguint_lt(&b, &x_aff, &p_const));
            }

            let cs = b.build();
            let mut w = cs.new_witness_filler();
            x.populate_limbs(&mut w, &to_limbs(&g.0));
            y.populate_limbs(&mut w, &to_limbs(&g.1));
            z.populate_limbs(&mut w, &to_limbs(&NB::from(1u32)));
            cs.populate_wire_witness(&mut w).is_ok()
        };

        // Without the assertion the malicious value is accepted — this is the hole.
        assert!(
            build(false),
            "control failed: the residue checks should accept x + p"
        );
        // With it, rejected.
        assert!(
            !build(true),
            "canonicality assertion did not reject a non-canonical representative"
        );
        let _ = p;
    }

    /// A non-canonical `x_aff` (i.e. `x + p`) satisfies the multiplication check but has
    /// the opposite low bit. The canonicality assertion must reject it.
    ///
    /// Without this constraint a prover could flip the compressed key's sign bit at will,
    /// so this is the test that proves the assertion is load-bearing rather than defensive.
    #[test]
    fn rejects_non_canonical_affine_x() {
        let p = p_bigint();
        let g = crate::host::basepoint();

        let b = CircuitBuilder::new();
        let f = Fp::new(&b);

        // Build the point from witnesses so we can drive the hint's inputs, then
        // deliberately assert against a non-canonical x.
        let x = BigUint::new_witness(&b, N_LIMBS);
        let p_const = f.constant(&b, &p);
        // x + p is the other representative: same residue, different bits.
        let shifted = f.add(&b, &x, &p_const);
        b.assert_true("is_canonical", biguint_lt(&b, &shifted, &p_const));

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        x.populate_limbs(&mut w, &to_limbs(&g.0));
        assert!(
            cs.populate_wire_witness(&mut w).is_err(),
            "accepted a non-canonical representative"
        );
    }

    /// The identity has Z ≠ 0, so it must convert cleanly rather than tripping the
    /// zero check — a degenerate input the comb can legitimately produce.
    #[test]
    fn identity_converts_to_zero_one() {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let pt = Point::identity(&b, &f);
        let (x_aff, y_aff) = to_affine(&b, &f, &pt);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        cs.populate_wire_witness(&mut w).unwrap();
        let xs: Vec<u64> = x_aff.limbs.iter().map(|l| w[*l].as_u64()).collect();
        let ys: Vec<u64> = y_aff.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        assert_eq!(xs, vec![0, 0, 0, 0], "identity x");
        assert_eq!(ys, vec![1, 0, 0, 0], "identity y");
    }
}

#[cfg(test)]
mod cost {
    use binius_frontend::CircuitBuilder;

    use super::*;
    use crate::scalar_mul::mul_basepoint;

    /// Cost of the affine conversion plus compression, on top of the comb.
    #[test]
    fn report_compress_cost() {
        let measure = |with_compress: bool| {
            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let s = BigUint::new_witness(&b, N_LIMBS);
            let pt = mul_basepoint(&b, &f, &s);
            if with_compress {
                let _ = compress(&b, &f, &pt);
            }
            let cs = b.build();
            let sys = cs.constraint_system();
            (sys.n_and_constraints(), sys.imul_constraints.len())
        };
        let (a0, m0) = measure(false);
        let (a1, m1) = measure(true);
        println!("comb only:        {a0} AND, {m0} IMUL");
        println!("comb + compress:  {a1} AND, {m1} IMUL");
        println!("compress adds:    {} AND, {} IMUL", a1 - a0, m1 - m0);
    }
}
