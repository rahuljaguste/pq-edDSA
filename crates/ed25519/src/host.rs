//! Host-side Ed25519 arithmetic — plain integers, no circuit.
//!
//! Not test-only, despite what an earlier name suggested: `scalar_mul` calls this at
//! circuit-build time to generate the constant comb tables, so it is production code. It
//! is also the reference tests compare against.
//!
//! Deliberately the most obvious implementation rather than the fastest, because it is a
//! *reference*: if it and the circuit ever disagree, this is the one that should be easy
//! to check by eye.
//!
//! Correctness is anchored to `curve25519-dalek` in the test module, so this is not a
//! second unverified implementation.

use num_bigint::BigUint as NB;

use crate::consts::{d_bigint, p_bigint};

/// Ed25519 base point x-coordinate (RFC 8032 section 5.1).
const GX_DEC: &str = "15112221349535400772501151409588531511454012693041857206046113283949847762202";

/// Ed25519 base point y-coordinate, i.e. `4/5 mod p`.
const GY_DEC: &str = "46316835694926478169428394003475163141307993866256225615783033603165251855960";

/// An affine point.
pub type Affine = (NB, NB);

/// The Ed25519 base point.
pub fn basepoint() -> Affine {
    (GX_DEC.parse().unwrap(), GY_DEC.parse().unwrap())
}

/// The identity `(0, 1)`.
pub fn identity() -> Affine {
    (NB::from(0u32), NB::from(1u32))
}

/// Modular inverse via Fermat. `p` is prime, so this is valid here — unlike in the
/// circuit, which works modulo the composite `2p`.
fn inv(z: &NB) -> NB {
    let p = p_bigint();
    z.modpow(&(&p - NB::from(2u32)), &p)
}

/// Affine addition on the twisted Edwards curve `-x^2 + y^2 = 1 + d x^2 y^2`.
///
/// The unified formula: complete for all inputs, including doubling and the identity.
pub fn add_affine(p1: &Affine, p2: &Affine) -> Affine {
    let p = p_bigint();
    let d = d_bigint();
    let (x1, y1) = p1;
    let (x2, y2) = p2;

    let x1x2 = (x1 * x2) % &p;
    let y1y2 = (y1 * y2) % &p;
    let dxy = (((&d * &x1x2) % &p) * &y1y2) % &p;

    let x3_num = ((x1 * y2) % &p + (y1 * x2) % &p) % &p;
    let x3 = (x3_num * inv(&((NB::from(1u32) + &dxy) % &p))) % &p;

    let y3_num = (&y1y2 + &x1x2) % &p;
    let y3 = (y3_num * inv(&((NB::from(1u32) + &p - &dxy) % &p))) % &p;

    (x3, y3)
}

/// `k · G` by double-and-add. Only used to cross-check the comb tables.
pub fn mul_basepoint(k: &NB) -> Affine {
    let mut acc = identity();
    let g = basepoint();
    for i in (0..k.bits()).rev() {
        acc = add_affine(&acc, &acc);
        if k.bit(i) {
            acc = add_affine(&acc, &g);
        }
    }
    acc
}

/// Is the point on the curve? `-x^2 + y^2 = 1 + d x^2 y^2 (mod p)`.
pub fn on_curve(pt: &Affine) -> bool {
    let p = p_bigint();
    let d = d_bigint();
    let (x, y) = pt;
    let xx = (x * x) % &p;
    let yy = (y * y) % &p;
    let lhs = (&yy + &p - &xx) % &p;
    let rhs = (NB::from(1u32) + ((&d * &xx) % &p) * &yy) % &p;
    lhs == rhs
}

/// RFC 8032 point compression: `y` little-endian, bit 255 set to the low bit of `x`.
pub fn compress(pt: &Affine) -> [u8; 32] {
    let (x, y) = pt;
    let mut out = [0u8; 32];
    let yb = y.to_bytes_le();
    out[..yb.len()].copy_from_slice(&yb);
    if x.bit(0) {
        out[31] |= 0x80;
    }
    out
}

/// Convert an affine point to niels form `(y+x, y-x, 2dxy)`, the representation the
/// circuit's mixed addition consumes.
pub fn to_niels(pt: &Affine) -> (NB, NB, NB) {
    let p = p_bigint();
    let d = d_bigint();
    let (x, y) = pt;
    let ypx = (y + x) % &p;
    let ymx = (y + &p - x) % &p;
    let t2d = ((((x * y) % &p) * NB::from(2u32)) % &p * &d) % &p;
    (ypx, ymx, t2d)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};

    use super::*;

    /// The hardcoded base point must satisfy the curve equation.
    #[test]
    fn basepoint_is_on_curve() {
        assert!(on_curve(&basepoint()));
    }

    /// …and must be the base point dalek uses. Comparing compressed encodings checks
    /// both coordinates and the sign convention at once.
    #[test]
    fn basepoint_matches_dalek() {
        assert_eq!(compress(&basepoint()), ED25519_BASEPOINT_POINT.compress().to_bytes());
    }

    /// Anchor the whole host-side implementation to dalek across a range of scalars.
    /// If this passes, `add_affine` is a trustworthy reference for the circuit tests.
    #[test]
    fn scalar_multiples_match_dalek() {
        for k in [1u64, 2, 3, 7, 8, 255, 256, 1 << 20, u32::MAX as u64] {
            let mine = mul_basepoint(&NB::from(k));
            let theirs = ED25519_BASEPOINT_POINT * Scalar::from(k);
            assert_eq!(
                compress(&mine),
                theirs.compress().to_bytes(),
                "mismatch at k = {k}"
            );
            assert!(on_curve(&mine), "off curve at k = {k}");
        }
    }

    /// The identity must be neutral, and doubling must agree with dalek.
    #[test]
    fn identity_is_neutral_and_doubling_agrees() {
        let g = basepoint();
        assert_eq!(add_affine(&g, &identity()), g);
        assert_eq!(add_affine(&identity(), &g), g);

        let two_g = add_affine(&g, &g);
        assert_eq!(
            compress(&two_g),
            (ED25519_BASEPOINT_POINT * Scalar::from(2u64)).compress().to_bytes()
        );
    }
}
