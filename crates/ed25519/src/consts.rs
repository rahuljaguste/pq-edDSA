//! Ed25519 constants.
//!
//! The coordinate field modulus is `p = 2^255 - 19`. Circuit arithmetic runs modulo
//! `2p = 2^256 - 38`, which is pseudo-Mersenne *and* limb-aligned, so binius64's
//! [`PseudoMersennePrimeField`] applies unmodified — `p` itself does not, because
//! `PseudoMersenneModReduce` requires `modulus_po2` to be a multiple of 64.
//!
//! [`PseudoMersennePrimeField`]: binius_circuits::bignum::PseudoMersennePrimeField

use num_bigint::BigUint as NB;

/// Number of 64-bit limbs in a field element.
pub const N_LIMBS: usize = 4;

/// `p = 2^255 - 19`, little-endian 64-bit limbs.
pub const P_LIMBS: [u64; N_LIMBS] = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

/// The subtrahend of the working modulus `2p = 2^256 - 38`.
pub const TWO_P_SUBTRAHEND: u64 = 38;

/// The power of two in the working modulus `2^256 - 38`.
pub const TWO_P_PO2: usize = 256;

/// `p = 2^255 - 19`.
pub fn p_bigint() -> NB {
    (NB::from(1u32) << 255u32) - NB::from(19u32)
}

/// `2p = 2^256 - 38`, the modulus circuit arithmetic actually reduces against.
pub fn two_p_bigint() -> NB {
    (NB::from(1u32) << 256u32) - NB::from(38u32)
}

/// The twisted-Edwards curve constant `d = -121665/121666 mod p`.
pub fn d_bigint() -> NB {
    let p = p_bigint();
    let num = &p - NB::from(121665u32);
    let den = NB::from(121666u32);
    // Inverse by Fermat, since p is prime.
    (num * den.modpow(&(&p - NB::from(2u32)), &p)) % &p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_limbs_match_p_bigint() {
        let p = p_bigint();
        let mut limbs = [0u64; N_LIMBS];
        for (i, d) in p.iter_u64_digits().enumerate() {
            limbs[i] = d;
        }
        assert_eq!(limbs, P_LIMBS);
    }

    #[test]
    fn two_p_is_twice_p_and_pseudo_mersenne() {
        assert_eq!(two_p_bigint(), p_bigint() * NB::from(2u32));
        // The form PseudoMersenneModReduce needs: 2^TWO_P_PO2 - TWO_P_SUBTRAHEND.
        assert_eq!(
            two_p_bigint(),
            (NB::from(1u32) << TWO_P_PO2 as u32) - NB::from(TWO_P_SUBTRAHEND)
        );
        // And its preconditions: limb-aligned, short subtrahend.
        assert_eq!(TWO_P_PO2 % 64, 0);
        assert!(TWO_P_SUBTRAHEND < u64::MAX);
    }

    /// `d` must satisfy `121666·d + 121665 ≡ 0 (mod p)`.
    #[test]
    fn d_is_the_curve_constant() {
        let p = p_bigint();
        let d = d_bigint();
        let lhs = (NB::from(121666u32) * &d + NB::from(121665u32)) % &p;
        assert_eq!(lhs, NB::from(0u32));
    }
}
