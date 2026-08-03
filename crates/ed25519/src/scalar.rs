//! Deriving the Ed25519 signing scalar from a seed, per RFC 8032 section 5.1.5.
//!
//! # Endianness
//!
//! This module exists because two conventions meet here and disagree.
//!
//! `sha512_fixed` returns eight **big-endian** 64-bit words: word `i` holds
//! `u64::from_be_bytes(digest[8i..8i+8])`. RFC 8032 reads the digest's low 32 bytes as a
//! **little-endian** integer. Converting therefore requires a byte swap *within* each
//! word, not merely a reordering of the words.
//!
//! Contrast `binius_examples::circuits::bip32`, whose comment notes that converting a
//! 256-bit hash half to a `BigUint` "is just a limb reversal — no per-byte swapping is
//! required". That is correct *there*, because BIP-32 interprets the hash as a
//! big-endian integer. Ed25519 does not. Applying the BIP-32 rule here would produce a
//! silently incorrect public key — no assertion would fire, the proof would simply
//! attest to the wrong statement.
//!
//! PQChain handles the same conversion explicitly with an `a_reversed` array in
//! `sdk/cpp/examples/PQChain/pqchain.cpp`, which is independent corroboration that the
//! step is required rather than an artefact of this design.

use binius_circuits::{bignum::BigUint, bytes::swap_bytes};
use binius_frontend::{CircuitBuilder, Wire};

use crate::consts::N_LIMBS;

/// Reinterpret the low 32 bytes of a SHA-512 digest as a little-endian integer.
///
/// Digest word `i` covers bytes `8i..8i+8` in big-endian order, so byte-swapping it
/// yields the little-endian reading of those same bytes — which is exactly limb `i`.
///
/// Costs four `swap_bytes`, roughly 24 AND constraints.
pub fn le_limbs_from_sha512(b: &CircuitBuilder, digest: &[Wire; 8]) -> BigUint {
    let limbs = (0..N_LIMBS).map(|i| swap_bytes(b, digest[i])).collect();
    BigUint { limbs }
}

/// RFC 8032 clamping, expressed against little-endian limbs.
///
/// The spec states this bytewise — `h[0] &= 248`, `h[31] &= 127`, `h[31] |= 64` — but
/// once the bytes are read as a little-endian integer those become bit operations:
/// `h[0]`'s low three bits are the integer's bits 0-2, and `h[31]`'s top two bits are
/// bits 255 and 254.
///
/// The result therefore lies in `[2^254, 2^255)` and is divisible by 8. The comb in
/// `scalar_mul` depends on that range for its window count.
///
/// All three operations are masks against constants — a handful of AND constraints.
pub fn clamp(b: &CircuitBuilder, s: &BigUint) -> BigUint {
    assert_eq!(
        s.limbs.len(),
        N_LIMBS,
        "clamp expects a {N_LIMBS}-limb scalar"
    );

    let clear_low = b.add_constant_64(!0b111u64);
    let clear_top = b.add_constant_64(!(1u64 << 63));
    let set_254 = b.add_constant_64(1u64 << 62);

    let mut limbs = s.limbs.clone();
    limbs[0] = b.band(limbs[0], clear_low);
    limbs[3] = b.band(limbs[3], clear_top);
    limbs[3] = b.bor(limbs[3], set_254);

    BigUint { limbs }
}

/// The full derivation: little-endian read of the digest's low half, then clamping.
pub fn derive_clamped(b: &CircuitBuilder, digest: &[Wire; 8]) -> BigUint {
    let s = le_limbs_from_sha512(b, digest);
    clamp(b, &s)
}

#[cfg(test)]
mod tests {
    use binius_circuits::{bignum::BigUint, sha512::sha512_fixed};
    use binius_core::{verify::verify_constraints, word::Word};
    use binius_frontend::CircuitBuilder;
    use proptest::prelude::*;

    use super::*;
    use crate::consts::N_LIMBS;

    fn nb_to_limbs(v: &num_bigint::BigUint) -> [u64; N_LIMBS] {
        let mut out = [0u64; N_LIMBS];
        for (i, d) in v.iter_u64_digits().enumerate() {
            out[i] = d;
        }
        out
    }

    /// The reference derivation: SHA-512(seed), low 32 bytes, clamp, read little-endian.
    fn reference_clamped_scalar(seed: &[u8; 32]) -> num_bigint::BigUint {
        crate::host::clamped_scalar_from_seed(seed)
    }

    /// Derive in-circuit and compare against the reference. Returns the limbs so callers
    /// can assert further.
    fn assert_derivation_matches(seed: &[u8; 32]) {
        let expected = reference_clamped_scalar(seed);

        let b = CircuitBuilder::new();
        let msg: Vec<_> = (0..4).map(|_| b.add_witness()).collect();
        let digest = sha512_fixed(&b, &msg, 32);
        let out = derive_clamped(&b, &digest);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        for (i, wire) in msg.iter().enumerate() {
            let mut word = [0u8; 8];
            word.copy_from_slice(&seed[8 * i..8 * i + 8]);
            w[*wire] = Word::from_u64(u64::from_be_bytes(word));
        }
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<u64> = out.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        assert_eq!(
            nb_to_limbs(&expected).to_vec(),
            got,
            "derivation mismatch for seed {}",
            hex::encode(seed)
        );
    }

    /// Every seed published in RFC 8032 section 7.1.
    ///
    /// One vector is weak evidence — a subtly wrong implementation can coincide with a
    /// single input. These are the spec's own, so a disagreement is unambiguous.
    #[test]
    fn clamped_scalar_matches_reference_on_rfc8032_vectors() {
        const SEEDS: &[&str] = &[
            // TEST 1
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            // TEST 2
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            // TEST 3
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            // TEST 1024
            "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
            // TEST SHA(abc)
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        ];

        for hexed in SEEDS {
            let seed: [u8; 32] = hex::decode(hexed).unwrap().try_into().unwrap();
            assert_derivation_matches(&seed);
        }
    }

    /// All-zero and all-ones seeds, which no published vector covers.
    #[test]
    fn clamped_scalar_matches_reference_on_extreme_seeds() {
        assert_derivation_matches(&[0u8; 32]);
        assert_derivation_matches(&[0xFFu8; 32]);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        /// Random seeds. Stronger than any fixed vector set: a byte-order error that
        /// happened to survive the published vectors cannot survive arbitrary input.
        #[test]
        fn clamped_scalar_matches_reference_on_random_seeds(seed in proptest::array::uniform32(any::<u8>())) {
            assert_derivation_matches(&seed);
        }
    }

    /// Clamping must clear bits 0-2 and 255, and set bit 254 — checked against an
    /// all-ones input so every affected bit visibly changes.
    #[test]
    fn clamp_sets_the_right_bits() {
        let b = CircuitBuilder::new();
        let s = BigUint::new_witness(&b, N_LIMBS);
        let out = clamp(&b, &s);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        s.populate_limbs(&mut w, &[u64::MAX; N_LIMBS]);
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<u64> = out.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        assert_eq!(got[0] & 0b111, 0, "low 3 bits must be cleared");
        assert_eq!(got[3] >> 63, 0, "bit 255 must be cleared");
        assert_eq!((got[3] >> 62) & 1, 1, "bit 254 must be set");
        // Everything else untouched. Written as literals: the obvious
        // `(u64::MAX & !(1 << 63)) | (1 << 62)` reads as if the OR does work, but bit 62
        // is already set in that value, so it would silently pass even if `clamp` never
        // set bit 254. The dedicated assertion above is what actually covers that.
        assert_eq!(
            got[0], 0xFFFF_FFFF_FFFF_FFF8,
            "low 3 bits cleared, rest intact"
        );
        assert_eq!(got[1], u64::MAX);
        assert_eq!(got[2], u64::MAX);
        assert_eq!(
            got[3], 0x7FFF_FFFF_FFFF_FFFF,
            "bit 255 cleared, bit 254 already set"
        );
    }

    /// Clamping an all-zero scalar must still set bit 254 — the range guarantee
    /// `[2^254, 2^255)` that the comb's window count depends on.
    #[test]
    fn clamp_forces_bit_254_even_from_zero() {
        let b = CircuitBuilder::new();
        let s = BigUint::new_witness(&b, N_LIMBS);
        let out = clamp(&b, &s);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        s.populate_limbs(&mut w, &[0u64; N_LIMBS]);
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<u64> = out.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        assert_eq!(got, vec![0, 0, 0, 1u64 << 62]);
    }

    /// The byte-swap must be a genuine little-endian reinterpretation, not a word
    /// reordering. A digest whose words are distinguishable catches the difference.
    #[test]
    fn le_limbs_reverses_bytes_not_just_words() {
        let b = CircuitBuilder::new();
        // Fabricate a "digest" directly so the mapping is checked in isolation.
        let digest: [_; 8] = std::array::from_fn(|_| b.add_witness());
        let out = le_limbs_from_sha512(&b, &digest);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        // Word i holds bytes 8i..8i+8 big-endian; use a pattern where byte order matters.
        let words: [u64; 8] = [
            0x0001_0203_0405_0607,
            0x0809_0A0B_0C0D_0E0F,
            0x1011_1213_1415_1617,
            0x1819_1A1B_1C1D_1E1F,
            0,
            0,
            0,
            0,
        ];
        for (i, wire) in digest.iter().enumerate() {
            w[*wire] = Word::from_u64(words[i]);
        }
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<u64> = out.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        // Bytes 0..32 of the digest, read as a little-endian integer.
        let bytes: Vec<u8> = words[..4].iter().flat_map(|x| x.to_be_bytes()).collect();
        let expected = num_bigint::BigUint::from_bytes_le(&bytes);
        assert_eq!(nb_to_limbs(&expected).to_vec(), got);
        // And explicitly: limb 0 must be the byte-reverse of word 0, not word 0 itself.
        assert_eq!(got[0], words[0].swap_bytes());
        assert_ne!(
            got[0], words[0],
            "a word reordering would pass without this"
        );
    }
}

#[cfg(test)]
mod clamp_agreement {
    use binius_circuits::bignum::BigUint;
    use binius_core::{verify::verify_constraints, word::Word};
    use binius_frontend::CircuitBuilder;
    use proptest::prelude::*;

    use super::*;
    use crate::{consts::N_LIMBS, host::clamp_bytes};

    /// The in-circuit clamp and the host clamp must agree, across arbitrary inputs.
    ///
    /// They necessarily differ in form — one masks little-endian 64-bit limbs, the other
    /// indexes bytes — so matching constants is *not* the same as matching semantics. A
    /// structural divergence could hide behind identical numbers. This asserts the
    /// behaviour directly rather than relying on the end-to-end vectors to notice.
    fn assert_clamps_agree(input: [u8; 32]) {
        let mut expected_bytes = input;
        clamp_bytes(&mut expected_bytes);
        let expected = num_bigint::BigUint::from_bytes_le(&expected_bytes);

        let b = CircuitBuilder::new();
        let s = BigUint::new_witness(&b, N_LIMBS);
        let out = clamp(&b, &s);

        let cs = b.build();
        let mut w = cs.new_witness_filler();
        let mut limbs = [0u64; N_LIMBS];
        for (i, chunk) in input.chunks(8).enumerate() {
            limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        s.populate_limbs(&mut w, &limbs);
        cs.populate_wire_witness(&mut w).unwrap();
        let got: Vec<u64> = out.limbs.iter().map(|l| w[*l].as_u64()).collect();
        verify_constraints(cs.constraint_system(), &w.into_value_vec()).unwrap();

        let mut want = [0u64; N_LIMBS];
        for (i, d) in expected.iter_u64_digits().enumerate() {
            want[i] = d;
        }
        assert_eq!(want.to_vec(), got, "clamps disagree on {input:?}");
        let _ = Word::ZERO;
    }

    #[test]
    fn clamp_agrees_with_host_on_edge_inputs() {
        assert_clamps_agree([0u8; 32]);
        assert_clamps_agree([0xFFu8; 32]);
        let mut only_low = [0u8; 32];
        only_low[0] = 0xFF;
        assert_clamps_agree(only_low);
        let mut only_high = [0u8; 32];
        only_high[31] = 0xFF;
        assert_clamps_agree(only_high);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn clamp_agrees_with_host(input in proptest::array::uniform32(any::<u8>())) {
            assert_clamps_agree(input);
        }
    }
}
