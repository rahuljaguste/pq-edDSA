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
    assert_eq!(s.limbs.len(), N_LIMBS, "clamp expects a {N_LIMBS}-limb scalar");

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
    use sha2::{Digest, Sha512};

    use super::*;
    use crate::consts::N_LIMBS;

    /// RFC 8032 section 7.1, TEST 1.
    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn nb_to_limbs(v: &num_bigint::BigUint) -> [u64; N_LIMBS] {
        let mut out = [0u64; N_LIMBS];
        for (i, d) in v.iter_u64_digits().enumerate() {
            out[i] = d;
        }
        out
    }

    /// The clamped scalar derived in-circuit must match the reference byte for byte.
    ///
    /// This is the test that would have caught the endianness bug: `sha512_fixed`
    /// emits big-endian words, RFC 8032 reads the low half as a little-endian integer.
    #[test]
    fn clamped_scalar_matches_reference() {
        let seed = hex::decode(SEED_HEX).unwrap();

        // Reference: SHA-512(seed), low 32 bytes, clamp, read little-endian.
        let h = Sha512::digest(&seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let expected = num_bigint::BigUint::from_bytes_le(&a);

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

        assert_eq!(nb_to_limbs(&expected).to_vec(), got);
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
        // Everything else untouched.
        assert_eq!(got[0], u64::MAX & !0b111);
        assert_eq!(got[1], u64::MAX);
        assert_eq!(got[2], u64::MAX);
        assert_eq!(got[3], (u64::MAX & !(1u64 << 63)) | (1u64 << 62));
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
            0, 0, 0, 0,
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
        assert_ne!(got[0], words[0], "a word reordering would pass without this");
    }
}
