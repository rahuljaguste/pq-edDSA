//! The relation `R_det` from *Post-Quantum Readiness in EdDSA Chains* (FC 2026), Eq. 2.
//!
//! ```text
//! R_det = { (pk, msg, hx) | ∃ seed :
//!           pk = HashToScalar(SHA-512(seed)[:32]) · G
//!         ∧ hx = SHA-512(msg ‖ seed) }
//! ```
//!
//! The argument layout matches SoundnessLabs/PQChain exactly, so benchmarks compare like
//! with like:
//!
//! | arg | value | privacy |
//! |---|---|---|
//! | 1 | `seed` (32 B) | **private** |
//! | 2 | `pk` (32 B) | public |
//! | 3 | `msg` (32 B) | public |
//! | 4 | `hx` (64 B) | public |
//!
//! Note this is Eq. 2, the *deterministic* relation. The paper's Theorem 2 is proved over
//! Eq. 1, the randomised `R_rand` with an extra `rx`. PQChain implements Eq. 2 as well, so
//! this PoC inherits that gap rather than introducing it — closing it costs one more
//! SHA-512 block. See the design spec's Scope section.

use anyhow::{Result, ensure};
use binius_circuits::sha512::sha512_fixed;
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};
use ed25519_binius::{
    compress::compress, field::Fp, scalar::derive_clamped, scalar_mul::mul_basepoint,
};

/// Seed and message are both 32 bytes; four 64-bit words each.
const WORDS_32: usize = 4;

/// A SHA-512 digest is eight 64-bit words.
const WORDS_64: usize = 8;

pub struct PqEddsaCircuit {
    /// Private: the 32-byte seed, as four **big-endian** 64-bit words.
    pub seed: [Wire; WORDS_32],
    /// Public: the compressed public key, four **little-endian** words (RFC 8032 order).
    pub pk: [Wire; WORDS_32],
    /// Public: the 32-byte message, four big-endian words.
    pub msg: [Wire; WORDS_32],
    /// Public: `hx = SHA-512(msg ‖ seed)`, eight big-endian words.
    pub hx: [Wire; WORDS_64],
}

impl PqEddsaCircuit {
    pub fn build(b: &CircuitBuilder) -> Self {
        let seed: [Wire; WORDS_32] = std::array::from_fn(|_| b.add_witness());
        let pk: [Wire; WORDS_32] = std::array::from_fn(|_| b.add_inout());
        let msg: [Wire; WORDS_32] = std::array::from_fn(|_| b.add_inout());
        let hx: [Wire; WORDS_64] = std::array::from_fn(|_| b.add_inout());

        let f = Fp::new(b);

        // pk = clamp(SHA-512(seed)[:32]) · G
        let h = sha512_fixed(b, &seed, 32);
        let a = derive_clamped(b, &h);
        let point = mul_basepoint(b, &f, &a);
        let computed_pk = compress(b, &f, &point);
        for i in 0..WORDS_32 {
            b.assert_eq("pk", computed_pk[i], pk[i]);
        }

        // hx = SHA-512(msg ‖ seed)
        let mut concat = msg.to_vec();
        concat.extend_from_slice(&seed);
        let computed_hx = sha512_fixed(b, &concat, 64);
        for i in 0..WORDS_64 {
            b.assert_eq("hx", computed_hx[i], hx[i]);
        }

        Self { seed, pk, msg, hx }
    }

    /// Populate every input from a seed and message.
    pub fn populate(
        &self,
        w: &mut WitnessFiller,
        seed: &[u8; 32],
        msg: &[u8; 32],
    ) -> Result<()> {
        self.populate_private(w, seed);
        self.populate_public(w, &Self::public_inputs(seed, msg));
        Ok(())
    }

    /// The private witness — the seed, and nothing else.
    ///
    /// Everything downstream is derived, so there is nothing further to fill: no
    /// intermediate is witnessed, which is also why there is nothing for a malicious
    /// prover to tamper with inside the circuit.
    pub fn populate_private(&self, w: &mut WitnessFiller, seed: &[u8; 32]) {
        for i in 0..WORDS_32 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&seed[8 * i..8 * i + 8]);
            w[self.seed[i]] = Word::from_u64(u64::from_be_bytes(word));
        }
    }

    /// The public inputs implied by a `(seed, msg)` pair.
    ///
    /// Separated from population so tests can supply *inconsistent* public inputs — the
    /// case a negative test needs and an honest prover never produces.
    pub fn public_inputs(seed: &[u8; 32], msg: &[u8; 32]) -> PublicInputs {
        PublicInputs { pk: derive_pk(seed), msg: *msg, hx: derive_hx(seed, msg) }
    }

    pub fn populate_public(&self, w: &mut WitnessFiller, pi: &PublicInputs) {
        for i in 0..WORDS_32 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&pi.pk[8 * i..8 * i + 8]);
            w[self.pk[i]] = Word::from_u64(u64::from_le_bytes(word));

            word.copy_from_slice(&pi.msg[8 * i..8 * i + 8]);
            w[self.msg[i]] = Word::from_u64(u64::from_be_bytes(word));
        }
        for i in 0..WORDS_64 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&pi.hx[8 * i..8 * i + 8]);
            w[self.hx[i]] = Word::from_u64(u64::from_be_bytes(word));
        }
    }

    /// Check the relation host-side before proving.
    ///
    /// The CLI runs this so a mismatched input fails with a readable message instead of
    /// producing an unprovable constraint system.
    pub fn check_relation(seed: &[u8; 32], msg: &[u8; 32], pi: &PublicInputs) -> Result<()> {
        ensure!(pi.pk == derive_pk(seed), "public key does not match the seed");
        ensure!(pi.msg == *msg, "message does not match");
        ensure!(pi.hx == derive_hx(seed, msg), "hx is not SHA-512(msg ‖ seed)");
        Ok(())
    }
}

/// Reconstruct the circuit's public input words from public data alone.
///
/// The public section is `[constants, inout]`, and `ValueVec::new` zeroes everything —
/// constants are only filled by `populate_wire_witness`, which evaluates the whole
/// circuit and therefore needs the seed. A verifier has no seed, so it must rebuild the
/// constants block itself.
///
/// Doing this rather than accepting a prover-supplied blob matters: a proof is valid for
/// *whatever* public input accompanies it, so a verifier that takes the prover's word for
/// the public section can be handed a sound proof of a different statement and accept it
/// believing it checked its own.
pub fn public_words(
    cs: &binius_frontend::Circuit,
    circuit: &PqEddsaCircuit,
    pi: &PublicInputs,
) -> Vec<Word> {
    let mut w = cs.new_witness_filler();
    circuit.populate_public(&mut w, pi);
    let vv = w.into_value_vec();
    let mut public = vv.public().to_vec();

    // Overwrite the constants block, which the filler left zeroed.
    let consts = &cs.constraint_system().constants;
    assert!(consts.len() <= public.len(), "constants exceed the public section");
    public[..consts.len()].copy_from_slice(consts);
    public
}

/// The public half of a statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub pk: [u8; 32],
    pub msg: [u8; 32],
    pub hx: [u8; 64],
}

/// `pk` from a seed, per RFC 8032 — computed with the host-side reference that
/// `ed25519_binius` already anchors to `curve25519-dalek`.
pub fn derive_pk(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let h = Sha512::digest(seed);
    let mut a = [0u8; 32];
    a.copy_from_slice(&h[..32]);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    let k = num_bigint::BigUint::from_bytes_le(&a);
    ed25519_binius::host::compress(&ed25519_binius::host::mul_basepoint(&k))
}

/// `hx = SHA-512(msg ‖ seed)`.
pub fn derive_hx(seed: &[u8; 32], msg: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(msg);
    hasher.update(seed);
    hasher.finalize().into()
}
