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
//! # Which relation
//!
//! Both are implemented, selected by [`Relation`] at circuit-build time.
//!
//! - [`Relation::Det`] is Eq. 2, `hx = SHA-512(msg ‖ seed)`. This is what PQChain
//!   implements, and it is the mode benchmarks use so the comparison is like for like.
//! - [`Relation::Rand`] is Eq. 1, `hx = SHA-512(msg ‖ seed ‖ rx)` with `rx` a fresh
//!   random value in the witness. **This is the relation the paper's Theorem 2 is proved
//!   over.**
//!
//! The difference is not merely formal. Under `Det`, `hx` is a deterministic function of
//! `(msg, seed)`, so anyone holding the public `msg` and `hx` can test candidate seeds
//! offline — `hx` is effectively an unsalted commitment to the private key. Against a
//! full-entropy 256-bit seed that is not a practical attack, but it is exactly the
//! property the paper's proof needs `rx` to rule out, and it bites for any seed drawn
//! from a searchable space (a weak mnemonic, a low-entropy RNG, a seed derived from
//! something guessable).
//!
//! `Rand` costs almost nothing: `msg ‖ seed ‖ rx` is 96 bytes, still inside a single
//! SHA-512 block, so the extra cost is four witness wires rather than the extra
//! compression the design spec projected.

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

/// Which form of the relation to prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Relation {
    /// Eq. 2: `hx = SHA-512(msg ‖ seed)`. Matches PQChain; used for benchmark parity.
    #[default]
    Det,
    /// Eq. 1: `hx = SHA-512(msg ‖ seed ‖ rx)`. The relation Theorem 2 is proved over.
    Rand,
}

pub struct PqEddsaCircuit {
    pub relation: Relation,
    /// Private: the 32-byte seed, as four **big-endian** 64-bit words.
    pub seed: [Wire; WORDS_32],
    /// Private: fresh randomness, present only under [`Relation::Rand`].
    ///
    /// Deliberately unconstrained — any `rx` yields a valid proof for the `hx` it
    /// produces. Its job is to randomise `hx`, not to be checked.
    pub rx: Option<[Wire; WORDS_32]>,
    /// Public: the compressed public key, four **little-endian** words (RFC 8032 order).
    pub pk: [Wire; WORDS_32],
    /// Public: the 32-byte message, four big-endian words.
    pub msg: [Wire; WORDS_32],
    /// Public: `hx = SHA-512(msg ‖ seed)`, eight big-endian words.
    pub hx: [Wire; WORDS_64],
}

impl PqEddsaCircuit {
    /// Build the `R_det` circuit. Equivalent to `build_with(b, Relation::Det)`.
    pub fn build(b: &CircuitBuilder) -> Self {
        Self::build_with(b, Relation::Det)
    }

    pub fn build_with(b: &CircuitBuilder, relation: Relation) -> Self {
        let seed: [Wire; WORDS_32] = std::array::from_fn(|_| b.add_witness());
        let rx: Option<[Wire; WORDS_32]> = match relation {
            Relation::Det => None,
            Relation::Rand => Some(std::array::from_fn(|_| b.add_witness())),
        };
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

        // hx = SHA-512(msg ‖ seed [‖ rx])
        let mut concat = msg.to_vec();
        concat.extend_from_slice(&seed);
        if let Some(rx) = &rx {
            concat.extend_from_slice(rx);
        }
        let computed_hx = sha512_fixed(b, &concat, concat.len() * 8);
        for i in 0..WORDS_64 {
            b.assert_eq("hx", computed_hx[i], hx[i]);
        }

        Self {
            relation,
            seed,
            rx,
            pk,
            msg,
            hx,
        }
    }

    /// Populate every input from a seed and message.
    ///
    /// Infallible, and typed that way. Both halves are total functions over fixed-size
    /// arrays, so there is no failure mode to report — returning `Result` would invite
    /// callers to handle a path that cannot fire, and would mask the signature change if
    /// a future revision genuinely could fail.
    /// Populate everything from a seed and message, using `rx = 0` under
    /// [`Relation::Rand`].
    ///
    /// Convenient for tests and for `Det`, where there is no `rx`. **Do not use for real
    /// `Rand` proving** — a fixed `rx` provides no randomisation, which is the entire
    /// point of that mode. Use [`Self::populate_randomised`].
    pub fn populate(&self, w: &mut WitnessFiller, seed: &[u8; 32], msg: &[u8; 32]) {
        self.populate_with_rx(w, seed, msg, &[0u8; 32]);
    }

    /// Populate with a caller-supplied `rx`.
    pub fn populate_with_rx(
        &self,
        w: &mut WitnessFiller,
        seed: &[u8; 32],
        msg: &[u8; 32],
        rx: &[u8; 32],
    ) {
        self.populate_private_with_rx(w, seed, rx);
        self.populate_public(w, &self.public_inputs_with_rx(seed, msg, rx));
    }

    /// Populate with freshly sampled `rx`, returning it so the caller can reproduce the
    /// statement. Under [`Relation::Det`] the sampled value is unused.
    pub fn populate_randomised(
        &self,
        w: &mut WitnessFiller,
        seed: &[u8; 32],
        msg: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut rx = [0u8; 32];
        if self.relation == Relation::Rand {
            getrandom::fill(&mut rx)?;
        }
        self.populate_with_rx(w, seed, msg, &rx);
        Ok(rx)
    }

    /// The private witness — the seed, and nothing else.
    ///
    /// Everything downstream is derived, so there is nothing further to fill: no
    /// intermediate is witnessed, which is also why there is nothing for a malicious
    /// prover to tamper with inside the circuit.
    pub fn populate_private(&self, w: &mut WitnessFiller, seed: &[u8; 32]) {
        self.populate_private_with_rx(w, seed, &[0u8; 32]);
    }

    pub fn populate_private_with_rx(&self, w: &mut WitnessFiller, seed: &[u8; 32], rx: &[u8; 32]) {
        for i in 0..WORDS_32 {
            let mut word = [0u8; 8];
            word.copy_from_slice(&seed[8 * i..8 * i + 8]);
            w[self.seed[i]] = Word::from_u64(u64::from_be_bytes(word));
        }
        if let Some(rx_wires) = &self.rx {
            for i in 0..WORDS_32 {
                let mut word = [0u8; 8];
                word.copy_from_slice(&rx[8 * i..8 * i + 8]);
                w[rx_wires[i]] = Word::from_u64(u64::from_be_bytes(word));
            }
        }
    }

    /// The public inputs implied by a `(seed, msg)` pair.
    ///
    /// Separated from population so tests can supply *inconsistent* public inputs — the
    /// case a negative test needs and an honest prover never produces.
    pub fn public_inputs(seed: &[u8; 32], msg: &[u8; 32]) -> PublicInputs {
        PublicInputs {
            pk: derive_pk(seed),
            msg: *msg,
            hx: derive_hx(seed, msg, None),
        }
    }

    /// The public inputs for this circuit's relation, given `rx`.
    pub fn public_inputs_with_rx(
        &self,
        seed: &[u8; 32],
        msg: &[u8; 32],
        rx: &[u8; 32],
    ) -> PublicInputs {
        let rx = match self.relation {
            Relation::Det => None,
            Relation::Rand => Some(rx),
        };
        PublicInputs {
            pk: derive_pk(seed),
            msg: *msg,
            hx: derive_hx(seed, msg, rx),
        }
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
        Self::check_relation_with_rx(seed, msg, None, pi)
    }

    /// As [`Self::check_relation`], for a given `rx` (`None` under [`Relation::Det`]).
    pub fn check_relation_with_rx(
        seed: &[u8; 32],
        msg: &[u8; 32],
        rx: Option<&[u8; 32]>,
        pi: &PublicInputs,
    ) -> Result<()> {
        ensure!(
            pi.pk == derive_pk(seed),
            "public key does not match the seed"
        );
        ensure!(pi.msg == *msg, "message does not match");
        ensure!(
            pi.hx == derive_hx(seed, msg, rx),
            "hx does not match msg, seed and rx"
        );
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
    assert!(
        consts.len() <= public.len(),
        "constants exceed the public section"
    );
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
    let k = ed25519_binius::host::clamped_scalar_from_seed(seed);
    ed25519_binius::host::compress(&ed25519_binius::host::mul_basepoint(&k))
}

/// `hx = SHA-512(msg ‖ seed [‖ rx])`.
///
/// `rx` is `None` for [`Relation::Det`] and `Some` for [`Relation::Rand`].
pub fn derive_hx(seed: &[u8; 32], msg: &[u8; 32], rx: Option<&[u8; 32]>) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(msg);
    hasher.update(seed);
    if let Some(rx) = rx {
        hasher.update(rx);
    }
    hasher.finalize().into()
}
