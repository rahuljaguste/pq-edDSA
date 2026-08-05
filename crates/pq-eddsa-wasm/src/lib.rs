//! Browser bindings: prove and verify the PQ-EdDSA relation client-side.
//!
//! The point of this crate is that **the seed never leaves the machine**. A user proves
//! they control an EdDSA key without transmitting the key, and the verifier learns only
//! `(pk, msg, hx)`. That property is only credible if the proving happens where the seed
//! already is, which on the web means in the page.
//!
//! # Layout
//!
//! [`Session`] is plain Rust and holds the whole proving apparatus; the `#[wasm_bindgen]`
//! types below are a thin adapter over it. Keeping the two apart means the logic is
//! covered by ordinary native `cargo test` rather than only by a browser run, and no
//! `JsValue` is constructed on a non-wasm target.
//!
//! # Timing
//!
//! Nothing here measures time. `std::time::Instant` panics on
//! `wasm32-unknown-unknown`, so every duration reported by the demo comes from
//! `performance.now()` on the JavaScript side, around these calls.
//!
//! # Build
//!
//! Do **not** pass `-C target-feature=+simd128`. binius64's wasm32 SIMD module does not
//! compile at the pinned revision (fix submitted upstream as binius-zk/binius64#1993),
//! and measured **0.7%** on this circuit with the fix applied — the module aliases the
//! portable field arithmetic and only its lane splitting uses intrinsics, and wasm has no
//! carry-less multiply for it to reach.

use binius_frontend::{Circuit, CircuitBuilder};
use binius_verifier::transcript::{ProverTranscript, VerifierTranscript};
use pq_eddsa::{
    circuit::{PqEddsaCircuit, PublicInputs, Relation, public_words},
    config::{Challenger, DEFAULT_SECURITY_BITS, ProofConfig, Prover, Verifier},
};
use wasm_bindgen::prelude::*;

/// A proof together with the statement it proves.
pub struct Proof {
    pub bytes: Vec<u8>,
    pub public: PublicInputs,
}

/// Circuit shape, for display.
#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub and_constraints: usize,
    pub imul_constraints: usize,
    pub private_wires: usize,
    pub security_bits: usize,
}

/// The built circuit plus a matched prover and verifier.
///
/// Construction is the expensive one-time step — circuit building and prover setup — and
/// is amortised across every proof made with the same session.
pub struct Session {
    relation: Relation,
    circuit: PqEddsaCircuit,
    cs: Circuit,
    prover: Prover,
    verifier: Verifier,
}

impl Session {
    pub fn new(relation: Relation, log_inv_rate: usize) -> Result<Self, String> {
        let b = CircuitBuilder::new();
        let circuit = PqEddsaCircuit::build_with(&b, relation);
        let cs = b.build();
        let (verifier, prover) = ProofConfig {
            log_inv_rate,
            ..Default::default()
        }
        .setup(cs.constraint_system().clone())
        .map_err(|e| e.to_string())?;
        Ok(Self {
            relation,
            circuit,
            cs,
            prover,
            verifier,
        })
    }

    pub fn stats(&self) -> Stats {
        let s = self.cs.constraint_system();
        Stats {
            and_constraints: s.n_and_constraints(),
            imul_constraints: s.imul_constraints.len(),
            private_wires: s.n_private,
            security_bits: DEFAULT_SECURITY_BITS,
        }
    }

    /// Prove knowledge of `seed`. Mirrors the CLI's `prove` path exactly.
    ///
    /// Under [`Relation::Rand`] a fresh `rx` is sampled here and deliberately **not**
    /// returned: it is witness, not statement, and only `hx` is published.
    pub fn prove(&self, seed: &[u8; 32], msg: &[u8; 32]) -> Result<Proof, String> {
        let mut w = self.cs.new_witness_filler();
        let rx = self
            .circuit
            .populate_randomised(&mut w, seed, msg)
            .map_err(|e| e.to_string())?;
        let public = self.circuit.public_inputs_with_rx(seed, msg, &rx);

        // Fail readably rather than handing the prover an unsatisfiable system.
        let rx_ref = (self.relation == Relation::Rand).then_some(&rx);
        PqEddsaCircuit::check_relation_with_rx(seed, msg, rx_ref, &public)
            .map_err(|e| format!("witness does not satisfy the relation: {e}"))?;
        self.cs
            .populate_wire_witness(&mut w)
            .map_err(|e| format!("witness population failed: {e:?}"))?;
        let witness = w.into_value_vec();

        let mut rng_seed = [0u8; 32];
        getrandom::fill(&mut rng_seed).map_err(|e| format!("entropy unavailable: {e}"))?;
        let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(rng_seed);
        let mut tr = ProverTranscript::new(Challenger::default());
        self.prover
            .prove(&witness, &mut rng, &mut tr)
            .map_err(|e| format!("prove failed: {e:?}"))?;
        Ok(Proof {
            bytes: tr.finalize(),
            public,
        })
    }

    /// Verify a proof against a statement.
    ///
    /// The public words are reconstructed from `public` alone, never taken from the
    /// prover — a proof is valid for whatever public input accompanies it, so a verifier
    /// that trusts a prover-supplied public section can be handed a sound proof of a
    /// different statement and accept it believing it checked its own.
    pub fn verify(&self, proof: &[u8], public: &PublicInputs) -> Result<(), String> {
        let words = public_words(&self.cs, &self.circuit, public);
        let mut vt = VerifierTranscript::new(Challenger::default(), proof.to_vec());
        self.verifier
            .verify(&words, &mut vt)
            .map_err(|e| format!("verification failed: {e:?}"))?;
        vt.finalize()
            .map_err(|e| format!("transcript finalize failed: {e:?}"))
    }
}

fn parse_relation(s: &str) -> Result<Relation, String> {
    match s {
        "det" => Ok(Relation::Det),
        "rand" => Ok(Relation::Rand),
        other => Err(format!(
            "unknown relation {other:?}; expected \"det\" or \"rand\""
        )),
    }
}

fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], String> {
    <[u8; N]>::try_from(bytes).map_err(|_| format!("{what} must be {N} bytes, got {}", bytes.len()))
}

fn from_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|e| format!("{what} is not valid hex: {e}"))?;
    fixed(&raw, what)
}

// ---------------------------------------------------------------------------
// JavaScript surface
// ---------------------------------------------------------------------------

/// A proof and its statement, as seen from JavaScript.
#[wasm_bindgen]
pub struct JsProof {
    bytes: Vec<u8>,
    public: PublicInputs,
}

#[wasm_bindgen]
impl JsProof {
    /// The proof itself.
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// The compressed public key, hex.
    #[wasm_bindgen(getter)]
    pub fn pk(&self) -> String {
        hex::encode(self.public.pk)
    }

    #[wasm_bindgen(getter)]
    pub fn msg(&self) -> String {
        hex::encode(self.public.msg)
    }

    /// The 64-byte hash commitment, hex.
    #[wasm_bindgen(getter)]
    pub fn hx(&self) -> String {
        hex::encode(self.public.hx)
    }
}

/// Prover and verifier for one relation, held across calls.
#[wasm_bindgen(js_name = PqEddsa)]
pub struct JsSession(Session);

#[wasm_bindgen(js_class = PqEddsa)]
impl JsSession {
    /// Build the circuit and set up prover and verifier.
    ///
    /// `relation` is `"det"` (matches PQChain, the default) or `"rand"` (the relation the
    /// paper's Theorem 2 is proved over). This is the slow call; hold the result.
    #[wasm_bindgen(constructor)]
    pub fn new(relation: &str, log_inv_rate: usize) -> Result<JsSession, JsError> {
        let relation = parse_relation(relation).map_err(|e| JsError::new(&e))?;
        Session::new(relation, log_inv_rate)
            .map(JsSession)
            .map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen(getter)]
    pub fn and_constraints(&self) -> usize {
        self.0.stats().and_constraints
    }

    #[wasm_bindgen(getter)]
    pub fn imul_constraints(&self) -> usize {
        self.0.stats().imul_constraints
    }

    #[wasm_bindgen(getter)]
    pub fn private_wires(&self) -> usize {
        self.0.stats().private_wires
    }

    #[wasm_bindgen(getter)]
    pub fn security_bits(&self) -> usize {
        self.0.stats().security_bits
    }

    /// Prove knowledge of a 32-byte seed. The seed is consumed here and never returned,
    /// stored, or transmitted.
    pub fn prove(&self, seed: &[u8], msg: &[u8]) -> Result<JsProof, JsError> {
        let seed = fixed::<32>(seed, "seed").map_err(|e| JsError::new(&e))?;
        let msg = fixed::<32>(msg, "msg").map_err(|e| JsError::new(&e))?;
        let p = self.0.prove(&seed, &msg).map_err(|e| JsError::new(&e))?;
        Ok(JsProof {
            bytes: p.bytes,
            public: p.public,
        })
    }

    /// Verify a proof against a hex statement. Throws if it does not verify.
    pub fn verify(&self, proof: &[u8], pk: &str, msg: &str, hx: &str) -> Result<(), JsError> {
        let public = PublicInputs {
            pk: from_hex::<32>(pk, "pk").map_err(|e| JsError::new(&e))?,
            msg: from_hex::<32>(msg, "msg").map_err(|e| JsError::new(&e))?,
            hx: from_hex::<64>(hx, "hx").map_err(|e| JsError::new(&e))?,
        };
        self.0.verify(proof, &public).map_err(|e| JsError::new(&e))
    }
}

/// What this build targets, before any session exists.
///
/// The demo's warning box states a soundness level, and a page that hardcodes it will
/// claim 96 bits while running the wide configuration. Setup is slow, so the page cannot
/// wait for a session to ask.
#[wasm_bindgen]
pub fn default_security_bits() -> usize {
    pq_eddsa::config::DEFAULT_SECURITY_BITS
}

/// Whether this build uses the fork's wide `GF(2^256)` path.
///
/// Read from `pq_eddsa::config`, not from this crate's own `cfg!`. The local feature is
/// pure forwarding, so asking it is asking a copy: `--features pq-eddsa/wide` without
/// this crate's `wide` compiles a wide library under a crate that thinks it is narrow,
/// and the page would then advertise 96 bits while proving at 240.
#[wasm_bindgen]
pub fn is_wide_build() -> bool {
    pq_eddsa::config::IS_WIDE
}

/// The public key a seed yields, hex — without proving anything. Lets the page show the
/// statement before the expensive step.
#[wasm_bindgen]
pub fn derive_pk_hex(seed: &[u8]) -> Result<String, JsError> {
    let seed = fixed::<32>(seed, "seed").map_err(|e| JsError::new(&e))?;
    Ok(hex::encode(pq_eddsa::circuit::derive_pk(&seed)))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// RFC 8032 test vector 1, so a wrong wiring in this wrapper cannot pass.
    const SEED: [u8; 32] =
        hex_literal(b"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const PK: [u8; 32] =
        hex_literal(b"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    /// `hex::decode` is not const, and a literal array would be unreadable.
    const fn hex_literal(s: &[u8; 64]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            let hi = nibble(s[2 * i]);
            let lo = nibble(s[2 * i + 1]);
            out[i] = (hi << 4) | lo;
            i += 1;
        }
        out
    }

    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not lowercase hex"),
        }
    }

    #[test]
    fn round_trip_det() {
        let s = Session::new(Relation::Det, 1).expect("setup");
        let msg = [0u8; 32];
        let p = s.prove(&SEED, &msg).expect("prove");
        assert_eq!(p.public.pk, PK, "wrapper derived the wrong public key");
        s.verify(&p.bytes, &p.public).expect("verify");
    }

    #[test]
    fn round_trip_rand() {
        let s = Session::new(Relation::Rand, 1).expect("setup");
        let msg = [7u8; 32];
        let p = s.prove(&SEED, &msg).expect("prove");
        assert_eq!(p.public.pk, PK);
        s.verify(&p.bytes, &p.public).expect("verify");
    }

    /// Randomised `hx` must actually differ run to run, or `Rand` mode is decorative.
    #[test]
    fn rand_randomises_hx() {
        let s = Session::new(Relation::Rand, 1).expect("setup");
        let msg = [0u8; 32];
        let a = s.prove(&SEED, &msg).expect("prove a");
        let b = s.prove(&SEED, &msg).expect("prove b");
        assert_ne!(a.public.hx, b.public.hx);
    }

    /// The statement is load-bearing: a proof must not verify against a different one.
    #[test]
    fn verify_rejects_a_tampered_statement() {
        let s = Session::new(Relation::Det, 1).expect("setup");
        let msg = [0u8; 32];
        let p = s.prove(&SEED, &msg).expect("prove");

        let mut bad = p.public.clone();
        bad.pk[0] ^= 1;
        assert!(
            s.verify(&p.bytes, &bad).is_err(),
            "accepted a proof for a different pk"
        );

        let mut bad = p.public.clone();
        bad.hx[0] ^= 1;
        assert!(
            s.verify(&p.bytes, &bad).is_err(),
            "accepted a proof for a different hx"
        );
    }

    #[test]
    fn verify_rejects_a_corrupted_proof() {
        let s = Session::new(Relation::Det, 1).expect("setup");
        let msg = [0u8; 32];
        let p = s.prove(&SEED, &msg).expect("prove");
        let mut bytes = p.bytes.clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(
            s.verify(&bytes, &p.public).is_err(),
            "accepted a corrupted proof"
        );
    }

    /// The `wide` passthrough must actually reach the types, not merely type-check.
    ///
    /// A feature that forwards but changes nothing would compile, pass every other test,
    /// and quietly produce narrow proofs from a build labelled wide. Proof size is the
    /// cheapest thing that cannot be faked: the wide field roughly quintuples it.
    #[test]
    fn the_build_is_the_configuration_it_claims() {
        let s = Session::new(Relation::Det, 1).expect("setup");
        let p = s.prove(&SEED, &[0u8; 32]).expect("prove");
        let (lo, hi, label) = if pq_eddsa::config::IS_WIDE {
            (2_000_000, 3_500_000, "wide")
        } else {
            (400_000, 800_000, "narrow")
        };
        assert!(
            (lo..=hi).contains(&p.bytes.len()),
            "{label} build produced a {}-byte proof, outside {lo}..={hi}",
            p.bytes.len()
        );
        assert_eq!(
            s.stats().security_bits,
            pq_eddsa::config::DEFAULT_SECURITY_BITS,
            "reported target does not follow the build"
        );
    }

    #[test]
    fn relation_names_parse() {
        assert_eq!(parse_relation("det").unwrap(), Relation::Det);
        assert_eq!(parse_relation("rand").unwrap(), Relation::Rand);
        assert!(parse_relation("Det").is_err());
        assert!(parse_relation("").is_err());
    }

    #[test]
    fn wrong_length_inputs_are_rejected() {
        assert!(fixed::<32>(&[0u8; 31], "seed").is_err());
        assert!(fixed::<32>(&[0u8; 33], "seed").is_err());
        assert!(from_hex::<32>("zz", "pk").is_err());
        // A hex statement from the CLI carries no 0x prefix; both forms must work.
        assert_eq!(from_hex::<32>(&hex::encode(PK), "pk").unwrap(), PK);
        assert_eq!(
            from_hex::<32>(&format!("0x{}", hex::encode(PK)), "pk").unwrap(),
            PK
        );
    }
}
