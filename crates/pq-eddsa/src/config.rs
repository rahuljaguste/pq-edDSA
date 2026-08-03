//! Proving configuration.
//!
//! Wraps the parameters rather than calling binius64's `setup` directly, so a future
//! security-bits override or wider challenge field adds a field here instead of changing
//! every call site.
//!
//! # Soundness
//!
//! Upstream fixes `SECURITY_BITS = 96` (`crates/verifier/src/verify.rs:39`) and
//! `ZKVerifier::setup` takes no override, so **96 bits classical is the only setting
//! available**. That is below the ~128 bits the Ligetron-based reference implementation
//! carries, and every published benchmark must state its level alongside its numbers.
//! See the design spec's soundness section.

/// Classical soundness in bits. Fixed by upstream; not currently configurable.
pub const SECURITY_BITS: usize = 96;

/// Recommended `n_dummy_constraints` for the ZK blinding.
///
/// Upstream hardcodes 2 with `// TODO: Document why these are necessary`. Measurement
/// (`docs/spikes/2026-08-03-task8-blinding.md`) puts the free ceiling at 2,132 for this
/// circuit — below that, proof size is byte-identical and proving time is within noise.
/// 2,048 is a power of two comfortably inside it, and 1,024x the default.
///
/// This does **not** establish that 2 is insufficient or that 2,048 is sufficient.
/// Zero-knowledge is a simulation property and the claim here remains unaudited. The
/// value is set high because it is free, not because it was derived.
///
/// Not currently applied: upstream exposes no override. Recorded so it can be, and so a
/// future upstream change has a documented target.
pub const RECOMMENDED_N_DUMMY_CONSTRAINTS: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashSuite {
    Sha256,
    Blake3,
}

#[derive(Clone, Copy, Debug)]
pub struct ProofConfig {
    /// Log of the inverse Reed-Solomon rate. Trades proof size against proving time.
    pub log_inv_rate: usize,
    pub hash_suite: HashSuite,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self { log_inv_rate: 1, hash_suite: HashSuite::Sha256 }
    }
}
