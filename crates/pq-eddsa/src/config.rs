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
