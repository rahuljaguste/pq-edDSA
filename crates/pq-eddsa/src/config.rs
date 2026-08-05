//! Proving configuration.
//!
//! Every call site goes through [`ProofConfig`] rather than calling binius64's `setup`
//! directly, so a future security-bits override or wider challenge field adds a field
//! here instead of changing each caller.
//!
//! # Soundness
//!
//! Upstream fixes `SECURITY_BITS = 96` (`crates/verifier/src/verify.rs:39`) and
//! `ZKVerifier::setup` takes no override, so **96 bits classical is the only setting
//! available**. That is below the ~128 bits the Ligetron-based reference implementation
//! carries, and every published benchmark must state its level alongside its numbers.

use anyhow::{Result, anyhow};
use binius_core::constraint_system::ConstraintSystem;
use binius_prover::zk_config::ZKProver;
use binius_verifier::zk_config::ZKVerifier;

/// The Merkle and Fiat-Shamir hash suite.
///
/// SHA-256 rather than Blake3: measured ~8% faster on Apple silicon, which has SHA-256
/// instructions that `binius-hash`'s `sha256_x4` exploits. Proof size and soundness are
/// identical either way. See `crates/ed25519/BOUNDS.md` — the conclusion is
/// hardware-specific and worth re-measuring on x86-64 without SHA-NI.
/// The proving configuration: challenge field, packed representation, hash suite and
/// Fiat-Shamir challenger. All four move together, so they are declared together.
///
/// SPIKE BRANCH ONLY. `--features wide` selects the fork's `GF(2^256)` / SHA-512 path.
/// Upstream has only the narrow one.
#[cfg(not(feature = "wide"))]
mod cfg {
    pub type Field = binius_field::BinaryField128bGhash;
    pub type Packed = binius_prover::OptimalPackedB128;
    pub type Suite = binius_hash::sha256::Sha256HashSuite;
    pub type Challenger = binius_verifier::config::StdChallenger;
    /// The query target this configuration can actually reach. Past it, logUp\* binds.
    pub const DEFAULT_SECURITY_BITS: usize = binius_verifier::SECURITY_BITS;
}

#[cfg(feature = "wide")]
mod cfg {
    pub type Field = binius_field::GhashSq256b;
    pub type Packed = binius_field::PackedGhashSq1x256b;
    pub type Suite = binius_hash::Sha512HashSuite;
    pub type Challenger = binius_verifier::config::WideChallenger;
    pub const DEFAULT_SECURITY_BITS: usize = binius_verifier::SECURITY_BITS_WIDE;
}

pub use cfg::{Challenger, DEFAULT_SECURITY_BITS, Field, Packed, Suite};

pub type Verifier = ZKVerifier<Field, Suite>;
pub type Prover = ZKProver<Packed, Suite>;

/// Classical soundness in bits. Fixed by upstream; not currently configurable.
pub const SECURITY_BITS: usize = 96;

/// Recommended `n_dummy_constraints` for the ZK blinding.
///
/// Upstream hardcodes 2 with `// TODO: Document why these are necessary`. Measurement
/// puts the free ceiling at 2,133 for this
/// circuit — below it, proof size is byte-identical and proving time is within noise.
/// 2,048 is a power of two comfortably inside, and 1,024x the default.
///
/// This does **not** establish that 2 is insufficient or 2,048 sufficient. Zero-knowledge
/// is a simulation property and the claim here remains unaudited. The value is set high
/// because it is free, not because it was derived.
///
/// Not currently applied: upstream exposes no override. Recorded so it can be, and so a
/// future upstream change has a documented target.
pub const RECOMMENDED_N_DUMMY_CONSTRAINTS: usize = 2048;

#[derive(Clone, Copy, Debug)]
pub struct ProofConfig {
    /// Log of the inverse Reed-Solomon rate. Trades proof size against proving time.
    pub log_inv_rate: usize,
    /// FRI query-phase target, in bits.
    ///
    /// SPIKE BRANCH ONLY. Upstream hardcodes 96 and exposes no override; this is available
    /// because the branch patches in a fork carrying `setup_with_security_bits`. On the
    /// narrow field the useful ceiling is 112: past that the logUp\* term at `2^16/|F|`
    /// binds instead, and a larger query budget buys nothing.
    pub security_bits: usize,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            log_inv_rate: 1,
            security_bits: DEFAULT_SECURITY_BITS,
        }
    }
}

impl ProofConfig {
    /// Set up a verifier. Cheaper than [`Self::setup`] when proving is not needed.
    pub fn setup_verifier(&self, cs: ConstraintSystem) -> Result<Verifier> {
        ZKVerifier::setup_with_security_bits(cs, self.log_inv_rate, self.security_bits)
            .map_err(|e| anyhow!("verifier setup failed: {e:?}"))
    }

    /// Set up a matching verifier and prover.
    pub fn setup(&self, cs: ConstraintSystem) -> Result<(Verifier, Prover)> {
        let verifier = self.setup_verifier(cs)?;
        let prover =
            ZKProver::setup(&verifier).map_err(|e| anyhow!("prover setup failed: {e:?}"))?;
        Ok((verifier, prover))
    }

    /// The query-phase target this config was built with, for reporting alongside any
    /// measurement. Not the same as the achieved soundness: on the narrow field the
    /// logUp\* term caps the whole system at 112 regardless of what is requested here.
    pub const fn security_bits(&self) -> usize {
        self.security_bits
    }
}
