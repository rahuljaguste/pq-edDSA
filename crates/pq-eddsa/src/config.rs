//! Proving configuration.
//!
//! Every call site goes through [`ProofConfig`], never `ZKVerifier::setup` directly. That
//! is not tidiness: the plain `setup` hardcodes the narrow query target, so calling it
//! from a `--features wide` build pairs a `GF(2^256)` field with a 96-bit budget. The
//! query phase then binds at 96 and the result is wide-field cost for narrow-field
//! soundness. Any measurement taken that way is of a configuration nobody would ship.
//!
//! # Soundness
//!
//! Upstream fixes `SECURITY_BITS = 96` and `ZKVerifier::setup` takes no
//! override, so on `main` 96 bits classical is the only setting available. This branch
//! patches in a fork adding `setup_with_security_bits` and a wide configuration, so two
//! things become adjustable and neither is free:
//!
//! | build | query target | achieved | bound by |
//! |---|---|---|---|
//! | narrow (default) | 96, adjustable | up to ~112 | logUp\* at `2^16/|F|` |
//! | `--features wide` | 240 | ~240 classical, ~120 quantum | logUp\* again |
//!
//! Raising the target past what the field can deliver is accepted silently and costs real
//! proof size for nothing. Every published benchmark must state its level alongside its
//! numbers, and any figure measured here must also say it depends on an unmerged,
//! unaudited fork.

use anyhow::{Result, anyhow};
use binius_core::constraint_system::ConstraintSystem;
use binius_prover::zk_config::ZKProver;
use binius_verifier::zk_config::ZKVerifier;

/// The proving configuration: challenge field, packed representation, hash suite and
/// Fiat-Shamir challenger. All four move together, so they are declared together.
///
/// `--features wide` selects the fork's `GF(2^256)` / SHA-512 path.
/// Upstream has only the narrow one.
#[cfg(not(feature = "wide"))]
mod cfg {
    pub type Field = binius_field::BinaryField128bGhash;
    pub type Packed = binius_prover::OptimalPackedB128;
    /// SHA-256 rather than Blake3: measured ~8% faster on Apple silicon, which has
    /// SHA-256 instructions that `binius-hash`'s `sha256_x4` exploits. Proof size and
    /// soundness are identical either way. See `crates/ed25519/BOUNDS.md`; the conclusion
    /// is hardware-specific and worth re-measuring on x86-64 without SHA-NI.
    pub type Suite = binius_hash::sha256::Sha256HashSuite;
    pub const SUITE_NAME: &str = "SHA-256";
    /// Where logUp\* binds on this field: `2^16/|F|` with `|F| = 2^128`. No query budget
    /// exceeds it, so the achieved level is `min(target, cap)` and never the target alone.
    pub const LOGUP_CAP: usize = 112;
    pub type Challenger = binius_verifier::config::StdChallenger;
    /// 96, which is upstream's constant and **not** this field's ceiling: the narrow
    /// field reaches 112 before logUp\* binds, and 112 measured free in proving time for
    /// +12% proof size.
    ///
    /// Left at 96 deliberately, unlike the wide default which was moved to its binding
    /// level. A narrow build here should stay directly comparable with an upstream build,
    /// which cannot raise it at all. Pass `--security-bits 112` to take the rest.
    pub const DEFAULT_SECURITY_BITS: usize = binius_verifier::SECURITY_BITS;
    pub const IS_WIDE: bool = false;
}

#[cfg(feature = "wide")]
mod cfg {
    pub type Field = binius_field::GhashSq256b;
    pub type Packed = binius_field::PackedGhashSq1x256b;
    pub type Suite = binius_hash::Sha512HashSuite;
    pub const SUITE_NAME: &str = "SHA-512";
    /// `2^16/|F|` with `|F| = 2^256`.
    pub const LOGUP_CAP: usize = 240;
    pub type Challenger = binius_verifier::config::WideChallenger;

    /// 240, not the fork's `SECURITY_BITS_WIDE = 256`.
    ///
    /// logUp\* contributes a fixed `2^16/|F|` and binds at `2^-240`, so a target above 240
    /// delivers no more soundness and is charged for in full. Measured on `R_det`: 240
    /// yields a 2,505,280-byte proof and 256 yields 2,626,880, both achieving ~240 bits.
    /// The difference is 121,600 bytes for nothing.
    ///
    /// Proving time is flat across the whole range (499–541 ms from a target of 96 to
    /// 320), so the query budget buys bytes rather than cycles and there is no reason to
    /// leave the extra ones on.
    pub const DEFAULT_SECURITY_BITS: usize = 240;

    /// What the fork defaults to. Kept so the gap is documented rather than silently
    /// diverged from.
    pub const FORK_DEFAULT_SECURITY_BITS: usize = binius_verifier::SECURITY_BITS_WIDE;
    pub const IS_WIDE: bool = true;
}

#[cfg(feature = "wide")]
pub use cfg::FORK_DEFAULT_SECURITY_BITS;
/// The soundness this build actually achieves, in bits.
///
/// `min(target, cap)`. Reporting the requested target instead overstates it whenever the
/// target exceeds what the field can deliver, which is accepted silently.
pub const fn achieved_security_bits(target: usize) -> usize {
    if target < LOGUP_CAP {
        target
    } else {
        LOGUP_CAP
    }
}

/// Which configuration this build selected.
///
/// The single source of truth. A dependent crate asking `cfg!(feature = "wide")` about
/// itself keeps a second copy that can disagree: enabling `pq-eddsa/wide` without the
/// dependent's own forwarding feature compiles a wide library under a crate that believes
/// it is narrow, and anything it reports about soundness is then wrong.
pub use cfg::IS_WIDE;
pub use cfg::{Challenger, DEFAULT_SECURITY_BITS, Field, LOGUP_CAP, Packed, SUITE_NAME, Suite};

pub type Verifier = ZKVerifier<Field, Suite>;
pub type Prover = ZKProver<Packed, Suite>;

/// What upstream hardcodes, kept for reference and for documenting the gap.
///
/// **Not what this build uses.** Read [`DEFAULT_SECURITY_BITS`] for that, which follows
/// the selected feature. Reporting this constant instead is how the `stat` subcommand and
/// the wasm bindings both came to claim 96 bits while running the wide configuration.
pub const UPSTREAM_SECURITY_BITS: usize = 96;

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
/// **Measured on the narrow build only, and probably wrong for wide.** The cliff is set by
/// the outer Spartan system crossing a padding boundary, and its blinding budget is
/// `n_dummy_wires + 3 * n_dummy_constraints` where `n_dummy_wires` tracks the FRI query
/// count. That count follows the query target: 232 queries at 96 bits, 579 at 240. If the
/// boundary itself is unchanged, wide's extra 347 wires consume about 116 of the
/// constraint headroom and the ceiling lands near 2,017 — below this recommendation by
/// roughly 31.
///
/// That is a derivation, not a measurement, and this repository's own rule is that a
/// derived padding boundary is a hypothesis until measured. Two predictions of exactly
/// this kind have already been wrong here. Re-measuring needs an environment override for
/// `n_dummy_constraints` that neither upstream nor the fork exposes, so it is recorded
/// rather than resolved.
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
    /// Upstream hardcodes 96 and exposes no override; this is available
    /// because the branch patches in a fork carrying `setup_with_security_bits`. The
    /// useful ceiling is 112 on the narrow field and ~240 on the wide one: past that the
    /// logUp\* term at `2^16/|F|` binds instead, and a larger query budget buys nothing.
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
    /// measurement.
    ///
    /// **Not the achieved soundness.** logUp\* contributes a fixed `2^16/|F|` that no
    /// query budget affects, so the narrow field caps at 112 and the wide one at ~240,
    /// whatever is requested here. Asking for more is accepted silently and costs real
    /// proof size for nothing.
    pub const fn security_bits(&self) -> usize {
        self.security_bits
    }
}
