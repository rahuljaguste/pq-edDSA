# Upstream PR to `binius-zk/binius64`

**Status: opened — https://github.com/binius-zk/binius64/pull/1993**
Branch `fix/wasm32-simd128-orphaned-macros` in `rahuljaguste/binius64`, based on
`upstream/main` at `e0ddeb91` (not on the fork's divergent work).

**Patch:** `docs/binius64-wasm32-simd128.patch` (2 insertions, 21 deletions, one file)
**Against:** `21f0ceeabfdd530c3c3508883caa436d8b0f15ab`

---

## Suggested title

`fix(field): repair the wasm32 SIMD GHASH module, orphaned by the Broadcast/Transformation removal`

## Suggested description

### What's broken

`binius-field` does not compile for `wasm32-unknown-unknown` when `simd128` is enabled:

```
$ RUSTFLAGS="-C target-feature=+simd128" cargo build -p binius-field \
      --target wasm32-unknown-unknown

error[E0432]: unresolved imports
  `crate::arch::portable::packed_macros::impl_broadcast`,
  `crate::arithmetic_traits::impl_transformation_with_strategy`
  --> crates/field/src/arch/wasm32/packed_ghash_128.rs:18:4
```

`crates/field/src/arch/wasm32/packed_ghash_128.rs` still calls `impl_broadcast!` and
`impl_transformation_with_strategy!`. Both macros — and the `Broadcast` trait and the
`impl_transformation` mechanism they belonged to — were removed from the crate. The other
architecture modules were updated; `aarch64/packed_ghash_128.rs`, for instance, is now
type aliases only and calls neither macro.

`wasm32` was missed because `crates/field/src/arch/wasm32/mod.rs` gates the module behind
`#[cfg(target_feature = "simd128")]`, and nothing in CI builds with that flag. Without it
the target falls through to `portable` and compiles fine, so the breakage is invisible
unless you explicitly ask for SIMD — which is exactly what someone optimising a browser
build would do.

### The fix

Delete the two orphaned macro invocations and their now-unused imports. Nothing replaces
them: the abstractions they referenced no longer exist, and no other architecture module
provides an equivalent.

The module's actual contribution — `impl Underlier128bLanes for M128`, using
`u64x2_extract_lane`, `u64x2` and `u64x2_splat` — is untouched and still compiles.

### Verification

- `binius-field`, `binius-circuits`, `binius-prover` and `binius-verifier` all build for
  `wasm32-unknown-unknown` with `-C target-feature=+simd128`.
- Native `cargo test -p binius-field` still passes (226 tests, 0 failures) — the change is
  `wasm32`-only and cannot affect other targets.
- A ZK proof generated and verified in Chrome 150 with the SIMD build: correct proof, 63 MB
  heap, entropy via `getrandom`'s JS backend.

### On performance — please don't merge this expecting a speedup

Measured on the SIMD build against the portable fallback, same circuit, same browser:
**488 ms vs 497 ms, about 2%.**

That is what the module's own definitions predict. All three arithmetic wrappers alias the
portable implementations:

```rust
pub type GhashWideMul1x<T> = crate::arch::portable::arithmetic::ghash::GhashWideMul<T>;
pub type GhashSquare1x<T>  = crate::arch::portable::arithmetic::ghash::GhashSoftMul<T>;
pub type GhashInvert1x<T>  = crate::arch::portable::arithmetic::itoh_tsujii::GhashItohTsujii<T>;
```

Only lane splitting and joining use wasm intrinsics; the arithmetic is portable. So this
is a **correctness** fix, not an optimisation. It is worth taking because a code path that
cannot compile is worse than no code path, and this one specifically punishes users who
reach for the obvious performance flag.

### Suggested follow-up (not in this patch)

Add a `wasm32-unknown-unknown` build with `+simd128` to CI. Without it this module is
unbuildable by construction and will rot again — it is the only architecture module no
configuration in CI compiles.

---

## Provenance

Found while porting an Ed25519 circuit to Binius64. Full write-up of the diagnosis,
including a wrong first diagnosis that is corrected inline, is at
`docs/notes/derisking-wasm32-and-blinding.md` in this repository.

The first diagnosis claimed the module was selected unconditionally on `target_arch` and
that no build flag avoided it. That was wrong — it reads `arch/mod.rs`, which dispatches on
architecture, and misses `arch/wasm32/mod.rs`, which does the `simd128` gating. Worth
stating because it changes the severity: the target is usable today by omitting the flag,
so this is not a blocker for anyone, merely a trap.
