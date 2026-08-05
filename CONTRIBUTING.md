# Contributing

Contributions are welcome. [What is missing](README.md#what-is-missing) lists the open
gaps and, just as usefully, the things that were investigated and turned out to be dead
ends. Read that before starting on performance work.

## Before opening a pull request

Run what CI runs:

```bash
cargo test --workspace --release
cargo fmt --all --check
cargo clippy --workspace --all-targets --release -- -D warnings
cargo build --release --target wasm32-unknown-unknown -p pq-eddsa-wasm
```

Release mode is not optional for the tests. Proving in debug is slow enough that the suite
appears to hang.

## Conventions you cannot infer from the code

These four are what the repository is actually built around. Each exists because it caught
something real.

**A negative test must be mutation-verified.** Delete the assertion it guards and confirm
the test fails. An under-constrained circuit passes every positive test: it proves true
statements correctly and false ones too, so positive tests establish almost nothing about
soundness. This convention caught a canonicality assertion in `to_affine` with *no*
deployed coverage: the whole suite passed with it removed, because the test had rebuilt
the logic alongside the function instead of calling it.

**A number in a document needs a measurement in the repository.** Not a derivation, and
not a figure carried over from somewhere else. The README quoted a SHA-512 cost that
appeared nowhere but the README, and measuring it showed the label was wrong by a factor
of two. If you add a figure, add the test that produces it.

**Measure padding boundaries; do not derive them.** Constraint counts pad to powers of two,
which makes optimisation discontinuous and intuition unreliable. Two predictions here were
wrong: the comb window (predicted 4, measured 6, because ranking by AND count picks the wrong
one) and the ZK blinding ceiling (predicted ~12,000, measured ~2,132). Treat a derived
boundary as a hypothesis.

**Benchmarks need a quiet machine, and relative beats absolute.** The same binary has read
121 ms at load 8 and 114 ms at load 6 here. Check `uptime` first. Comparisons taken
back-to-back under identical conditions are trustworthy in a way that absolute timings are
not, so prefer them.

## Working on the field layer

`crates/ed25519` represents `F_p` modulo **`2p = 2^256 − 38`**, not `p`. `p = 2^255 − 19`
is not limb-aligned and Binius64's pseudo-Mersenne reduction rejects it. Two consequences:

- Elements are **non-canonical representatives** in `[0, 2p)`. Canonicalise wherever *bits*
  rather than residues are read. The four places this is required are enumerated in
  [`BOUNDS.md`](crates/ed25519/BOUNDS.md#where-canonicalisation-is-required).
- **Never call `PseudoMersennePrimeField::inverse` or `::div`.** Both assume a prime
  modulus, and `2p` is composite. See `BOUNDS.md`.

Property tests must draw representatives from all of `[0, 2p)`, including the upper half.
An adversarial witness can supply those, and they are the only thing that catches a missing
canonicalisation.

## Circuit shape must not depend on the witness

The constraint graph is fixed before any witness exists, so a secret-dependent shape is not
expressible. But a host-side helper can still leak by branching on a secret. PQChain
shipped a bug of exactly this class. Tests assert shape invariance; keep them passing.

## Dependencies

Binius64 is pinned to a git revision in the workspace `Cargo.toml`, and `Cargo.lock` is
committed deliberately: the published benchmarks only reproduce if the whole graph is
pinned. Bumping the revision is a real change: re-run the benchmarks and update the
figures in the same pull request.

If you find a bug in Binius64 itself, upstream it. I did once already, and the README says
what came of it.

## Scope

This is an unaudited proof of concept and is not trying to become a product. Changes that
make it a better *measurement*, meaning clearer or more reproducible or better covered,
are easier to land than changes that add surface area. See [SECURITY.md](SECURITY.md) for what has and
has not been checked.
