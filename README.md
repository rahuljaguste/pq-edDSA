# PQ-EdDSA on Binius64

[![CI](https://github.com/rahuljaguste/pq-edDSA/actions/workflows/ci.yml/badge.svg)](https://github.com/rahuljaguste/pq-edDSA/actions/workflows/ci.yml)

Prove ownership of an Ed25519 key from its seed, in zero knowledge, without revealing the
seed or changing the on-chain address.

An implementation of the relation from **[Post-Quantum Readiness in EdDSA
Chains](https://eprint.iacr.org/2025/1368.pdf)** (Baldimtsi, Chalkias, Roy, Sedaghat;
FC 2026) on [Binius64](https://github.com/binius-zk/binius64), measured against the paper's
reference implementation [SoundnessLabs/PQChain](https://github.com/SoundnessLabs/PQChain),
which uses the Ligetron zkVM.

PQChain names its own bottleneck: Ligetron needs an FFT-friendly field and `p = 2^255 − 19`
is not one, so it emulates. Binius64 computes over 64-bit machine words and has no such
requirement. The numbers below are a property of the two proving systems, not of the two
implementations.

> **Research artifact.** Not audited, not production-ready. The zero-knowledge claim in
> particular is unaudited; see [Soundness](#soundness). Do not use this to secure real
> assets.

## Quick start

Rust is pinned by `rust-toolchain.toml`. Nothing else is needed for the CLI.

```bash
git clone https://github.com/rahuljaguste/pq-edDSA && cd pq-edDSA

# RFC 8032 test vector 1, so the seed is public and safe to paste.
cargo run --release --bin cli -- prove \
  --seed 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 \
  --out proof.bin

# Read a real seed from a file or stdin. --seed puts it in your shell history.
cargo run --release --bin cli -- prove --seed-file seed.hex --out proof.bin
cargo run --release --bin cli -- verify --proof proof.bin --pk <hex> --hx <hex>
cargo run --release --bin cli -- stat
```

The first build compiles Binius64 from a pinned git revision, so expect a few minutes.

Browser demo, additionally needing `cargo install wasm-bindgen-cli --version 0.2.126`:

```bash
./web/build.sh && (cd web && python3 -m http.server 8742)   # WIDE=1 for GF(2^256)
```

## What it proves

```
R_det  = { (pk, msg, hx) | ∃ seed      : pk = clamp(SHA-512(seed)[:32])·G ∧ hx = SHA-512(msg ‖ seed)      }
R_rand = { (pk, msg, hx) | ∃ seed, rx  : pk = clamp(SHA-512(seed)[:32])·G ∧ hx = SHA-512(msg ‖ seed ‖ rx) }
```

Both are implemented. `R_det` (Eq. 2) matches PQChain and is the CLI default for benchmark
parity. `R_rand` (Eq. 1) is the relation Theorem 2 is proved over, costs **+5 AND
constraints** and nothing measurable in time, and is the browser demo's default.

Under `R_det`, `hx` is an unsalted commitment to the seed: anyone holding `msg` and `hx`
can test candidates offline. Harmless at full entropy, fatal for a guessable seed.

## Results

| | PQ-EdDSA | PQ-EdDSA `--features wide` | PQChain (Ligetron) |
|---|---|---|---|
| constraints | **64,742** (57,314 AND + 7,428 IMUL) | **64,742** | 4,924,225 |
| prove | **113.9 ms** | **475 ms** | 5,400 ms |
| verify | **47.5 ms** | **215 ms** | 2,300 ms |
| proof size | **515 KiB** | **2,447 KiB** | 5.4 MB |
| peak memory | ~280 MB | ~670 MB | **34 MB** |
| soundness, classical | 96-bit | **~240-bit** | ~128-bit |
| soundness, quantum | ~48-bit | **~120-bit** | ~64-bit |
| host | M1 Pro, 8 cores | M1 Pro, 8 cores | M4 Pro, 12 cores |

The circuit is the same either way; only the proving system's field changes. Narrow beats
PQChain on every row but memory and soundness. Wide takes soundness too, and is still
**11.4× faster with a 2.2× smaller proof** than PQChain.

Wide costs **2.99× the prove time and 4.75× the proof** of narrow. That is measured
like-for-like, both on the fork. The two columns above look further apart than that because
the narrow one is measured against upstream, and **the fork carries a ~30% regression on the
narrow path** — 125 ms upstream against 159 ms on the fork at the same 96-bit target. A
repaired fork would make the wide column faster, not slower.

**Memory is the row where this loses**: 8× worse than PQChain narrow, 20× wide, and nothing
here is tuned for it.

Mine: 30 runs, first discarded, single-threaded, `log_inv_rate = 1`, **system load ~6 on 8
cores**, not a quiescent machine, so these are conservative. Theirs: from
PQChain's own README, 100 runs on an M4 Pro, not re-run here. Where their README and the
paper disagree I quote **the figure more favourable to them**: 5.4 s, not the paper's 6.2 s,
which would make the ratio 54× instead of 47×. Reproduce with
`cargo test -p pq-eddsa --release --test bench -- --ignored --nocapture`.

PQChain reports that non-native field emulation and scalar multiplication are **~70%** of
its constraints, SHA-512 another ~20%. Here SHA-512 costs **918 AND per compression block**
and both hashes are single-block, so it is ~3% of the circuit. Removing the emulation
requirement is the whole result.

### The wide configuration

`--features wide` selects `GF(2^256)` challenges with SHA-512, from an unmerged fork.
Medians, first run discarded, machine settled below load 4 before each:

| | classical | quantum | prove | verify | proof | setup | peak heap |
|---|---|---|---|---|---|---|---|
| native, narrow | 96 | ~48 | **159 ms** | 58 ms | 515 KiB | 108 ms | — |
| native, wide | **~240** | **~120** | **475 ms** | 215 ms | 2,447 KiB | 252 ms | — |
| browser, narrow | 96 | ~48 | **1,763 ms** | 245 ms | 515 KiB | 760 ms | 212 MB |
| browser, wide | **~240** | **~120** | **6,059 ms** | 1,639 ms | 2,447 KiB | 913 ms | 604 MB |

**2.5× the bits** for 2.99× the prove time. Against PQChain's ~64 quantum, narrow is below
at ~48 and wide is roughly double at ~120.

Browser figures are Chrome 150, cold profile, caching disabled: **11.1× native for narrow,
12.8× for wide**, because WebAssembly has no carry-less multiply. In both configurations
`pk`, `hx` and the proof match the native CLI byte for byte, and the page issues no network
requests after load.

All four rows carry the fork's ~30% narrow-path regression described above, so compare them
with each other and not with `main`.

## Soundness

| configuration | field | hash | classical | quantum (√Grover) |
|---|---|---|---|---|
| Ligetron (PQChain) | BN254 Fr | SHA-256 | ~128 | ~64 |
| **binius64, default** | GF(2^128) | SHA-256 | **96** | ~48 |
| binius64, target raised | GF(2^128) | SHA-256 | 112 (logUp\* cap) | ~56 |
| **`--features wide`** | GF(2^256) | SHA-512 | **~240** | **~120** |

Upstream fixes `SECURITY_BITS = 96` and exposes no override, so against upstream 96 is the
ceiling. This branch patches upstream: 112 is reachable on the narrow field, free in
proving time for +12% proof size, and `--features wide` reaches ~240. Past those, logUp\*
contributes a fixed `2^16/|F|` that no query budget affects: 112 narrow, 240 not 256 wide.
The default stays 96 so a narrow build stays comparable with `main`.

**Ligetron's figure is derived here, not published by Ligetron.** From `include/params.hpp`:
192 column openings, rate `ρ = 1/4`, SHA-256, BN254. Interleaved Reed–Solomon proximity at
the unique-decoding bound gives `(5/8)^192 = 2^-130.2`; SHA-256's `~2^-128` birthday bound
therefore binds. Check it rather than taking it on trust.

**The zero-knowledge claim is unaudited.** Binius64's `n_dummy_constraints` is hardcoded to
`2` with a `TODO` where its derivation should be. Raising it is free up to 2,133 on the
narrow build; upstream exposes no override, and the wide build's larger query count (232 →
579) draws on the same budget, so that ceiling is not known to hold there. Zero-knowledge is
a simulation property and a real answer needs a simulator construction.

## What is missing

**Blocked on upstream.** Soundness above 96 bits: `SECURITY_BITS` is fixed and the narrow
field caps at 112 regardless. `--features wide` clears it at ~240/~120, but on an unmerged
fork, which is the part that matters. 96 bits is checkable in one grep of upstream;
~240 rests on unreviewed work by the same person claiming it. **Until that fork is merged
and reviewed, the stronger number is the weaker claim.** Also: `n_dummy_constraints` is
hardcoded to 2 with no override.

**Mine.** An on-chain verifier: a design problem, not a missing contract, since 515 KiB
cannot be posted. A Web Worker, so proving does not freeze the tab for 1.7 s. Memory, ~280
MB against 34 MB, unprofiled: on a phone that beats the proving time I win on. Firefox and
Safari untested. An audit.

**Investigated and rejected.** Multi-core proving: rayon is within noise here, since the
prover is latency-bound at 57K AND constraints. `+simd128`: 0.7%, measured. Further IMUL
reduction: every lever lands in the same 2^13 padding tier.

## Acknowledgements

- Foteini Baldimtsi, Kostas Kryptos Chalkias, Arnab Roy and Mahdi Sedaghat for
  *[Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368.pdf)*
  (FC 2026; ePrint 2025/1368). The construction and its security argument are theirs; this
  implements their relation on a different proving system.
- [SoundnessLabs/PQChain](https://github.com/SoundnessLabs/PQChain) (Apache-2.0), measured
  against here, and specifically its `fix/ed25519-scalar-mul-secret-leak` commit, which
  named a bug class this repository now tests for explicitly.
- [Binius](https://www.binius.xyz) and [Irreducible](https://www.irreducible.com) for
  [Binius64](https://github.com/binius-zk/binius64), which is what makes the result
  possible.
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek), the
  independent reference throughout the test suite.

## More

99 tests, under each configuration.
[CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) ·
[design rationale](crates/ed25519/BOUNDS.md) ·
[upstream fix](https://github.com/binius-zk/binius64/pull/1993)
([patch](docs/binius64-wasm32-simd128.patch))

## Licence

MIT OR Apache-2.0.
