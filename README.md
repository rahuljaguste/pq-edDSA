# PQ-EdDSA on Binius64

[![CI](https://github.com/rahuljaguste/pq-edDSA/actions/workflows/ci.yml/badge.svg)](https://github.com/rahuljaguste/pq-edDSA/actions/workflows/ci.yml)

Prove ownership of an Ed25519 key from its seed, in zero knowledge, without revealing the
seed or changing the on-chain address. The setting is Ed25519 chains: Sui, Solana, Near.

This implements the relation from **[Post-Quantum Readiness in EdDSA
Chains](https://eprint.iacr.org/2025/1368.pdf)** (Baldimtsi, Chalkias, Roy, Sedaghat;
FC 2026) on [Binius64](https://github.com/binius-zk/binius64). It is measured against the
paper's reference implementation,
[SoundnessLabs/PQChain](https://github.com/SoundnessLabs/PQChain), which uses the Ligetron
zkVM.

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

# A proof records none of the settings it was made under, and getting one wrong fails
# exactly like a forged proof does. prove prints the matching command; paste that.
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

The circuit is identical in both columns. Only the proving system's field changes.

Narrow beats PQChain everywhere except memory and soundness. Wide wins those two as well,
and is still **11.4× faster with a 2.2× smaller proof**. What it costs is **2.99× the prove
time and 4.75× the proof size** of narrow, measured like-for-like on the fork.

The two columns look further apart than 2.99× because they were measured differently. The
narrow one runs against upstream, the wide one against the fork. And **the fork is ~30%
slower on the narrow path**: 125 ms against 159 ms, at the same 96-bit target. Repairing
that would make the wide column faster, not slower.

**Memory is the one row where this loses.** Narrow uses 8× what PQChain does, wide 20×, and
nothing here has been tuned for it.

How these were measured:

- **Mine.** 30 runs, first discarded. Single-threaded, `log_inv_rate = 1`. **System load ~6
  on 8 cores**, so not a quiescent machine, and these figures are conservative.
- **Theirs.** From PQChain's own README: 100 runs on an M4 Pro. Not re-run here.
- **Where their README and the paper disagree**, I quote the figure more favourable to
  them. 5.4 s, not the paper's 6.2 s, which would make the ratio 54× instead of 47×.

```bash
cargo test -p pq-eddsa --release --test bench -- --ignored --nocapture
```

`--release` is not optional. A debug build produces the same proof byte for byte and
prints the same format, but takes 14,563 ms against 159 ms. The harness refuses to run
without it.

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

Wide buys **2.5× the bits**, classical and quantum alike. Set against PQChain's ~64-bit
quantum figure, narrow falls short at ~48 and wide roughly doubles it at ~120.

Browser figures are Chrome 150, cold profile, caching disabled: **11.1× native for narrow,
12.8× for wide**, because WebAssembly has no carry-less multiply. In both configurations
`pk`, `hx` and the proof match the native CLI byte for byte, and the page issues no network
requests after load.

All four rows carry the fork's ~30% narrow-path regression described above, so compare them
with each other, not with an upstream build.

## Soundness

| configuration | field | hash | classical | quantum (√Grover) |
|---|---|---|---|---|
| Ligetron (PQChain) | BN254 Fr | SHA-256 | ~128 | ~64 |
| **binius64, default** | GF(2^128) | SHA-256 | **96** | ~48 |
| binius64, target raised | GF(2^128) | SHA-256 | 112 (logUp\* cap) | ~56 |
| **`--features wide`** | GF(2^256) | SHA-512 | **~240** | **~120** |

Upstream fixes `SECURITY_BITS = 96` and exposes no override, so 96 is the ceiling against
upstream. This branch patches it, which opens two routes higher. Staying on the narrow
field reaches 112, free in proving time and costing +12% proof size. Switching to
`--features wide` reaches ~240.

Neither goes higher. logUp\* contributes a fixed `2^16/|F|` that no query budget affects,
capping the narrow field at 112 and the wide one at 240, not 256. The default stays at 96
so a narrow build here remains comparable with upstream.

**Ligetron's figure is derived here, not published by Ligetron.** From `include/params.hpp`:
192 column openings, rate `ρ = 1/4`, SHA-256, BN254. Interleaved Reed–Solomon proximity at
the unique-decoding bound gives `(5/8)^192 = 2^-130.2`; SHA-256's `~2^-128` birthday bound
therefore binds. Check it rather than taking it on trust.

**The zero-knowledge claim is unaudited.** Binius64 hardcodes `n_dummy_constraints` to `2`,
with a `TODO` where its derivation should be. Raising it is free up to 2,133 on the narrow
build, but upstream exposes no override, so the value cannot be set.

That ceiling is not known to hold under `--features wide`, which raises the FRI query count
from 232 to 579 and draws on the same budget. None of this establishes zero-knowledge
anyway. Zero-knowledge is a simulation property, and answering it properly needs a
simulator construction.

## What is missing

**Blocked on upstream.** Two things: soundness above 96 bits, and a settable
`n_dummy_constraints`.

`--features wide` does reach ~240/~120, but only against an unmerged fork, and the fork is
the problem. Anyone can check 96 bits with one grep of upstream. ~240 rests on unreviewed
work by the same person claiming it. **Until that fork is merged and reviewed, the stronger
number is the weaker claim.**

**Mine.**

- A Web Worker, so proving does not freeze the tab for 1.7 s.
- Memory. ~280 MB against PQChain's 34 MB, and unprofiled. On a phone that would matter
  more than the proving time this wins on.
- Firefox and Safari, both untested. Only Chrome 150 has been measured.
- An audit. There has not been one.

**Investigated and rejected.** Multi-core proving would buy nothing, because rayon measures
within noise at 57K AND constraints, where the prover is latency-bound. `+simd128` is worth
0.7%, measured. Reducing IMUL further is impossible: every available lever lands in the same
2^13 padding tier.

## Acknowledgements

- Foteini Baldimtsi, Kostas Kryptos Chalkias, Arnab Roy and Mahdi Sedaghat for
  *[Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368.pdf)*
  (FC 2026; ePrint 2025/1368). The construction and its security argument are theirs; this
  implements their relation on a different proving system.
- [SoundnessLabs/PQChain](https://github.com/SoundnessLabs/PQChain) (Apache-2.0), the
  implementation measured against here, and in particular its
  `fix/ed25519-scalar-mul-secret-leak` commit, which named a bug class this repository now
  tests for explicitly.
- [Binius](https://www.binius.xyz) and [Irreducible](https://www.irreducible.com) for
  [Binius64](https://github.com/binius-zk/binius64). The result is a property of their
  proving system.
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
