# PQ-EdDSA on Binius64

[![CI](https://github.com/rahuljaguste/pq-edDSA/actions/workflows/ci.yml/badge.svg)](https://github.com/rahuljaguste/pq-edDSA/actions/workflows/ci.yml)

Prove ownership of an Ed25519 key from its seed, in zero knowledge, without revealing the
seed or changing the on-chain address.

A proof-of-concept implementation of the relation from **[Post-Quantum Readiness in EdDSA
Chains](https://eprint.iacr.org/2025/1368.pdf)** (Baldimtsi, Chalkias, Roy, Sedaghat;
FC 2026) on [Binius64](https://github.com/binius-zk/binius64), for comparison with the
paper's reference implementation [SoundnessLabs/PQChain](https://github.com/SoundnessLabs/PQChain),
which uses the Ligetron zkVM.

It builds on PQChain's work. They identified the bottleneck as a field requirement of the
proving system rather than anything about their circuit: Ligetron needs an FFT-friendly
field, and `p = 2^255 − 19` is not one. Binius64 has no such requirement, computing natively
over 64-bit machine words instead of emulating a foreign field.

So the question here is theirs: what does a proving system without that requirement give you
on this relation? The numbers below measure it, and they are a property of the two proving
systems rather than of the two implementations.

> **Research artifact.** Not audited, not production-ready. The zero-knowledge claim in
> particular is unaudited; see [Soundness](#soundness). Do not use this to secure real
> assets.

## Quick start

Rust is pinned by `rust-toolchain.toml`, so rustup installs the right version and the
`wasm32-unknown-unknown` target on its own. Nothing else is needed for the CLI.

```bash
git clone https://github.com/rahuljaguste/pq-edDSA && cd pq-edDSA

# Prove that you know the seed behind a public key, revealing nothing about it.
# This is RFC 8032 test vector 1, so the seed is public and safe to paste.
cargo run --release --bin cli -- prove \
  --seed 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 \
  --out proof.bin
```

The first build compiles Binius64 from a pinned git revision, twenty-odd crates, so expect
a few minutes; later builds are seconds. Full command reference under [Usage](#usage).

For the browser demo, which additionally needs
`cargo install wasm-bindgen-cli --version 0.2.126`:

```bash
./web/build.sh && (cd web && python3 -m http.server 8742)
```

## What it proves

```
R_det  = { (pk, msg, hx) | ∃ seed      : pk = clamp(SHA-512(seed)[:32])·G ∧ hx = SHA-512(msg ‖ seed)      }
R_rand = { (pk, msg, hx) | ∃ seed, rx  : pk = clamp(SHA-512(seed)[:32])·G ∧ hx = SHA-512(msg ‖ seed ‖ rx) }
```

Both are implemented. `R_det` (Eq. 2) matches PQChain and is the **CLI** default, so
benchmarks compare like with like. `R_rand` (Eq. 1) is **the relation the paper's Theorem 2
is actually proved over**; it costs +5 AND constraints and nothing measurable in time, so
the [browser demo](#browser-proving) defaults to it instead. See [Relations](#relations).

## Why Binius64

Four properties, and the first is the one that decides the comparison.

- **It computes over 64-bit machine words.** Constraints are ANDs of shifted 64-bit words
  plus a native 64×64→128 integer multiply, so `p = 2^255 − 19` is four limbs of ordinary
  schoolbook bignum. There is no FFT-friendly-field requirement, so there is no foreign
  field to emulate, which is where PQChain spends ~70% of its constraints.
- **SHA-512 lands well for the same reason.** It is defined on 64-bit words, and costs
  **918 AND constraints per compression block** here. Both hashes in this relation are
  single-block, so together they are ~3% of the circuit. PQChain's own published breakdown
  puts SHA-512 at ~20% of theirs. The two constraint systems are not the same unit, so no
  ratio between the raw counts means much, but the shares are comparable: a hash defined
  on 64-bit words is a fifth of their circuit and a rounding error in this one. Measured by
  `crates/pq-eddsa/tests/sha512_cost.rs`.
- **Hash-based and transparent.** No trusted setup and no ceremony to trust, and the
  assumptions are hash collision and preimage resistance rather than discrete log or
  pairings. That is the right assumption family for an artifact about post-quantum
  readiness, though it is not sufficient on its own: the parameters upstream currently
  exposes give 96-bit classical and roughly 48-bit quantum security, which is not
  adequate. See [Soundness](#soundness).
- **The constraint graph is fixed before any witness exists.** A circuit whose shape
  depends on the secret is not expressible, which makes one real bug class structurally
  impossible rather than merely tested for.

## Results

Measured on this repository at commit time. Methodology below; please read it before
quoting these.

| | PQ-EdDSA (this) | PQChain (Ligetron) | ratio |
|---|---|---|---|
| constraints | **64,742** (57,314 AND + 7,428 IMUL) | 4,924,225 | **76× fewer** |
| prove | **113.9 ms** | 5,400 ms | **47× faster** |
| verify | **47.5 ms** | 2,300 ms | **48× faster** |
| proof size | **515 KiB** | 5.4 MB | **10.5× smaller** |
| **peak memory** | **~280 MB** | **34 MB** | **8× more, this is worse** |
| host | Apple M1 Pro, 8 cores | Apple M4 Pro, 12 cores | *this is slower silicon* |
| **soundness, classical** | **96-bit** | **~128-bit** | **this is weaker** |
| **soundness, quantum** | **~48-bit** | **~64-bit** | **this is weaker** |

The last four rows matter. My hardware is slower, which understates the gap; my memory
use and soundness are both worse, which overstates it. The quantum row is the one an
artifact about post-quantum readiness should be judged on, and it is the row where this
does worst — see [the wide configuration](#the-wide-configuration-measured-on-this-branch)
for what closes it. None of the four is negligible and all are quantified below.

Memory is measured as whole-process peak RSS over three runs; PQChain's README gives 34 MB
without stating how it was measured, so the two may not be counting the same thing. It is
reported here because they publish it and a comparison that quietly drops the metric where
I lose is not a comparison.

### The wide configuration, measured on this branch

`--features wide` selects a `GF(2^256)` challenge field with SHA-512, from an unmerged
fork. All four rows below were measured on this branch, medians with the first run
discarded, the machine settled below load 4 before each:

| | classical | quantum | prove | verify | proof | setup | peak heap |
|---|---|---|---|---|---|---|---|
| native, narrow | 96 | ~48 | **159 ms** | 58 ms | 515 KiB | 108 ms | — |
| native, wide | **~240** | **~120** | **475 ms** | 215 ms | 2,447 KiB | 252 ms | — |
| browser, narrow | 96 | ~48 | **1,763 ms** | 245 ms | 515 KiB | 760 ms | 212 MB |
| browser, wide | **~240** | **~120** | **6,059 ms** | 1,639 ms | 2,447 KiB | 913 ms | 604 MB |

Soundness first, because it is the only reason to pay the rest. Wide costs 2.99× prove and
4.75× proof size natively and buys **2.5× the classical bits and 2.5× the quantum bits**.
Both quantum figures are the square-root Grover heuristic applied to Fiat-Shamir challenge
search, and both are bound by logUp\* rather than by the query budget: 240 not 256 on the
wide field, 96 rising only to 112 on the narrow one. Proof sizes are byte-identical between
native and browser in both configurations.

For the comparison that matters to a post-quantum readiness artifact: PQChain carries ~64
bits quantum. Narrow is well below it at ~48; wide is roughly double at ~120.

**These are not comparable with the table above.** Every row here carries a ~30% narrow-path
regression in the fork: at the same 96-bit target, upstream proves in 125 ms and the fork in
159 ms. Compare the four rows with each other, never with `main`.

The browser penalty is 11.1× narrow and 12.8× wide. An earlier round measured 14.8× and
12.2×, the opposite ordering, so the two are close and this machine cannot separate them —
any claim that one is systematically cheaper would be over-reading single rounds under
sustained load.

### Why the gap is that large

PQChain publishes the breakdown itself:

| their category | constraints | share |
|---|---|---|
| non-native field emulation & scalar multiplication | ~3.4M | ~70% |
| SHA-512 operations | ~1.0M | ~20% |
| other (comparisons, assertions) | ~0.5M | ~10% |

That top row is not an implementation inefficiency; it is the price of representing `F_p`
for `p = 2^255 − 19` inside BN254, in three 85-bit limbs, because the proving system needs
an FFT-friendly field.

Binius64 pays none of it. A native 64×64→128 integer-multiply constraint makes 255-bit
arithmetic ordinary 4-limb schoolbook bignum, with no emulation layer underneath. SHA-512,
being 64-bit-word-oriented, is likewise native at 918 AND constraints per compression
block.

The measurement therefore **confirms PQChain's own diagnosis** rather than contradicting
it. Remove the emulation requirement and roughly 70% of the constraints go with it; the
constraint count falls 76×, which is more than 70% because the remaining work also gets
cheaper.

### Where Ligetron is ahead

Binius64 is not the better system on every axis, and several of the differences matter for
the paper's actual use case:

- **Memory.** They report 34 MB; I measure ~280 MB peak RSS, roughly 8× more. Binius64
  materialises a large witness and commitment structure even for a small circuit, and
  nothing here has been tuned for footprint. On a phone that gap matters more than
  proving time does.
- **Soundness.** Ligetron carries ~128-bit classical; this carries 96-bit, and upstream
  Binius64 offers no way to raise it. See [Soundness](#soundness). For a *post-quantum
  readiness* artifact this is the wrong direction to move.
- **Browser proving.** Ligetron was designed for it: WebAssembly with WebGPU shaders, and
  PQChain ships a hosted demo with wallet integration. This runs in a browser too
  ([below](#browser-proving)), but it costs **14.8× native** for a reason that is not going
  away soon: WebAssembly has no carry-less multiply instruction, so GF(2^128) multiplication
  falls back to software. Binius64 also has no GPU path. On client-side proving, which is
  central to the paper's argument since the seed must never leave the user's machine,
  Ligetron is the more mature choice today.
- **Maturity.** Ligetron is a released zkVM. Binius64's zero-knowledge path is new enough
  that its blinding parameter still carries a `TODO` upstream.

## Soundness

**This PoC carries 96-bit classical soundness by default. PQChain carries ~128-bit.
That is a real difference and it is not in my favour** — see below for what this branch
reaches, and at what cost to how much you should trust it.

Upstream Binius64 fixes `SECURITY_BITS = 96` (`crates/verifier/src/verify.rs` in *their*
repository, not this one) and `ZKVerifier::setup` accepts no override, so **against
upstream** 96 is the only setting available.

This branch patches upstream, so on it 96 is a default rather than a ceiling. `112` is
reachable on the narrow field and was measured free in proving time for +12% proof size;
past it the logUp\* term contributes a fixed `2^16/|F| = 2^-112` that no query budget
affects. `--features wide` moves to `GF(2^256)` and reaches ~240. The default stays 96 so
that a narrow build here is directly comparable with `main`.

| configuration | field | hash | classical | quantum (√Grover) |
|---|---|---|---|---|
| Ligetron (PQChain) | BN254 Fr | SHA-256 | ~128 | ~64 |
| **binius64, as used here** | GF(2^128) | SHA-256 | **96** | ~48 |
| binius64, query budget raised | GF(2^128) | SHA-256 | 112 (logUp\* cap) | ~56 |
| GF(2^256) challenges, SHA-512 | GF(2^256) | SHA-512 | ~240 | ~120 |

Ligetron's figure is derived here, not published by Ligetron. Its codebase contains no
soundness documentation (no occurrence of "soundness", "security parameter", or "bits of
security"). From `include/params.hpp`: 192 column openings, rate `ρ = 8192/32768 = 1/4`,
one repetition of each test, SHA-256 for Merkle and Fiat–Shamir, BN254 scalar field.
Interleaved Reed–Solomon proximity at the unique-decoding bound gives per-column pass
probability `(1+ρ)/2 = 5/8`, so the query phase is `(5/8)^192 = 2^-130.2`; field terms are
`2^15/2^254 = 2^-239`, negligible; SHA-256's `~2^-128` birthday bound therefore binds. The
unique-decoding assumption is the paper's own; it states Ligetron "is instantiated using
proximity within the unique-decoding bound".

Both derivations should be checked rather than taken on trust.

### The zero-knowledge claim is unaudited

Binius64's ZK blinding parameter `n_dummy_constraints` is set to `2` upstream with a
`// TODO: Document why these are necessary`. Its sibling `n_dummy_wires` *is* derived: one
random wire per FRI query opening. This one is not.

I measured that raising it is free up to 2,133 for this circuit, and recommend 2,048
(1,024× the default) on that basis, but upstream exposes no override, so it is recorded
rather than applied. **This does not establish that 2 is insufficient.** Zero-knowledge is a
simulation property; a real answer needs a simulator construction. The ceiling is pinned by
`crates/pq-eddsa/tests/circuit_size.rs`, which fails if the circuit changes enough to move
it.

That matters more here than in most applications, because the witness is a private key.

## Relations

Under `R_det`, `hx = SHA-512(msg ‖ seed)` is a **deterministic** function of the seed, so
anyone holding the public `msg` and `hx` can test candidate seeds offline. `hx` is
effectively an unsalted commitment to the private key. Against a full-entropy 256-bit seed
that is not a practical attack, which is presumably why PQChain ships it. But it bites for
any seed drawn from a searchable space: a weak mnemonic, a low-entropy RNG, a seed derived
from something guessable. Ruling that out is exactly what `rx` does, and why Theorem 2 is
stated over Eq. 1.

`R_rand` costs **+5 AND constraints and no extra multiplications**: `msg ‖ seed ‖ rx` is
96 bytes, still inside a single 128-byte SHA-512 block. In the browser that is below the
noise floor: two cold browsers per relation put warm proving at 1,681–1,684 ms for `R_det`
and 1,681–1,689 ms for `R_rand`, a gap smaller than the one between two runs of the same
relation. **Nothing is traded for the stronger relation**, which is why the demo defaults
to it and why `R_det` remains only for PQChain parity.

```bash
cargo run --release --bin cli -- prove --seed <hex> --relation rand
```

Two `rand` proofs of the same seed produce different `hx`; two `det` proofs produce
identical `hx`.

## Usage

```bash
# Circuit statistics
cargo run --release --bin cli -- stat

# Prove. The seed is the witness: it is never published and the proof does not
# reveal it. Read it from a file or stdin rather than argv --
# `--seed <hex>` would land in your shell history.
cargo run --release --bin cli -- prove --seed-file seed.hex --out proof.bin
printf %s "$SEED" | cargo run --release --bin cli -- prove --seed-file - --out proof.bin

# Verify against public inputs only
cargo run --release --bin cli -- verify \
  --proof proof.bin --pk <hex> --hx <hex>
```

`--seed <hex>` still exists, and the examples elsewhere in this README use it with RFC 8032
test vector 1, a published seed with nothing to protect. For a seed you care about, use
`--seed-file`. Zero-knowledge protects the seed from the *verifier*; it does nothing about
the shell you typed it into.

The verifier reconstructs the circuit's public input words from `(pk, msg, hx)` alone
and never trusts a prover-supplied blob. A proof is valid for *whatever* public input
accompanies it, so a verifier that takes the prover's word can be handed a sound proof of a
different statement.

## Browser proving

The seed must never leave the user's machine. That is the paper's premise, and it only
holds if the proof is generated where the seed already is. So it runs in the browser:

```bash
./web/build.sh                              # needs `cargo install wasm-bindgen-cli`
(cd web && python3 -m http.server 8742)     # file:// fails CORS
open http://localhost:8742/
```

Paste or generate a seed, click prove, watch it verify, then click *Verify against a
tampered statement* to watch it refuse. Nothing is transmitted: the page is static files
with no server component, and after the module loads it issues no network requests at all,
which is checkable in DevTools rather than merely asserted here.

Measured in Chrome 150 on the same M1 Pro, single-threaded, cold profile with caching
disabled, two independent browsers per relation:

| | `R_rand` | `R_det` | native (`R_det`) |
|---|---|---|---|
| circuit build + prover setup (one-time) | 701–707 ms | 705–707 ms | — |
| prove | **1,681–1,689 ms** | 1,682–1,684 ms | 113.9 ms |
| verify | **221 ms** | 222–227 ms | 47.5 ms |
| proof size | 515 KiB | 515 KiB | 515 KiB |
| peak wasm heap | 213 MB | 213 MB | — |

`R_rand` is quoted first here deliberately. The native table above uses `R_det` for
parity with PQChain, comparing like with like. This section makes no PQChain comparison,
so parity buys nothing, and the relation that belongs in a *deployment* story is the one
the paper's Theorem 2 is proved over. The demo page defaults to `R_rand` for the same
reason, while the CLI keeps `R_det` for benchmark parity.

The choice costs nothing: the two relations differ by less than the spread between repeated
runs of either one, which is what +5 AND constraints predicts. Against native `R_det`, the
browser penalty is **14.8× on proving and 4.7× on verification**.

The browser's `pk`, `hx` and proof size match the native CLI byte for byte.

Those figures are `main`'s, against upstream. A build of this branch is slower on every
row, because the fork it patches in carries a ~30% narrow-path regression: browser narrow
measures 1,763 ms here rather than 1,684. See
[the wide configuration](#the-wide-configuration-measured-on-this-branch) for all four
combinations measured on the branch itself, including what `--features wide` costs in a
browser (6,059 ms, 604 MB).

**Why 15×, and why `+simd128` does not fix it.** binius64 multiplies in GF(2^128) with a
hardware carry-less multiply on both native architectures: `vmull_p64` on aarch64,
`_mm_clmulepi64_si128` on x86-64. WebAssembly has no such instruction, so wasm32 falls
through to a software GHASH multiply. Enabling `+simd128` (with my upstream fix) buys
**0.7%**, because the wasm SIMD module can only accelerate lane splitting, not the
multiply. This is a property of the field, not of this circuit, and would apply to any
GF(2^128) prover targeting the web today.

Reproducing that last figure needs a `[patch]` section pointing *every* `binius-*` crate at
a copy of the pinned revision with
[`docs/binius64-wasm32-simd128.patch`](docs/binius64-wasm32-simd128.patch) applied; patching
only some of them duplicates `binius-utils` and breaks trait identity. Everything else in
this section reproduces with `./web/build.sh` and `web/bench.html`.

I deliberately do **not** compare this to PQChain's 5.4 s: their README does not say
whether that figure is a browser measurement, and I have not re-run it. Comparing a
browser number against one of unknown provenance would be the sort of ratio that flatters
whoever picks it.

## Benchmark methodology

Please read this before quoting the numbers above.

- **Host:** Apple M1 Pro, 8 cores, macOS 25.5, rustc 1.97.1, single-threaded.
- **Configuration:** ZK path, `log_inv_rate = 1`, SHA-256 Merkle, `R_det`.
- **Runs:** 30, first discarded. The first run of a process measures ~1.6× slow from
  warm-up. Reported as mean, with median/min/max in the raw output.
- **Distribution:** prove mean 113.9, median 113, min 110, max 128. Verify mean 47.5,
  median 48, min 46, max 49.
- **System load at measurement: ~6 on 8 cores.** Not a quiescent machine. A quieter host
  would likely be faster, so these figures are conservative rather than flattering.
- **PQChain's figures** are from its own README (average of 100 runs, M4 Pro 12-core). I
  have not re-run them, so this is not a controlled comparison: different silicon,
  different day, their measurement not mine.
- **Their README does not say which backend produced those numbers.** The binaries it
  documents are named `webgpu_prover` and `webgpu_verifier`, and it states neither that
  GPU acceleration was used for the 5.4 s figure nor that it was not. If it was, my
  single-threaded CPU comparison is more conservative than the table suggests. I am not
  claiming that it was.
- **Where PQChain's README and the paper disagree, I use the figure more favourable to
  PQChain.** The README reports 5.4 s proving; the paper reports 6.2 s. Using 6.2 s would
  make the ratio 54× rather than 47×. The README is their current claim and the more
  conservative choice for me, so it is the one quoted.
- **PQChain describes itself as a work in progress** whose "APIs, circuit design, and
  implementation details may change without notice". Benchmarking against a self-declared
  WIP warrants some caution about how much weight these ratios carry.

Reproduce:

```bash
cargo test -p pq-eddsa --release --test bench -- --ignored --nocapture
```

A caution learned the hard way: the same binary measured 121 ms under load 8 and 114 ms
under load 6. **Absolute timings on a busy machine are unreliable**, and a 50% error is
more than enough to invalidate a comparison. Relative results in this repository
(Blake3-vs-SHA-256, rayon-vs-single-threaded, the comb window sweep) were taken
back-to-back under identical conditions and are more trustworthy than the absolutes.

## Design notes

The interesting decisions, with measurements, are in
[`crates/ed25519/BOUNDS.md`](crates/ed25519/BOUNDS.md):

- **`F_p` modulo `2p`.** `p = 2^255 − 19` is not limb-aligned, so binius64's
  pseudo-Mersenne reduction rejects it. `2p = 2^256 − 38` *is*, with a one-limb subtrahend,
  so the existing fast path applies unmodified. Field elements become non-canonical
  representatives in `[0, 2p)`, canonicalised only where bits, not residues, are read.
- **Comb window = 6, chosen by measuring proving time, not constraint counts.** Ranking by
  AND count picks 5 and is wrong: `w = 6` has ~9% more AND constraints yet proves ~6%
  faster, because it drops the padded IMUL size from 2^14 to 2^13.
- **Signed-digit recoding** halves the multiplexer tables (33 entries, not 64), taking AND
  from 70,252 to 57,314 and crossing 2^17 → 2^16. Worth ~5%, not more; AND was never the
  bottleneck.
- **IMUL is at its practical floor.** Even a hypothetical zero-cost modular reduction stays
  in the same 2^13 padding tier.
- **No in-circuit inversion.** Affine coordinates arrive as a hint, pinned by two
  multiplications plus canonicality. Cheaper than an exponentiation, and forced by `2p`
  being composite.

## Testing

99 tests, under each of the two configurations. The suite is built around negative tests, because an under-constrained circuit
passes every positive test: it proves true statements correctly and false ones too.

- Differential against `curve25519-dalek` at every window size, plus RFC 8032 vectors.
- **Non-canonical representative** property tests drawing from all of `[0, 2p)`, including
  the upper half an adversarial witness can supply. These are the only thing that catches a
  missing canonicalisation.
- **Mutation-verified**: each negative test is checked to fail when the assertion it guards
  is deleted. A test that cannot fail proves nothing.
- Circuit-shape invariance: the constraint system must not depend on the witness. PQChain
  shipped a bug of exactly this class (`fix/ed25519-scalar-mul-secret-leak`); in Binius64
  it is structurally impossible, since the graph is fixed before any witness exists.
- The browser bindings are covered natively, not only by a browser run: `pq-eddsa-wasm`
  holds its logic in a plain-Rust `Session` with a thin `#[wasm_bindgen]` adapter over it,
  so round-trips, `rx` randomisation, and statement tampering are all ordinary
  `cargo test`. The browser run then checks that the same code agrees with the native CLI
  byte for byte.

## What is missing

This is a proof of concept, and the gaps are as interesting as the results. Ordered by how
much they matter for the paper's actual use case.

**Blocked on upstream Binius64:**

- **Soundness above 96 bits, upstream.** `SECURITY_BITS` is fixed and
  `ZKVerifier::setup` takes no override, and the narrow field caps the achievable level at
  112 regardless. Reaching a level worth calling post-quantum needs a wider challenge
  field.

  **This branch has done it, against an unmerged fork.** `--features wide` selects
  GF(2^256) challenges with SHA-512 and delivers **~240 bits classical, ~120 quantum**,
  measured, with every test passing under both configurations. On `R_det` it proves in
  475 ms and verifies in 215 ms against a 2,447 KiB proof — 2.99× the narrow prove time,
  and still 11× faster than PQChain with roughly twice its soundness. Full numbers under
  [Results](#the-wide-configuration-measured-on-this-branch).

  What remains blocked is the part that matters most. 96 bits is checkable in one grep of
  upstream; ~240 rests on unreviewed work by the same person claiming it. Until that fork
  is merged and reviewed, the stronger number is the weaker claim.
- **A settable ZK blinding parameter.** `n_dummy_constraints` is hardcoded to 2 with a
  `TODO` where its derivation should be. I measured that 2,048 would be free on the narrow
  build, but there is no way to ask for it — and the wide build raises the FRI query count
  from 232 to 579, which eats the same budget, so that ceiling is not known to hold there.

**Mine to do:**

- **An on-chain verifier.** The paper's setting is a chain, and nothing here verifies a
  proof on one. At 515 KiB a proof is far too large to post directly, so this is a real
  design problem rather than a matter of writing a contract.
- **Browser UX.** Proving blocks the main thread for ~1.7 s. A Web Worker would fix the
  freeze without making anything faster. Firefox and Safari are untested; only Chrome 150
  has been measured.
- **Memory footprint.** ~280 MB peak RSS against PQChain's reported 34 MB. Nothing here
  has been tuned for it and no profiling has been done, so it is not known how much is
  inherent to Binius64 and how much is mine. On a phone this matters more than the
  proving time I win on.
- **An audit.** None of this has had one. See [SECURITY.md](SECURITY.md).

**Investigated, and deliberately not doing:**

- **Multi-core browser proving.** `SharedArrayBuffer` with COOP/COEP headers is real work,
  and it would buy approximately nothing: rayon measures within noise on a circuit this
  small even natively, because the prover is latency-bound rather than throughput-bound at
  57K AND constraints. Measured in [`crates/ed25519/BOUNDS.md`](crates/ed25519/BOUNDS.md).
- **`+simd128` for the browser build.** Worth 0.7%, measured, and it needs a fix that is
  still open upstream. WebAssembly has no carry-less multiply for the module to reach.
- **Squeezing IMUL further.** Every available lever lands in the same 2^13 padding tier,
  so there is nothing there to win. The table is in
  [BOUNDS.md](crates/ed25519/BOUNDS.md).

## Upstream contribution

While porting, I found that `binius-field` does not compile for `wasm32-unknown-unknown`
with `+simd128`, a module orphaned by a refactor. Submitted upstream as
**[binius-zk/binius64#1993](https://github.com/binius-zk/binius64/pull/1993)**; the change
itself is two insertions and twenty-one deletions, kept here as
[`docs/binius64-wasm32-simd128.patch`](docs/binius64-wasm32-simd128.patch).

It is offered as a correctness fix, not an optimisation, and the PR says so: with the fix
applied, `+simd128` is worth 0.7% on this circuit. The demo does not need it at all — omit
the flag and wasm32 builds today. The PR body carries the full diagnosis.

## Acknowledgements

- Foteini Baldimtsi, Kostas Kryptos Chalkias, Arnab Roy and Mahdi Sedaghat for
  *[Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368.pdf)*
  (FC 2026; full version at ePrint 2025/1368), which this implements. The construction and
  its security argument are entirely theirs; this repository is an implementation of their
  relation on a different proving system.
- [SoundnessLabs/PQChain](https://github.com/SoundnessLabs/PQChain) (Apache-2.0) for the
  reference implementation this is measured against, and specifically for its
  `fix/ed25519-scalar-mul-secret-leak` commit, which named a bug class (constraint-graph
  shape depending on the secret scalar) that this repository now tests for explicitly.
- [Binius](https://www.binius.xyz) and [Irreducible](https://www.irreducible.com) for
  [Binius64](https://github.com/binius-zk/binius64), which is what makes the result here
  possible: the whole comparison is a property of their proving system, not of this
  circuit.
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek), used as the
  independent reference throughout the test suite.

## Repository layout

| path | what it is |
|---|---|
| `crates/ed25519/` | The circuit gadgets: field arithmetic mod `2p`, points, comb scalar multiplication, compression. The design argument is in [`BOUNDS.md`](crates/ed25519/BOUNDS.md). |
| `crates/pq-eddsa/` | The relation itself, plus the `cli` prover and verifier. |
| `crates/pq-eddsa-wasm/` | Browser bindings. Plain-Rust `Session`, thin `#[wasm_bindgen]` adapter over it. |
| `web/` | The demo page, the benchmark harness, and `build.sh`. |
| `docs/` | The patch submitted upstream to Binius64. |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The conventions worth knowing before you start are
that negative tests must be mutation-verified, and that any figure added to a document
needs a measurement in the repository behind it.

## Licence

MIT OR Apache-2.0.
