# PQ-EdDSA on Binius64

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
  single-block, so the two of them together are ~3% of the circuit and the scalar
  multiplication is essentially the whole cost. Measured by
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
| host | Apple M1 Pro, 8 cores | Apple M4 Pro, 12 cores | *ours is slower silicon* |
| **soundness** | **96-bit classical** | **~128-bit classical** | **ours is weaker** |

The last two rows matter. Our hardware is slower, which understates the gap; our
soundness is lower, which overstates it. Neither is negligible and both are quantified
below.

### Why the gap is that large

PQChain reports that non-native field emulation and the public-key consistency check are
**~70% of its 4.9M constraints**. That is not an implementation inefficiency; it is the
price of representing `F_p` for `p = 2^255 − 19` inside BN254, in three 85-bit limbs,
because the proving system needs an FFT-friendly field.

Binius64 pays none of it. A native 64×64→128 integer-multiply constraint makes 255-bit
arithmetic ordinary 4-limb schoolbook bignum, with no emulation layer underneath. SHA-512,
being 64-bit-word-oriented, is likewise native at 918 AND constraints per compression
block.

The measurement therefore **confirms PQChain's own diagnosis** rather than contradicting
it. Remove the emulation requirement and roughly 70% of the constraints go with it; the
constraint count falls 76×, which is more than 70% because the remaining work also gets
cheaper.

### Where Ligetron is ahead

Binius64 is not the better system on every axis, and two of the differences matter for the
paper's actual use case:

- **Soundness.** Ligetron carries ~128-bit classical; we carry 96-bit, and upstream
  Binius64 offers no way to raise it. See [Soundness](#soundness). For a *post-quantum
  readiness* artifact this is the wrong direction to move.
- **Browser proving.** Ligetron was designed for it: WebAssembly with WebGPU shaders, and
  PQChain ships a hosted demo with wallet integration. Ours runs in a browser too
  ([below](#browser-proving)), but it costs **14.8× native** for a reason that is not going
  away soon: WebAssembly has no carry-less multiply instruction, so GF(2^128) multiplication
  falls back to software. Binius64 also has no GPU path. On client-side proving, which is
  central to the paper's argument since the seed must never leave the user's machine,
  Ligetron is the more mature choice today.
- **Maturity.** Ligetron is a released zkVM. Binius64's zero-knowledge path is new enough
  that its blinding parameter still carries a `TODO` upstream.

## Soundness

**This PoC carries 96-bit classical soundness. PQChain carries ~128-bit. That is a real
difference and it is not in our favour.**

Upstream Binius64 fixes `SECURITY_BITS = 96` (`crates/verifier/src/verify.rs`) and
`ZKVerifier::setup` accepts no override, so 96 is the only setting available. Reaching even
112 would require patching upstream, and the narrow field caps there regardless: the
logUp\* term contributes a fixed `2^16/|F| = 2^-112` that no query budget affects.

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

We measured that raising it is free up to 2,132 for this circuit, and recommend 2,048
(1,024× the default) on that basis, but upstream exposes no override, so it is recorded
rather than applied. **This does not establish that 2 is insufficient.** Zero-knowledge is a
simulation property; a real answer needs a simulator construction. See
[`docs/notes/zk-blinding-parameter.md`](docs/notes/zk-blinding-parameter.md).

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

**Why 15×, and why `+simd128` does not fix it.** binius64 multiplies in GF(2^128) with a
hardware carry-less multiply on both native architectures: `vmull_p64` on aarch64,
`_mm_clmulepi64_si128` on x86-64. WebAssembly has no such instruction, so wasm32 falls
through to a software GHASH multiply. Enabling `+simd128` (with our upstream fix) buys
**0.7%**, because the wasm SIMD module can only accelerate lane splitting, not the
multiply. This is a property of the field, not of this circuit, and would apply to any
GF(2^128) prover targeting the web today.

Full methodology, the `R_rand` figures, and the SIMD comparison:
[`docs/notes/browser-proving.md`](docs/notes/browser-proving.md).

We deliberately do **not** compare this to PQChain's 5.4 s: their README does not say
whether that figure is a browser measurement, and we have not re-run it. Comparing a
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
- **PQChain's figures** are from its own README (average of 100 runs, M4 Pro 12-core). We
  have not re-run them, so this is not a controlled comparison: different silicon,
  different day, their measurement not ours.
- **Where PQChain's README and the paper disagree, we use the figure more favourable to
  PQChain.** The README reports 5.4 s proving; the paper reports 6.2 s. Using 6.2 s would
  make our ratio 54× rather than 47×. The README is their current claim and the more
  conservative choice for us, so it is the one quoted.
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

92 tests. The suite is built around negative tests, because an under-constrained circuit
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

## Upstream contribution

While porting, we found that `binius-field` does not compile for `wasm32-unknown-unknown`
with `+simd128`, a module orphaned by a refactor. Submitted upstream as
**[binius-zk/binius64#1993](https://github.com/binius-zk/binius64/pull/1993)**; the change
itself is two insertions and twenty-one deletions, kept here as
[`docs/binius64-wasm32-simd128.patch`](docs/binius64-wasm32-simd128.patch).

It is offered as a correctness fix, not an optimisation, and the PR says so: with the fix
applied, `+simd128` is worth 0.7% on this circuit. The demo does not need it at all — omit
the flag and wasm32 builds today. The diagnosis, including a first attempt that was
backwards, is in
[`docs/notes/derisking-wasm32-and-blinding.md`](docs/notes/derisking-wasm32-and-blinding.md).

## Acknowledgements

- [Baldimtsi, Chalkias, Roy, Sedaghat](https://eprint.iacr.org/2025/1368.pdf) for the paper.
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

## Licence

MIT OR Apache-2.0.
