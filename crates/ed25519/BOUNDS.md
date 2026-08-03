# Bounds argument for `F_p` modulo `2p`

Ed25519's coordinate field is `F_p` with `p = 2^255 - 19`. This crate performs circuit
arithmetic modulo `2p = 2^256 - 38` instead. This document is the argument that doing so is
correct, in a form an auditor can check without reading the circuit code.

The load-bearing claim is that a mistake here is **silent** — it produces wrong values, not
a crash — so the reasoning is written out rather than left implicit.

## Why not `p` directly

`PseudoMersenneModReduce::new` asserts (`crates/circuits/src/bignum/reduce.rs:117`):

```rust
assert!(modulus_po2.is_multiple_of(Word::BITS));
```

because it splits the dividend with `split_at_limbs`, which can only cut on a 64-bit
boundary. `p = 2^255 - 19` has `modulus_po2 = 255`, not a multiple of 64, so it is
rejected.

Rewriting `p` as `2^256 - (2^255 + 19)` satisfies the alignment assert but destroys the
point: the subtrahend `2^255 + 19` is four limbs long, and pseudo-Mersenne reduction is
only cheap when the subtrahend is short.

## Why `2p` works

```
2p = 2·(2^255 - 19) = 2^256 - 38
```

which is pseudo-Mersenne with `modulus_po2 = 256` and a **one-limb** subtrahend `38`. This
is the same shape as secp256k1's `2^256 - 2^32 - 977`, which the library already supports.

Preconditions, all checked in `consts.rs` tests:

| assert | site | holds |
|---|---|---|
| `2^modulus_po2 > modulus_subtrahend` | `prime_field.rs:30` | `2^256 > 38` ✓ |
| `subtrahend.limbs.len()·64 <= modulus_po2` | `reduce.rs:118` | `1·64 ≤ 256` ✓ |
| `modulus_po2 % Word::BITS == 0` | `reduce.rs:117` | `256 % 64 == 0` ✓ |
| `remainder.limbs.len()·64 <= modulus_po2` | `reduce.rs:119` | `4·64 ≤ 256` ✓ |

## The representation invariant

**Every field element is a representative in `[0, 2p)`.** Each residue class mod `p`
therefore has exactly two representatives, `x` and `x + p`.

This is maintained by the library, not assumed of callers:

- `mul` and `square` route through `reduce_product`, which asserts
  `remainder < modulus` directly (`prime_field.rs:113`) before applying the reduction
  constraint. Output is in `[0, 2p)` by construction.
- `mul` additionally documents "Both fe1 and fe2 may be greater or equal to modulus"
  (`prime_field.rs:99`), so it is more permissive than we require.
- `add` takes two values below the modulus, so the sum is below `2·(2p)` and the overflow
  past the top limb is a single carry bit. It conditionally subtracts the modulus, landing
  back in `[0, 2p)`.
- `sub(x, y)` is implemented upstream as `add(x, modulus - y)` (`prime_field.rs:81-87`),
  which lands in `[0, 2p)` as well — but see the caveat below.

### Caveat: `sub` momentarily violates `add`'s precondition

`add` documents that "Both inputs are reduced, so the sum is below `2 * modulus`". When
`y = 0`, `sub` passes `modulus - 0 = modulus` as `add`'s second operand, which is **not**
below the modulus. The result is still correct, but for a subtler reason than the stated
precondition:

- `sum = x + 2p` where `x < 2p`, so `sum < 4p` and the overflow past `2^256` is still a
  single bit — the carry-width assumption survives.
- That carry is set exactly when `x >= 38`, since `2p = 2^256 - 38`.
- The final step is a *wrapping* subtraction, and upstream's own comment covers this case:
  "with one [carry] it borrows out by exactly the `2^(64 * l)` the carry stands for."

So correctness rests on the carry and the wrap cancelling, not on the documented
precondition. That is a fragile-looking argument to leave implicit, so
`sub_edge_cases_around_zero_and_modulus` in `field.rs` pins it with explicit cases on both
sides of the `x = 38` boundary — values a random property test would essentially never
generate.

### Product bound

Inputs are below `2p < 2^256`, so a product is below `4p^2 < 2^512` and occupies at most
eight 64-bit limbs — exactly what `textbook_mul` on 4-limb inputs produces, and what the
8-limb reduction consumes. The quotient is below `2^512 / 2^256 = 2^256`, four limbs, the
same shape as the secp256k1 case.

## Where canonicalisation is required

Canonicalisation is needed exactly where a value's **bits** are read, rather than only its
residue class. Reading bits of a non-canonical representative gives the wrong answer even
though the residue is right.

The complete list for this crate:

1. **Comparison against the public key.** `pk` is a specific 32-byte encoding, so the
   y-coordinate must be canonical before its limbs are compared.
2. **x-parity for point compression.** RFC 8032 puts the low bit of `x` in bit 255 of the
   encoding. `x` and `x + p` have *different* low bits, since `p` is odd.
3. **Equality between field elements** (`assert_congruent`). Plain limb equality is wrong:
   `x` and `x + p` are the same residue with different bit patterns.
4. **Zero tests** (`is_zero_mod_p`). Both `0` and `p` represent zero.

**Nowhere else.** In particular, complete twisted-Edwards addition contains no equality
tests and no branches — that is what "complete" means — so the scalar multiplication inner
loop needs no canonicalisation at all. This is why the redundancy costs almost nothing:
roughly two canonicalisations in the whole circuit, at ~10–20 AND each.

## What must never be called

`PseudoMersennePrimeField::inverse` (`prime_field.rs:131`) and `::div` (`prime_field.rs:166`)
both document prime-modulus formulas — they compute `x^(m-2) mod m`, which inverts only
when `m` is prime. `2p` is not prime. Neither is re-exposed through `Fp`, and neither is
used: the single inversion the circuit needs (`Z^-1` for extended→affine) is done as a hint
plus a multiplication check, which is the better construction anyway.

## Test coverage of this argument

`field.rs` property tests draw representatives uniformly from all of `[0, 2p)` —
**deliberately including the upper half** that a naive implementation never produces during
testing but an adversarial witness can supply — and assert that `add`, `sub`, and `mul`
agree with a `num-bigint` reference computed mod `p`.

The suite was mutation-tested: disabling `canonicalize` fails 5 of the 12 tests. A suite
that cannot fail proves nothing, so this check should be repeated whenever the module
changes.

---

# Measured costs

Recorded as they are established, so later projections rest on measurement rather than
estimate. Reproduce with `cargo test -p ed25519-binius --release -- --nocapture`.

| operation | AND | IMUL | source |
|---|---|---|---|
| `Fp::mul` / `Fp::square` | ~118 | 24 | derived from below |
| `Point::add_niels` (7 field mults) | **827** | **168** | `point::cost::report_add_niels_cost` |
| × 64 comb windows | 52,928 | 10,752 | |

The per-addition figure is a *marginal* cost — measured as the difference between chains of
one and two additions, so fixed setup cancels.

## Against the design spec's projection

The spec projected ~53,800 AND and ~7,200 IMUL for the 64 additions.

- **AND: 52,928 measured vs 53,800 projected — within 2%.**
- **IMUL: 10,752 measured vs 7,200 projected — 49% over.**

The IMUL gap comes from assuming 16 IMUL per field multiplication (a 4×4 `textbook_mul`).
The true figure is 24: the product costs 16, and the pseudo-Mersenne reduction adds a
further 8 for `quotient × subtrahend` and the associated range machinery.

Consequence for the end-to-end projection: AND lands *below* the spec's estimate and IMUL
*above* it. Since `IntMul` was roughly half of `ec_msm`'s proving time, the two partly
offset and the ~60–70 ms estimate stands, but it should be re-derived from a full-circuit
measurement in Task 4 rather than carried forward on this basis.

## Comb window size

Settled by measurement in Task 4. Reproduce with:

```bash
cargo test -p ed25519-binius --release report_window_sweep -- --nocapture
cargo test -p ed25519-binius --release report_prove_time_by_window -- --ignored --nocapture
```

Scalar multiplication only, M1 Pro, ZK path, `log_inv_rate = 1`, first run discarded:

| w | windows | AND | pads to | IMUL | pads to | prove (ms) | table entries |
|---|---|---|---|---|---|---|---|
| 3 | 86 | 78,434 | 2^17 | 14,436 | 2^14 | — | 688 |
| 4 | 64 | 64,512 | 2^16 | 10,740 | 2^14 | 126 | 1,024 |
| 5 | 52 | **62,403** | 2^16 | 8,724 | 2^14 | 129 | 1,664 |
| **6** | **43** | 68,114 | 2^17 | 7,212 | **2^13** | **118** | 2,752 |
| 7 | 37 | 87,027 | 2^17 | **6,204** | 2^13 | 129 | 4,736 |

**Chosen: `w = 6`.**

### Why constraint counts pick the wrong window

Ranking by AND count selects `w = 5`. That is wrong. `w = 6` carries ~9% *more* AND
constraints and still proves ~6% faster, because:

- IMUL costs far more per constraint than AND. On the `ec_msm` reference, the IntMul phase
  was ~50% of proving time for 15,236 constraints while the BitAnd phase was ~11% for
  110,426 — roughly a 30× per-constraint difference.
- Both counts are padded to a power of two, so what matters is which side of a boundary
  you land on, not the raw count. `w = 6` is the largest window whose IMUL count fits in
  2^13.

`w = 7` pushes IMUL lower still but loses: its AND count jumps to 87,027, and it gains
nothing from the padding since it shares 2^13 with `w = 6`.

### Caveat

The spread between the best and worst is only ~10% (118–131 ms), which is not a wide
margin. A machine with different SIMD width or memory behaviour could plausibly reorder
`w = 4`, `5` and `7`; `w = 6`'s advantage is the more robust part of the result because it
comes from a padding boundary rather than a constant factor. Re-measure before treating
this as settled on other hardware.

### Effect in the full circuit

The scalar multiplication is not the whole circuit — two SHA-512 blocks and compression
add roughly 4,000 more AND. That pushes `w = 4` and `w = 5` from 2^16 into 2^17, where
`w = 6` already sits, so the AND-count advantage those windows held disappears while
`w = 6` keeps its IMUL padding advantage. The choice should therefore hold or improve at
full circuit size, but Task 6 must re-measure rather than assume it.

## Affine conversion and compression

| step | AND | IMUL |
|---|---|---|
| comb scalar multiplication (w=6) | 68,114 | 7,212 |
| + affine conversion and compression | **+297** | **+48** |
| **total** | **68,411** | **7,260** |

The spec projected ~400 AND and ~32 IMUL for this step; measured 297 and 48. Two field
multiplications at 24 IMUL each accounts for the 48.

Avoiding the in-circuit inversion is what makes this cheap. A modular exponentiation would
have cost hundreds of multiplications; the hint-plus-check costs two. The constraint that
began as a workaround for the composite modulus — `PseudoMersennePrimeField::inverse`
being unusable mod `2p` — is simply the better construction.

### The canonicality assertion is load-bearing, not defensive

`x_aff < p` and `y_aff < p` are the only things stopping a prover from supplying `x + p`.
That value satisfies both residue checks, since it is the same residue — but it has the
opposite low bit, and the low bit of `x` is exactly what RFC 8032 compression encodes as
the sign. Without the assertion a prover could choose the compressed public key's sign bit
freely.

Nothing in the honest test suite would notice if the assertion were deleted, because the
honest hint never produces a non-canonical value. `canonicality_assertion_rejects_the_other_representative`
therefore installs a deliberately malicious hint and checks both directions: without the
assertion the bad value is accepted (confirming the hole is real), with it the constraint
system rejects.

## Does Rayon help?

**No — ~1% at this circuit size, within noise.** Measured on the full `R_det` circuit,
M1 Pro (6 performance + 2 efficiency cores), direct test binary, three runs each:

| build | run 1 | run 2 | run 3 |
|---|---|---|---|
| single-threaded | 78.9 ms | 83.6 ms | 81.4 ms |
| `--features rayon` | 79.9 ms | 79.7 ms | 79.8 ms |

Rayon *is* wired correctly — the `rayon` crate enters the dependency graph only when the
feature is on, confirmed with `cargo tree`. It simply has nothing to work with: at 70,252
AND and 7,260 IMUL this circuit is small by binius64's standards, and the prover is
latency-bound rather than throughput-bound. Thread coordination cancels the gains.

The one visible effect is **lower variance** (77–87 ms against 76–106 ms), consistent with
rayon being active but not improving throughput.

Not established here: whether rayon pays off at larger circuit sizes. binius64's own
published benchmarks are on signature-aggregation workloads orders of magnitude bigger,
where it presumably does. The claim above is scoped to this circuit.

### Benchmark methodology error, corrected

Earlier figures of 119.6 ms proving were taken while other `cargo` processes were running.
Run on a quiescent machine the same code measures **80.0 ms**. Benchmarks must run from
the test binary directly on an otherwise idle machine, not under `cargo test` alongside
other work — a 50% error is more than enough to invalidate a comparison.

## Merkle hash suite: SHA-256 or Blake3?

**SHA-256. Blake3 is ~8% slower here.** Measured back-to-back in one process, then with
the order reversed as a control:

| order | Blake3 | SHA-256 |
|---|---|---|
| SHA-256 first | 131.1 ms | 119.8 ms |
| Blake3 first | 130.3 ms | 120.3 ms |

Both orders agree, so this is the suites rather than a warm-up artefact. Proof size is
identical (527,584 bytes) and verification is within noise, so there is no compensating
gain. Soundness is unchanged: both produce 256-bit digests, so the Merkle and
Fiat-Shamir birthday bounds stay at ~2^-128.

Likely cause: Apple silicon has SHA-256 instructions, and `sha256_x4` in `binius-hash`
exists to use them. Blake3's advantage on general hardware does not survive against a
hardware-accelerated competitor. **This conclusion is therefore hardware-specific** and
should be re-measured on x86-64 without SHA-NI before being treated as general.

Note the *in-circuit* hash is not a choice: RFC 8032 mandates SHA-512 for `sk = H(seed)`,
so the blake2b and blake3 gadgets in `binius-circuits` cannot substitute without changing
the relation being proved. binius-hash also offers no blake2b Merkle suite — the options
are SHA-256 and Blake3 only.

## Benchmarking requires an idle machine — absolute figures are provisional

The same binary measured **80 ms** and **121 ms** for proving on the same machine on the
same day. The difference is system load: the second was taken at load average 8.15 on an
8-core host.

**No absolute timing in this repository should be published until it is re-measured on a
quiescent machine.** The relative results above are sound — Blake3 against SHA-256, and
rayon against single-threaded, were each taken back-to-back under identical conditions,
and the Blake3 comparison additionally survives order reversal. Ratios against PQChain do
not have that protection and must be re-derived.

## Signed-digit comb recoding

Digits are recoded in-circuit to `[-2^(w-1), 2^(w-1)-1]`, so each table holds `|d|` only:
`2^(w-1)+1` entries instead of `2^w` — 33 rather than 64 at `w = 6`. Negative digits reuse
the entry with a conditional negation, which in niels form `(y+x, y-x, 2dxy)` is a swap of
the first two coordinates and a negation of the third.

One extra window absorbs the recoding's final carry, so 44 windows rather than 43.

| signal | before | after | change |
|---|---|---|---|
| AND | 70,252 | **57,314** | −18%, **2^17 → 2^16 padded** |
| IMUL | 7,260 | 7,428 | +2% (the extra window), tier 2^13 unchanged |
| private wires | 82,311 | 69,598 | −15% |
| proof size | 527,584 | 527,552 | −32 bytes |
| prove time | ~119 ms | ~113 ms | ~5% |

### The padding-tier flip is real; the payoff is modest

Halving the padded AND stream sounds decisive and is not, because **AND was never the
bottleneck**. On the `ec_msm` reference profile the BitAnd phase was ~11% of proving time
against IntMul's ~50%. Halving an 11% term caps the win near 5%, which is what the
measurement shows. Proof size is essentially unchanged.

Worth stating plainly because the tier crossing invites a larger expectation than the
profile supports. The optimisation is still worth keeping — strictly smaller circuit,
fewer wires, no correctness cost, all differential tests still passing against
`curve25519-dalek` at `w = 3, 4, 5, 6` — but the lever that matters for proving time is
IMUL, not AND.

### Why the recoding is in-circuit

It cannot be done host-side and supplied as a hint. The digits must be a verified function
of the committed scalar, and constraining a hinted recomposition
(`Σ dᵢ·(2^w)^i == scalar`) would cost a full-width bignum computation — more than the
multiplexer saves. In-circuit it is word arithmetic on values below `2^w`: an add, a
comparison, a conditional subtract and a select per window, a few constraints each.

## Can the IMUL cost be reduced?

Largely no, and the reason is the padding tier rather than the arithmetic.

**Where it goes.** Measured by `field::imul_breakdown::report_imul_breakdown`:

```
4x4 textbook product only : 16 IMUL
full Fp::mul (with reduce): 24 IMUL
=> modular reduction costs:  8 IMUL
```

310 field multiplications (44 windows × 7, plus 2 for compression) × 24 = 7,440,
matching the measured 7,428.

**Every available lever lands in the same tier.** IMUL pads to a power of two, and at 7,428
we sit at 91% of 2^13 = 8,192. Nothing short of dropping below 2^12 = 4,096 changes the
padded size:

| lever | IMUL | tier |
|---|---|---|
| current | 7,440 | 2^13 |
| Karatsuba product (12 + 8) | 6,200 | 2^13 |
| `w = 7`, 38 windows | 6,432 | 2^13 |
| *free* reduction (16 + 0), hypothetical | 4,960 | 2^13 |
| `w = 11`, 24 windows | 4,080 | 2^12 |

Even an impossible zero-cost modular reduction stays in 2^13. The only configuration that
drops a tier is `w = 11`, where the table is `2^10 + 1 = 1,025` entries and the multiplexer
cost is prohibitive — it would trade a 2^13→2^12 IMUL saving for an AND increase far larger
than the 2^16→2^17 crossing it would also cause.

**Specific options assessed and rejected:**

- **Karatsuba at 4 limbs.** `optimal_mul` picks textbook below `KARATSUBA_LIMBS_THRESHOLD =
  8` limbs. Calling `karatsuba_mul` directly would give 12 IMUL instead of 16 — but at the
  cost of extra additions and carries in AND, for no tier change. Upstream's threshold looks
  right even under our AND-cheap cost model.
- **Lazy reduction** (defer reduction across the formula). Does not apply here: in the HWCD
  mixed addition the three initial products feed additions that immediately feed four more
  products, so unreduced 8-limb intermediates would make those products 8×8 = 64 IMUL —
  far worse than the 8 IMUL saved per reduction.
- **Fewer multiplications per addition.** 7M is optimal for extended-coordinate mixed
  addition with `a = -1`; there is no 6M variant.
- **Skipping the final `T`.** `T` is only consumed by the next addition, so the last window
  could omit it — one multiplication out of 310, ~0.3%.

**Conclusion.** IMUL is at its practical floor for this construction. The window sweep
already picks the best point (`w = 6`), and it does so *because* of the tier: `w = 7` has
14% fewer IMUL, lands in the same tier, and proves slower on the AND increase alone.

Reducing proving time further would need a change of approach rather than a change of
parameter — a smaller field representation, a different reduction strategy inside
binius64's `bignum`, or a proof system whose multiply constraint is cheaper relative to its
AND constraint.
