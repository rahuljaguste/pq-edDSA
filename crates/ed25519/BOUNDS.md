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
