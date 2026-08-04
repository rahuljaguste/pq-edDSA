# Security

## This is not production software

An unaudited research proof of concept, built to compare proving systems on one
relation. Do not use it to secure anything of value.

Two specific things you should know before trusting a proof from this code:

- **96-bit classical soundness**, not the ~128 you should want. Upstream Binius64 fixes
  `SECURITY_BITS = 96` and exposes no override, so this is not a configuration choice we
  made: it is the ceiling available. See [Soundness](README.md#soundness).
- **The zero-knowledge property is unaudited.** Binius64's blinding parameter
  `n_dummy_constraints` is set to `2` upstream with a `// TODO` where its derivation
  should be. We measured that raising it is free up to 2,133 for this circuit, which is
  not the same as establishing that 2 is insufficient or 2,048 sufficient. Zero-knowledge
  is a simulation property and a real answer needs a simulator construction. See
  [`docs/notes/zk-blinding-parameter.md`](docs/notes/zk-blinding-parameter.md).

The witness here is an Ed25519 private key. If the ZK property does not hold as assumed,
that key is what leaks. Use throwaway keys.

## Reporting

Open a GitHub issue. Nothing here guards live assets, so there is no embargo to respect
and a public issue is more useful than a private one.

If you find a soundness bug; a way to produce a proof for a statement you cannot
satisfy, that is the most valuable thing you could report, and it is worth saying so
explicitly: the test suite is built around negative tests precisely because a circuit that
is under-constrained passes every positive test.

## What has and has not been checked

Checked:

- Differential agreement with `curve25519-dalek` across every comb window size, and the
  RFC 8032 test vectors.
- Negative tests are mutation-verified: each is confirmed to fail when the assertion it
  guards is deleted. This caught one assertion with no deployed coverage at all.
- Non-canonical field representatives drawn from the whole of `[0, 2p)`, including the
  upper half an adversarial witness can supply.
- Circuit shape does not depend on the witness.

Not checked:

- No external audit of any kind.
- No formal verification, and no proof that the constraint system is a faithful encoding
  of the relation. The argument for that is prose in
  [`crates/ed25519/BOUNDS.md`](crates/ed25519/BOUNDS.md), meant to be checked rather than
  taken on trust.
- Side channels. Proving is not constant-time and was never intended to be.
- The browser demo is tested on Chrome only.
