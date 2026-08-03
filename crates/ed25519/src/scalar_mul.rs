//! Fixed-base scalar multiplication by a constant comb.
//!
//! Because `G` is public, every multiple `d · (2^w)^i · G` is a **circuit constant**.
//! That removes both the doublings and the in-circuit table construction a variable-base
//! algorithm needs: the whole multiplication is `ceil(256/w)` mixed additions.
//!
//! ```text
//! acc = identity
//! for i in 0..n_windows:
//!     acc = acc + mux(digit_i(scalar), TABLE_i)     // TABLE_i entries are constants
//! ```
//!
//! For comparison, PQChain's `scalar_mul_generator` uses 2-bit windows with two doublings
//! per window — 254 doublings and 127 additions. This is 64 additions and no doublings.
//!
//! # Why no special cases
//!
//! `TABLE_i[0]` is the identity, and complete twisted-Edwards addition absorbs it (see
//! [`crate::point`]). The digit-zero case therefore needs no branch, and since the
//! selector is derived from the secret scalar, a branch is exactly what must be avoided.
//! The circuit shape is independent of the scalar by construction.

use binius_circuits::{bignum::BigUint, multiplexer::multi_wire_multiplex};
use binius_frontend::{CircuitBuilder, Wire};
use num_bigint::BigUint as NB;

use crate::{
    consts::N_LIMBS,
    field::Fp,
    point::{Niels, Point},
    host::{Affine, add_affine, basepoint, identity, to_niels},
};

/// Bits consumed per window.
///
/// **6**, chosen by measuring proving time rather than constraint counts — see
/// `report_prove_time_by_window` and `BOUNDS.md`. Ranking by AND count picks 5 and is
/// wrong: `w = 6` has ~9% more AND constraints yet proves ~6% faster, because it drops
/// the padded IMUL size from 2^14 to 2^13 and IMUL dominates proving time.
pub const WINDOW_BITS: usize = 6;

/// Number of windows needed to cover a 256-bit scalar at `w` bits per window.
pub const fn n_windows(w: usize) -> usize {
    256usize.div_ceil(w)
}

/// Host-side tables for every window: table `i` is `[0·B_i, …, (2^w - 1)·B_i]` with
/// `B_i = (2^w)^i · G`, as affine points.
///
/// Entry zero of each table is the identity, which is what makes the digit-zero case
/// free — complete addition absorbs it, so no branch is needed on a secret-derived digit.
///
/// Bases are carried forward across windows rather than recomputed from `G` each time.
/// The naive form is quadratic: window `i` needs `i·w` doublings, so all 64 windows cost
/// ~8,000 where ~250 suffice — and each doubling is two 255-bit modular inversions.
pub fn host_comb_tables(w: usize) -> Vec<Vec<Affine>> {
    let size = 1usize << w;
    let mut base = basepoint();
    let mut tables = Vec::with_capacity(n_windows(w));

    for _ in 0..n_windows(w) {
        let mut table = Vec::with_capacity(size);
        table.push(identity());
        let mut acc = base.clone();
        for _ in 1..size {
            table.push(acc.clone());
            acc = add_affine(&acc, &base);
        }
        tables.push(table);
        // Advance to the next window's base: B_{i+1} = 2^w · B_i.
        for _ in 0..w {
            base = add_affine(&base, &base);
        }
    }
    tables
}


/// All windows' tables as circuit constants in niels form.
fn comb_tables(b: &CircuitBuilder, f: &Fp, w: usize) -> Vec<Vec<Niels>> {
    host_comb_tables(w)
        .iter()
        .map(|table| {
            table
                .iter()
                .map(|pt| {
                    let (ypx, ymx, t2d) = to_niels(pt);
                    Niels {
                        y_plus_x: f.constant(b, &ypx),
                        y_minus_x: f.constant(b, &ymx),
                        t2d: f.constant(b, &t2d),
                    }
                })
                .collect()
        })
        .collect()
}

/// Extract the `i`-th `w`-bit digit of `scalar` as a selector wire.
///
/// Handles digits straddling a limb boundary, which happens whenever `w` does not divide
/// 64 — so for `w` of 3, 5 and 6 but never 4. The `spans` decision is made on
/// compile-time values, so the circuit shape stays independent of the witness.
fn digit(b: &CircuitBuilder, scalar: &BigUint, i: usize, w: usize) -> Wire {
    let lo_bit = i * w;
    let limb_ix = lo_bit / 64;
    let shift = lo_bit % 64;
    let mask = b.add_constant_64((1u64 << w) - 1);

    let lo = b.shr(scalar.limbs[limb_ix], shift as u32);

    // A straddle needs shift > 0, so `64 - shift` is in 1..=63 and the shift is well
    // defined. Past the top limb the scalar's bits are zero, so treating that as
    // non-straddling is correct rather than merely convenient.
    let spans = shift > 0 && shift + w > 64 && limb_ix + 1 < scalar.limbs.len();
    let combined = if spans {
        let hi = b.shl(scalar.limbs[limb_ix + 1], (64 - shift) as u32);
        b.bor(lo, hi)
    } else {
        lo
    };
    b.band(combined, mask)
}

/// `scalar · G` in extended coordinates, using `w`-bit windows.
pub fn mul_basepoint_with_window(
    b: &CircuitBuilder,
    f: &Fp,
    scalar: &BigUint,
    w: usize,
) -> Point {
    assert_eq!(scalar.limbs.len(), N_LIMBS);
    assert!((1..=8).contains(&w), "window must be 1..=8 bits");
    let tables = comb_tables(b, f, w);

    let mut acc = Point::identity(b, f);
    for (i, table) in tables.iter().enumerate() {
        let sel = digit(b, scalar, i, w);
        let groups: Vec<Vec<Wire>> = table
            .iter()
            .map(|n| {
                let mut v = n.y_plus_x.limbs.clone();
                v.extend_from_slice(&n.y_minus_x.limbs);
                v.extend_from_slice(&n.t2d.limbs);
                v
            })
            .collect();
        let refs: Vec<&[Wire]> = groups.iter().map(|g| g.as_slice()).collect();
        let picked = multi_wire_multiplex(b, &refs, sel);

        let chosen = Niels {
            y_plus_x: BigUint { limbs: picked[0..N_LIMBS].to_vec() },
            y_minus_x: BigUint { limbs: picked[N_LIMBS..2 * N_LIMBS].to_vec() },
            t2d: BigUint { limbs: picked[2 * N_LIMBS..3 * N_LIMBS].to_vec() },
        };
        acc = acc.add_niels(b, f, &chosen);
    }
    acc
}

/// `scalar · G` at the chosen window size.
pub fn mul_basepoint(b: &CircuitBuilder, f: &Fp, scalar: &BigUint) -> Point {
    mul_basepoint_with_window(b, f, scalar, WINDOW_BITS)
}

/// Host-side `k · G` via the same comb, for cross-checking the tables.
pub fn host_comb_mul(k: &NB, w: usize) -> Affine {
    let tables = host_comb_tables(w);
    let mut acc = identity();
    for (i, table) in tables.iter().enumerate() {
        let mut d = 0u64;
        for bit in 0..w {
            if k.bit((i * w + bit) as u64) {
                d |= 1 << bit;
            }
        }
        if d != 0 {
            acc = add_affine(&acc, &table[d as usize]);
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use binius_core::verify::verify_constraints;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};

    use super::*;
    use crate::{consts::p_bigint, host::{compress, mul_basepoint as host_mul, on_curve}};

    fn to_limbs(v: &NB) -> [u64; N_LIMBS] {
        let mut out = [0u64; N_LIMBS];
        for (i, d) in v.iter_u64_digits().enumerate() {
            out[i] = d;
        }
        out
    }

    fn clamped(seed_byte: u8) -> ([u8; 32], NB) {
        let mut bytes = [seed_byte; 32];
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        (bytes, NB::from_bytes_le(&bytes))
    }

    /// Table entries must be the multiples they claim to be.
    #[test]
    fn comb_tables_hold_correct_multiples() {
        for w in [3usize, 4, 5] {
            let tables = host_comb_tables(w);
            let table = &tables[0];
            for (d, entry) in table.iter().enumerate() {
                let expected = if d == 0 { identity() } else { host_mul(&NB::from(d as u64)) };
                assert_eq!(*entry, expected, "w={w} window=0 digit={d}");
            }
            // Window 1's base must be (2^w)·G.
            assert_eq!(tables[1][1], host_mul(&NB::from(1u64 << w)), "w={w} window=1 base");
        }
    }

    /// The host comb must agree with plain double-and-add — this validates the digit
    /// decomposition independently of the circuit.
    #[test]
    fn host_comb_matches_double_and_add() {
        for w in [3usize, 4, 5, 6] {
            for seed in [1u8, 7, 0x5A, 0xFF] {
                let (_, k) = clamped(seed);
                assert_eq!(host_comb_mul(&k, w), host_mul(&k), "w={w} seed={seed:#x}");
            }
        }
    }

    /// In-circuit `a·G` must match dalek, at every window size under consideration.
    ///
    /// Running this for each `w` is what catches a straddling-digit bug: `w` of 3, 5 and
    /// 6 cross limb boundaries, `w = 4` never does.
    #[test]
    fn mul_basepoint_matches_dalek_across_windows() {
        let p = p_bigint();
        for w in [3usize, 4, 5, 6] {
            let (bytes, k) = clamped(0x37);
            let expected = ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(bytes);
            let expected_bytes = expected.compress().to_bytes();

            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let s = BigUint::new_witness(&b, N_LIMBS);
            let out = mul_basepoint_with_window(&b, &f, &s, w);

            let cs = b.build();
            let mut w_fill = cs.new_witness_filler();
            s.populate_limbs(&mut w_fill, &to_limbs(&k));
            cs.populate_wire_witness(&mut w_fill).unwrap();
            let read = |v: &BigUint| -> NB {
                let limbs: Vec<u64> = v.limbs.iter().map(|l| w_fill[*l].as_u64()).collect();
                let mut acc = NB::from(0u32);
                for (i, l) in limbs.iter().enumerate() {
                    acc += NB::from(*l) << (64 * i as u32);
                }
                acc % &p
            };
            let (xx, yy, zz) = (read(&out.x), read(&out.y), read(&out.z));
            verify_constraints(cs.constraint_system(), &w_fill.into_value_vec()).unwrap();

            let zinv = zz.modpow(&(&p - NB::from(2u32)), &p);
            let affine = ((xx * &zinv) % &p, (yy * &zinv) % &p);
            assert!(on_curve(&affine), "w={w}: result off curve");
            assert_eq!(compress(&affine), expected_bytes, "w={w}: mismatch vs dalek");
        }
    }

    /// Several distinct scalars at the chosen window, including the range extremes the
    /// clamp guarantees.
    #[test]
    fn mul_basepoint_matches_dalek_across_scalars() {
        let p = p_bigint();
        for seed in [0x00u8, 0x01, 0x37, 0x80, 0xFF] {
            let (bytes, k) = clamped(seed);
            let expected = (ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(bytes))
                .compress()
                .to_bytes();

            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let s = BigUint::new_witness(&b, N_LIMBS);
            let out = mul_basepoint(&b, &f, &s);

            let cs = b.build();
            let mut wf = cs.new_witness_filler();
            s.populate_limbs(&mut wf, &to_limbs(&k));
            cs.populate_wire_witness(&mut wf).unwrap();
            let read = |v: &BigUint| -> NB {
                let mut acc = NB::from(0u32);
                for (i, l) in v.limbs.iter().enumerate() {
                    acc += NB::from(wf[*l].as_u64()) << (64 * i as u32);
                }
                acc % &p
            };
            let (xx, yy, zz) = (read(&out.x), read(&out.y), read(&out.z));
            verify_constraints(cs.constraint_system(), &wf.into_value_vec()).unwrap();
            let zinv = zz.modpow(&(&p - NB::from(2u32)), &p);
            assert_eq!(
                compress(&((xx * &zinv) % &p, (yy * &zinv) % &p)),
                expected,
                "seed={seed:#x}"
            );
        }
    }
}

#[cfg(test)]
mod sweep {
    use binius_frontend::CircuitBuilder;

    use super::*;

    /// Sweep the window size and report the cost of each.
    ///
    /// This is a **design** decision rather than a tuning knob: the window determines the
    /// number of tables, the digit extraction, and every downstream cost figure, so it is
    /// settled here rather than deferred to the benchmark task.
    ///
    /// The tradeoff is not the usual one. Because our tables are *constants*, there is no
    /// in-circuit table-construction cost growing with `w` — the term that caps
    /// secp256k1's variable-base MSM at `MSM_WINDOW = 4`. Here only the multiplexer grows
    /// (as `2^w`) while the additions shrink (as `1/w`), so the optimum may sit higher.
    #[test]
    fn report_window_sweep() {
        println!("\n  w  windows  AND      IMUL     table entries");
        let mut best = (usize::MAX, 0usize);
        for w in [3usize, 4, 5, 6, 7] {
            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let s = BigUint::new_witness(&b, N_LIMBS);
            let _ = mul_basepoint_with_window(&b, &f, &s, w);
            let cs = b.build();
            let sys = cs.constraint_system();
            let (and, imul) = (sys.n_and_constraints(), sys.imul_constraints.len());
            let entries = n_windows(w) * (1 << w);
            println!(
                "  {w}  {:>7}  {and:<8} {imul:<8} {entries}",
                n_windows(w)
            );
            // Rank by AND, the dominant term.
            if and < best.0 {
                best = (and, w);
            }
        }
        println!("\n  lowest AND at w = {}\n", best.1);
    }
}

/// Proving-time sweep — the measurement that actually settles the window size.
///
/// Constraint counts alone cannot decide it. IMUL costs far more per constraint than
/// AND, and both are padded to a power of two, so a window that lowers the AND count can
/// still lose by pushing IMUL into the next power of two (or win by dropping below one).
#[cfg(test)]
mod prove_sweep {
    use binius_frontend::CircuitBuilder;
    use binius_hash::sha256::Sha256HashSuite;
    use binius_prover::{OptimalPackedB128, zk_config::ZKProver};
    use binius_verifier::{
        config::StdChallenger, transcript::ProverTranscript, zk_config::ZKVerifier,
    };

    use super::*;

    type Suite = Sha256HashSuite;

    fn time_window(w: usize) -> (usize, usize, u128, usize) {
        let b = CircuitBuilder::new();
        let f = Fp::new(&b);
        let s = BigUint::new_witness(&b, N_LIMBS);
        let _ = mul_basepoint_with_window(&b, &f, &s, w);
        let cs = b.build();
        let (and, imul) = {
            let sys = cs.constraint_system();
            (sys.n_and_constraints(), sys.imul_constraints.len())
        };

        let mut wf = cs.new_witness_filler();
        let mut bytes = [0x37u8; 32];
        bytes[0] &= 248;
        bytes[31] &= 127;
        bytes[31] |= 64;
        let k = NB::from_bytes_le(&bytes);
        let mut limbs = [0u64; N_LIMBS];
        for (i, d) in k.iter_u64_digits().enumerate() {
            limbs[i] = d;
        }
        s.populate_limbs(&mut wf, &limbs);
        cs.populate_wire_witness(&mut wf).unwrap();
        let witness = wf.into_value_vec();

        let verifier = ZKVerifier::<Suite>::setup(cs.constraint_system().clone(), 1).unwrap();
        let prover = ZKProver::<OptimalPackedB128, Suite>::setup(&verifier).unwrap();

        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();

        // Discard the first run: it measures ~1.6x slow from warm-up.
        let mut size = 0usize;
        let mut best = u128::MAX;
        for run in 0..4 {
            let t = std::time::Instant::now();
            let mut tr = ProverTranscript::new(StdChallenger::default());
            let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::from_seed(seed);
            prover.prove(&witness, &mut rng, &mut tr).unwrap();
            let proof = tr.finalize();
            let el = t.elapsed().as_millis();
            if run > 0 && el < best {
                best = el;
                size = proof.len();
            }
        }
        (and, imul, best, size)
    }

    #[test]
    #[ignore = "slow; run explicitly with --ignored"]
    fn report_prove_time_by_window() {
        println!("\n  w  AND     IMUL    prove(ms)  proof(KiB)");
        for w in [4usize, 5, 6, 7] {
            let (and, imul, ms, size) = time_window(w);
            println!("  {w}  {and:<7} {imul:<7} {ms:<10} {}", size / 1024);
        }
        println!();
    }
}

#[cfg(test)]
mod shape {
    use binius_frontend::CircuitBuilder;

    use super::*;

    /// The constraint system must not depend on the scalar.
    ///
    /// This is the module where that property actually matters. PQChain shipped a bug of
    /// exactly this class — `fix/ed25519-scalar-mul-secret-leak`, where the scalar
    /// multiplication's constraint graph varied with the secret — and fixed it by hand
    /// with oblivious muxes.
    ///
    /// In Binius64 the property is structural rather than earned: `CircuitBuilder` fixes
    /// the graph before any witness exists, so a branch on a secret is not expressible.
    /// That is precisely why it is worth asserting — a regression could only arrive via
    /// someone reintroducing host-side branching on a scalar value, which this catches.
    #[test]
    fn circuit_shape_is_independent_of_the_scalar() {
        let build = || {
            let b = CircuitBuilder::new();
            let f = Fp::new(&b);
            let s = BigUint::new_witness(&b, N_LIMBS);
            let _ = mul_basepoint(&b, &f, &s);
            let cs = b.build();
            let sys = cs.constraint_system();
            (
                sys.n_and_constraints(),
                sys.imul_constraints.len(),
                sys.zero_constraints.len(),
                sys.n_private,
                sys.constants.len(),
            )
        };
        assert_eq!(build(), build(), "circuit shape is not deterministic");
    }

    /// Distinct scalars must give distinct results — a sanity check that the comb is not
    /// accidentally ignoring some of its digits.
    #[test]
    fn distinct_scalars_give_distinct_points() {
        use crate::host::compress;
        let a = (NB::from(1u32) << 200u32) + NB::from(12345u64);
        let b_ = (NB::from(1u32) << 200u32) + NB::from(12346u64);
        assert_ne!(
            compress(&host_comb_mul(&a, WINDOW_BITS)),
            compress(&host_comb_mul(&b_, WINDOW_BITS))
        );
        // And a difference confined to the top window.
        let c = NB::from(1u32) << 250u32;
        let d = NB::from(3u32) << 250u32;
        assert_ne!(
            compress(&host_comb_mul(&c, WINDOW_BITS)),
            compress(&host_comb_mul(&d, WINDOW_BITS))
        );
    }
}
