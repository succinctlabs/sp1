#![allow(clippy::disallowed_types)]
pub use p3_koala_bear::*;
mod koala_bear_poseidon2;
pub use koala_bear_poseidon2::*;

#[cfg(test)]
mod tests {
    use p3_koala_bear::{
        DiffusionMatrixKoalaBear, KoalaBear, MONTY_INVERSE,
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY,
    };
    use slop_algebra::{AbstractField, Field, PrimeField32};
    use slop_symmetric::Permutation;

    const WIDTH: usize = 16;

    /// The prime, as the field itself reports it.
    fn prime() -> u64 {
        u64::from(KoalaBear::ORDER_U32)
    }

    /// The Montgomery radix `R`, derived rather than written down: the shift trick depends on what it
    /// is, so it is checked in [`the_radix_is_a_power_of_two_and_monty_inverse_undoes_it`].
    fn montgomery_radix() -> KoalaBear {
        let mut r = KoalaBear::two();
        for _ in 0..5 {
            r = r.square();
        }
        r
    }

    /// The word actually stored for `x`. `KoalaBear::value` is `pub(crate)` upstream; this reaches the
    /// same number without it.
    fn montgomery_word(x: KoalaBear) -> u32 {
        (x * montgomery_radix()).as_canonical_u32()
    }

    fn internal_diagonal() -> [KoalaBear; WIDTH] {
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY
    }

    /// The shift amounts, derived from the diagonal. Panics unless every entry is a power of two, which
    /// is the precondition the whole optimisation rests on.
    fn internal_shifts() -> [u32; WIDTH - 1] {
        core::array::from_fn(|i| {
            let entry = internal_diagonal()[i + 1].as_canonical_u32();
            assert!(
                entry.is_power_of_two(),
                "diagonal entry {} is {entry}, which is not a power of two, so it cannot be \
                 applied as a shift",
                i + 1
            );
            entry.trailing_zeros()
        })
    }

    /// Probe states, including lane zero at zero, where the CUDA path's `v0 == 0 ? 0 : MOD - v0`
    /// takes its other branch, and lane zero at its largest, the worst case for its subtraction.
    fn probe_states() -> Vec<[KoalaBear; WIDTH]> {
        let mut states = vec![
            [KoalaBear::zero(); WIDTH],
            {
                let mut s = [KoalaBear::one(); WIDTH];
                s[0] = KoalaBear::zero();
                s
            },
            {
                let mut s = [KoalaBear::zero(); WIDTH];
                s[0] = KoalaBear::zero() - KoalaBear::one();
                s
            },
        ];

        let mut x = KoalaBear::from_canonical_u32(7);
        let mut walk = Vec::with_capacity(WIDTH * 4);
        for _ in 0..(WIDTH * 4) {
            x = x.cube() + KoalaBear::from_canonical_u32(3);
            walk.push(x);
        }
        states.extend(walk.chunks_exact(WIDTH).map(|c| {
            let mut s = [KoalaBear::zero(); WIDTH];
            s.copy_from_slice(c);
            s
        }));
        states
    }

    /// Pins `R = 2^32` and `MONTY_INVERSE` as the scalar undoing it.
    ///
    /// Upstream writes `MONTY_INVERSE` as `KoalaBear { value: 1 }`, which names `R^-1` only if you
    /// already know the convention, so it is pinned from the outside here.
    #[test]
    fn the_radix_is_a_power_of_two_and_monty_inverse_undoes_it() {
        let radix = montgomery_radix();
        assert_eq!(
            u64::from(radix.as_canonical_u32()),
            (1u64 << 32) % prime(),
            "the Montgomery radix is not 2^32, so shifting a stored word is not scaling it"
        );
        assert_eq!(montgomery_word(KoalaBear::one()), radix.as_canonical_u32());

        assert_eq!(montgomery_word(MONTY_INVERSE), 1, "MONTY_INVERSE is not the element R^-1");
        assert_eq!(MONTY_INVERSE * radix, KoalaBear::one());
        assert_eq!(
            MONTY_INVERSE.as_canonical_u32(),
            1_057_030_144,
            "the literal `kb31_t(1057030144)` in poseidon2_kb31_16.cuh no longer names R^-1"
        );
    }

    /// Pins the diagonal as shifts, and lane zero as the `-2` that is not one.
    ///
    /// The derived shifts are also the `SH` table hardcoded in `poseidon2_kb31_16.cuh`. That table is
    /// live on the GPU side and the drift guard checks neither it nor `MAT_INTERNAL_DIAG_M1`.
    #[test]
    fn the_internal_diagonal_is_made_of_shifts() {
        assert_eq!(
            internal_diagonal()[0],
            KoalaBear::zero() - KoalaBear::two(),
            "lane zero is no longer -2, so the non-negative rewrite it needs may not apply"
        );
        assert_eq!(
            internal_shifts(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15],
            "the derived shifts no longer match the `SH` table in poseidon2_kb31_16.cuh"
        );
    }

    /// Pins the internal layer as `R^-1 * (J + diag(D))`, which is not `J + diag(D)`.
    ///
    /// Stored words carry a factor of `R` into the sum and the shifts, and REDC divides by `R` on the
    /// way out. Rather than spend a multiply putting it back, the `R^-1` is defined into the layer;
    /// scaling an internal matrix by a nonzero constant leaves a valid Poseidon2 instance. Read
    /// backwards this looks like an off-by-`R` bug, so both halves are asserted.
    #[test]
    fn the_internal_layer_has_r_inverse_folded_into_it() {
        let diagonal = internal_diagonal();
        let r_inverse = montgomery_radix().inverse();

        for state in probe_states() {
            let sum = state.iter().fold(KoalaBear::zero(), |acc, x| acc + *x);
            let textbook: [KoalaBear; WIDTH] =
                core::array::from_fn(|i| sum + diagonal[i] * state[i]);
            let scaled: [KoalaBear; WIDTH] = core::array::from_fn(|i| textbook[i] * r_inverse);

            let mut got = state;
            DiffusionMatrixKoalaBear.permute_mut(&mut got);

            assert_eq!(
                got, scaled,
                "the internal layer is not `R^-1 * (J + diag(D))`, so the reduction is no longer \
                 paying for itself"
            );
            if textbook.iter().any(|x| *x != KoalaBear::zero()) {
                assert_ne!(
                    got, textbook,
                    "the internal layer became the textbook one, which means someone put the R \
                     back and the two sides now disagree"
                );
            }
        }
    }

    /// Pins the REDC precondition against the live width and shifts, rather than quoting the bound.
    /// Widening the state or adding a larger shift fails here.
    #[test]
    fn the_redc_precondition_has_room_for_the_widest_shift() {
        let p = u128::from(prime());
        let max_shift = internal_shifts().iter().copied().max().expect("the diagonal is non-empty");

        let sum_bound = WIDTH as u128 * p;
        let shifted_bound = p << max_shift;
        let largest_input = sum_bound + shifted_bound;
        let redc_limit = p << 32;

        assert!(
            largest_input < redc_limit,
            "an internal-layer input can reach {largest_input}, at or past the REDC limit of \
             {redc_limit}"
        );
    }

    /// Pins the non-negative rewrite lane zero needs.
    ///
    /// `sum - 2 * v0` is computed in unsigned 64-bit and goes negative when the other lanes are small,
    /// wrapping to something REDC will happily reduce to the wrong answer. `(sum - v0) + (p - v0)`
    /// cannot: `v0` is one of the terms of `sum`, and `p - v0` stands in for `-v0`.
    #[test]
    fn lane_zero_avoids_the_unsigned_underflow() {
        let p = prime();
        let mut underflows_seen = 0;

        for state in probe_states() {
            let words: Vec<u64> = state.iter().map(|x| u64::from(montgomery_word(*x))).collect();
            let v0 = words[0];
            let part_sum: u64 = words[1..].iter().sum();
            let full_sum = part_sum + v0;

            let naive = i128::from(full_sum) - 2 * i128::from(v0);
            if naive < 0 {
                underflows_seen += 1;
                assert!(
                    full_sum.checked_sub(2 * v0).is_none(),
                    "the naive form was expected to underflow u64 here"
                );
            }

            let rewritten = part_sum + (p - v0);
            assert_eq!(
                i128::from(rewritten).rem_euclid(i128::from(p)),
                naive.rem_euclid(i128::from(p)),
                "the non-negative rewrite is not congruent to `sum - 2 * v0`"
            );
            assert!(u128::from(rewritten) < u128::from(p) << 32, "the rewrite left the REDC bound");
        }

        assert!(
            underflows_seen > 0,
            "no probe state reached the underflow, so this test proved nothing"
        );
    }
}
