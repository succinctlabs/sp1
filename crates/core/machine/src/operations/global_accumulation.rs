use crate::operations::GlobalInteractionOperation;
use p3_air::AirBuilder;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::Field;
use p3_field::PrimeField32;
use sp1_derive::AlignedBorrow;
use sp1_stark::air::BaseAirBuilder;
use sp1_stark::air::SepticExtensionAirBuilder;
use sp1_stark::septic_curve::SepticCurveComplete;
use sp1_stark::{
    air::SP1AirBuilder,
    septic_curve::SepticCurve,
    septic_digest::SepticDigest,
    septic_extension::{SepticBlock, SepticExtension},
};

/// A set of columns needed to compute the global interaction elliptic curve digest.
/// It is critical that this struct is at the end of the main trace, as the permutation constraints will be dependent on this fact.
/// It is also critical the the cumulative sum is at the end of this struct, for the same reason.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalAccumulationOperation<T, const N: usize> {
    pub initial_digest: [SepticBlock<T>; 2],
    pub sum_checker: [SepticBlock<T>; N],
    pub cumulative_sum: [[SepticBlock<T>; 2]; N],
}

impl<T: Default, const N: usize> Default for GlobalAccumulationOperation<T, N> {
    fn default() -> Self {
        Self {
            initial_digest: core::array::from_fn(|_| SepticBlock::<T>::default()),
            sum_checker: core::array::from_fn(|_| SepticBlock::<T>::default()),
            cumulative_sum: core::array::from_fn(|_| {
                [SepticBlock::<T>::default(), SepticBlock::<T>::default()]
            }),
        }
    }
}

impl<F: PrimeField32, const N: usize> GlobalAccumulationOperation<F, N> {
    pub fn populate(
        &mut self,
        initial_digest: &mut SepticCurve<F>,
        global_interaction_cols: [GlobalInteractionOperation<F>; N],
        is_real: [F; N],
    ) {
        self.initial_digest[0] = SepticBlock::from(initial_digest.x.0);
        self.initial_digest[1] = SepticBlock::from(initial_digest.y.0);

        for i in 0..N {
            let point_cur = SepticCurve {
                x: SepticExtension(global_interaction_cols[i].x_coordinate.0),
                y: SepticExtension(global_interaction_cols[i].y_coordinate.0),
            };
            assert!(is_real[i] == F::one() || is_real[i] == F::zero());
            let sum_point = if is_real[i] == F::one() {
                point_cur.add_incomplete(*initial_digest)
            } else {
                *initial_digest
            };
            let sum_checker = if is_real[i] == F::one() {
                SepticExtension::<F>::zero()
            } else {
                SepticCurve::<F>::sum_checker_x(*initial_digest, point_cur, sum_point)
            };
            self.sum_checker[i] = SepticBlock::from(sum_checker.0);
            self.cumulative_sum[i][0] = SepticBlock::from(sum_point.x.0);
            self.cumulative_sum[i][1] = SepticBlock::from(sum_point.y.0);
            *initial_digest = sum_point;
        }
    }

    pub fn populate_dummy(
        &mut self,
        final_digest: SepticCurve<F>,
        final_sum_checker: SepticExtension<F>,
    ) {
        self.initial_digest[0] = SepticBlock::from(final_digest.x.0);
        self.initial_digest[1] = SepticBlock::from(final_digest.y.0);
        for i in 0..N {
            self.sum_checker[i] = SepticBlock::from(final_sum_checker.0);
            self.cumulative_sum[i][0] = SepticBlock::from(final_digest.x.0);
            self.cumulative_sum[i][1] = SepticBlock::from(final_digest.y.0);
        }
    }

    pub fn populate_real(
        &mut self,
        sums: &[SepticCurveComplete<F>],
        final_digest: SepticCurve<F>,
        final_sum_checker: SepticExtension<F>,
    ) {
        let len = sums.len();
        let sums = sums.iter().map(|complete_point| complete_point.point()).collect::<Vec<_>>();
        self.initial_digest[0] = SepticBlock::from(sums[0].x.0);
        self.initial_digest[1] = SepticBlock::from(sums[0].y.0);
        for i in 0..N {
            if len >= i + 2 {
                self.sum_checker[i] = SepticBlock([F::zero(); 7]);
                self.cumulative_sum[i][0] = SepticBlock::from(sums[i + 1].x.0);
                self.cumulative_sum[i][1] = SepticBlock::from(sums[i + 1].y.0);
            } else {
                self.sum_checker[i] = SepticBlock::from(final_sum_checker.0);
                self.cumulative_sum[i][0] = SepticBlock::from(final_digest.x.0);
                self.cumulative_sum[i][1] = SepticBlock::from(final_digest.y.0);
            }
        }
    }
}

impl<F: Field, const N: usize> GlobalAccumulationOperation<F, N> {
    pub fn eval_accumulation<AB: SP1AirBuilder>(
        builder: &mut AB,
        global_interaction_cols: [GlobalInteractionOperation<AB::Var>; N],
        local_is_real: [AB::Var; N],
        next_is_real: [AB::Var; N],
        local_accumulation: GlobalAccumulationOperation<AB::Var, N>,
        next_accumulation: GlobalAccumulationOperation<AB::Var, N>,
    ) {
        // First, constrain the control flow regarding `is_real`.
        // Constrain that all `is_real` values are boolean.
        for i in 0..N {
            builder.assert_bool(local_is_real[i]);
        }

        // Constrain that `is_real = 0` implies the next `is_real` values are all zero.
        for i in 0..N - 1 {
            // `is_real[i] == 0` implies `is_real[i + 1] == 0`.
            builder.when_not(local_is_real[i]).assert_zero(local_is_real[i + 1]);
        }

        // Constrain that `is_real[N - 1] == 0` implies `next.is_real[0] == 0`
        builder.when_transition().when_not(local_is_real[N - 1]).assert_zero(next_is_real[0]);

        // Next, constrain the accumulation.
        let initial_digest = SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.initial_digest[0][i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.initial_digest[1][i].into()
            }),
        };

        let ith_cumulative_sum = |idx: usize| SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.cumulative_sum[idx][0].0[i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.cumulative_sum[idx][1].0[i].into()
            }),
        };

        let ith_point_to_add = |idx: usize| SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                global_interaction_cols[idx].x_coordinate.0[i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                global_interaction_cols[idx].y_coordinate.0[i].into()
            }),
        };

        // Constrain that the first `initial_digest` is the zero digest.
        let zero_digest = SepticDigest::<AB::Expr>::zero().0;
        builder.when_first_row().assert_septic_ext_eq(initial_digest.x.clone(), zero_digest.x);
        builder.when_first_row().assert_septic_ext_eq(initial_digest.y.clone(), zero_digest.y);

        // Constrain that when `is_real = 1`, addition is being carried out, and when `is_real = 0`, the sum remains the same.
        for i in 0..N {
            let current_sum =
                if i == 0 { initial_digest.clone() } else { ith_cumulative_sum(i - 1) };
            let point_to_add = ith_point_to_add(i);
            let next_sum = ith_cumulative_sum(i);
            // If `local_is_real[i] == 1`, current_sum + point_to_add == next_sum must hold.
            // To do this, constrain that `sum_checker_x` and `sum_checker_y` are both zero when `is_real == 1`.
            let sum_checker_x = SepticCurve::<AB::Expr>::sum_checker_x(
                current_sum.clone(),
                point_to_add.clone(),
                next_sum.clone(),
            );
            let sum_checker_y = SepticCurve::<AB::Expr>::sum_checker_y(
                current_sum.clone(),
                point_to_add,
                next_sum.clone(),
            );
            let witnessed_sum_checker_x = SepticExtension::<AB::Expr>::from_base_fn(|idx| {
                local_accumulation.sum_checker[i].0[idx].into()
            });
            // Since `sum_checker_x` is degree 3, we constrain it to be equal to `witnessed_sum_checker_x` first.
            builder.assert_septic_ext_eq(sum_checker_x, witnessed_sum_checker_x.clone());
            // Now we can constrain that when `local_is_real[i] == 1`, the two `sum_checker` values are both zero.
            builder
                .when(local_is_real[i])
                .assert_septic_ext_eq(witnessed_sum_checker_x, SepticExtension::<AB::Expr>::zero());
            builder
                .when(local_is_real[i])
                .assert_septic_ext_eq(sum_checker_y, SepticExtension::<AB::Expr>::zero());

            // If `is_real == 0`, current_sum == next_sum must hold.
            builder
                .when_not(local_is_real[i])
                .assert_septic_ext_eq(current_sum.x.clone(), next_sum.x.clone());
            builder.when_not(local_is_real[i]).assert_septic_ext_eq(current_sum.y, next_sum.y);
        }

        // Constrain that the final digest is the next row's initial_digest.
        let final_digest = ith_cumulative_sum(N - 1);

        let next_initial_digest = SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                next_accumulation.initial_digest[0][i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                next_accumulation.initial_digest[1][i].into()
            }),
        };

        builder
            .when_transition()
            .assert_septic_ext_eq(final_digest.x.clone(), next_initial_digest.x.clone());
        builder.when_transition().assert_septic_ext_eq(final_digest.y, next_initial_digest.y);
    }
}
