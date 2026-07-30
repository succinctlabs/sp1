use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
    sync::Arc,
};

use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde::{Deserialize, Serialize};
use slop_air::Air;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, ExtensionField, Field,
    UnivariatePolynomial,
};
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::{Mle, PaddedMle};
use slop_sumcheck::SumcheckPolyBase;

use crate::{air::MachineAir, ConstraintSumcheckFolder};
use slop_alloc::HasBackend;

use super::ZeroCheckPoly;

/// Zerocheck data for the CPU backend.
#[derive(Clone)]
pub struct ZerocheckCpuProver<F, EF, A> {
    /// The AIR that contains the constraint polynomial.
    air: Arc<A>,
    /// The public values.
    public_values: Arc<Vec<F>>,
    /// The powers of alpha.
    powers_of_alpha: Arc<Vec<EF>>,
    gkr_powers: Arc<Vec<EF>>,
}

impl<F, EF, A> ZerocheckCpuProver<F, EF, A> {
    /// Creates a new `ZerocheckAirData`.
    pub fn new(
        air: Arc<A>,
        public_values: Arc<Vec<F>>,
        powers_of_alpha: Arc<Vec<EF>>,
        gkr_powers: Arc<Vec<EF>>,
    ) -> Self {
        Self { air, public_values, powers_of_alpha, gkr_powers }
    }
}

impl<F, EF, A> ZerocheckCpuProver<F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
{
    pub(crate) fn sum_as_poly_in_last_variable<K, const IS_FIRST_ROUND: bool>(
        &self,
        partial_lagrange: &Mle<EF>,
        preprocessed_values: Option<&PaddedMle<K>>,
        main_values: &PaddedMle<K>,
    ) -> (EF, EF, EF)
    where
        K: ExtensionField<F>,
        EF: ExtensionField<K>,
        A: for<'b> Air<ConstraintSumcheckFolder<'b, F, K, EF>> + MachineAir<F>,
    {
        let air = self.air.clone();
        let public_values = self.public_values.clone();
        let powers_of_alpha = self.powers_of_alpha.clone();
        let gkr_powers = self.gkr_powers.clone();
        {
            let num_non_padded_terms = main_values.num_real_entries().div_ceil(2);
            let eq_chunk_size = std::cmp::max(num_non_padded_terms / num_cpus::get(), 1);
            let values_chunk_size = eq_chunk_size * 2;

            let eq_guts = partial_lagrange.guts().as_buffer().as_slice();

            let num_main_columns = main_values.num_polynomials();
            let num_preprocessed_columns =
                preprocessed_values.map_or(0, slop_multilinear::PaddedMle::num_polynomials);

            let main_values = main_values.inner().as_ref().unwrap().guts().as_buffer().as_slice();
            let has_preprocessed_values = preprocessed_values.is_some();
            let preprocessed_values = preprocessed_values.as_ref().map_or([].as_slice(), |p| {
                p.inner().as_ref().unwrap().guts().as_buffer().as_slice()
            });

            // Handle the case when the zerocheck polynomial has non-padded variables.
            let eq_guts = eq_guts[0..num_non_padded_terms].to_vec();

            let cumul_ys = eq_guts
                .chunks(eq_chunk_size)
                .zip(main_values.chunks(values_chunk_size * num_main_columns))
                .enumerate()
                .par_bridge()
                .map(|(i, (eq_chunk, main_chunk))| {
                    // Evaluate the constraint polynomial at the points 0, 2, and 4, and
                    // add the results to the y_0, y_2, and y_4 accumulators.
                    let mut cumul_y_0 = EF::zero();
                    let mut cumul_y_2 = EF::zero();
                    let mut cumul_y_4 = EF::zero();

                    let mut main_values_0 = vec![K::zero(); num_main_columns];
                    let mut main_values_2 = vec![K::zero(); num_main_columns];
                    let mut main_values_4 = vec![K::zero(); num_main_columns];

                    let mut preprocessed_values_0 = vec![K::zero(); num_preprocessed_columns];
                    let mut preprocessed_values_2 = vec![K::zero(); num_preprocessed_columns];
                    let mut preprocessed_values_4 = vec![K::zero(); num_preprocessed_columns];

                    for (j, (eq, main_row)) in
                        eq_chunk.iter().zip(main_chunk.chunks(num_main_columns * 2)).enumerate()
                    {
                        let main_row_0 = &main_row[0..num_main_columns];
                        let main_row_1 = if main_row.len() == 2 * num_main_columns {
                            &main_row[num_main_columns..num_main_columns * 2]
                        } else {
                            // Provide a dummy row if there is an odd number of rows.
                            &vec![K::zero(); num_main_columns]
                        };

                        interpolate_last_var_non_padded_values::<K, IS_FIRST_ROUND>(
                            main_row_0,
                            main_row_1,
                            &mut main_values_0,
                            &mut main_values_2,
                            &mut main_values_4,
                        );

                        if has_preprocessed_values {
                            let preprocess_chunk_size =
                                values_chunk_size * num_preprocessed_columns;
                            let preprocessed_row_0_start_idx =
                                i * preprocess_chunk_size + 2 * j * num_preprocessed_columns;
                            let preprocessed_row_0 = &preprocessed_values
                                [preprocessed_row_0_start_idx
                                    ..preprocessed_row_0_start_idx + num_preprocessed_columns];
                            let preprocessed_row_1_start_idx =
                                preprocessed_row_0_start_idx + num_preprocessed_columns;
                            let preprocessed_row_1 =
                                if preprocessed_values.len() != preprocessed_row_1_start_idx {
                                    &preprocessed_values[preprocessed_row_1_start_idx
                                        ..preprocessed_row_1_start_idx + num_preprocessed_columns]
                                } else {
                                    // Provide padding values if there is an odd number of rows.
                                    &vec![K::zero(); num_preprocessed_columns]
                                };

                            interpolate_last_var_non_padded_values::<K, IS_FIRST_ROUND>(
                                preprocessed_row_0,
                                preprocessed_row_1,
                                &mut preprocessed_values_0,
                                &mut preprocessed_values_2,
                                &mut preprocessed_values_4,
                            );
                        }

                        increment_y_values::<K, F, EF, A, IS_FIRST_ROUND>(
                            &public_values,
                            &powers_of_alpha,
                            &air,
                            &mut cumul_y_0,
                            &mut cumul_y_2,
                            &mut cumul_y_4,
                            &preprocessed_values_0,
                            &main_values_0,
                            &preprocessed_values_2,
                            &main_values_2,
                            &preprocessed_values_4,
                            &main_values_4,
                            &gkr_powers,
                            *eq,
                        );
                    }
                    (cumul_y_0, cumul_y_2, cumul_y_4)
                })
                .collect::<Vec<_>>();

            cumul_ys.into_iter().fold(
                (EF::zero(), EF::zero(), EF::zero()),
                |(y_0, y_2, y_4), (y_0_i, y_2_i, y_4_i)| (y_0 + y_0_i, y_2 + y_2_i, y_4 + y_4_i),
            )
        }
    }
}

/// This function will calculate the univariate polynomial where all variables other than the last
/// are summed on the boolean hypercube and the last variable is left as a free variable.
/// TODO:  Add flexibility to support degree 2 and degree 3 constraint polynomials.
pub fn zerocheck_sum_as_poly_in_last_variable<
    K: ExtensionField<F>,
    F: Field,
    EF: ExtensionField<F> + ExtensionField<K> + ExtensionField<F> + AbstractExtensionField<K>,
    AirData,
    const IS_FIRST_ROUND: bool,
>(
    poly: &ZeroCheckPoly<K, F, EF, AirData>,
    claim: Option<EF>,
) -> UnivariatePolynomial<EF>
where
    AirData: for<'b> Air<ConstraintSumcheckFolder<'b, F, K, EF>> + MachineAir<F>,
{
    let num_real_entries = poly.main_columns.num_real_entries();
    if num_real_entries == 0 {
        // NOTE: We hard-code the degree of the zerocheck to be three here. This is important to get
        // the correct shape of a dummy proof.
        return UnivariatePolynomial::zero(4);
    }

    let claim = claim.expect("claim must be provided");

    let (rest_point_host, last) = poly.zeta.split_at(poly.zeta.dimension() - 1);
    let last = *last[0];

    // TODO:  Optimization of computing this once per zerocheck sumcheck.
    let partial_lagrange: Mle<EF> = Mle::partial_lagrange(&rest_point_host);
    let partial_lagrange = Arc::new(partial_lagrange);

    // For the first round, we know that at point 0 and 1, the zerocheck polynomial will evaluate to
    // 0. For all rounds, we can find a root of the zerocheck polynomial by finding a root of
    // the eq term in the last coord.
    // So for the first round, we need to find an additional 2 points (since the constraint
    // polynomial is degree 3). We calculate the eval at points 2 and 4 (since we don't need to
    // do any multiplications when interpolating the column evals).
    // For the other rounds, we need to find an additional 1 point since we don't know the zercheck
    // poly eval at point 0 and 1.
    // We calculate the eval at point 0 and then infer the eval at point 1 by the passed in claim.
    let mut xs = Vec::new();
    let mut ys = Vec::new();

    let (mut y_0, mut y_2, mut y_4) =
        poly.air_data.sum_as_poly_in_last_variable::<K, IS_FIRST_ROUND>(
            partial_lagrange.as_ref(),
            poly.preprocessed_columns.as_ref(),
            &poly.main_columns,
        );

    // Add the point 0 and it's eval to the xs and ys.
    let virtual_geq = poly.virtual_geq;

    let threshold_half = poly.main_columns.num_real_entries().div_ceil(2) - 1;
    let msb_lagrange_eval: EF = poly.eq_adjustment
        * if threshold_half < (1 << (poly.num_variables() - 1)) {
            partial_lagrange.guts().as_buffer()[threshold_half]
                .copy_into_host(partial_lagrange.backend())
        } else {
            EF::zero()
        };

    let virtual_0 = virtual_geq.fix_last_variable(EF::zero()).eval_at_usize(threshold_half);
    let virtual_2 = virtual_geq.fix_last_variable(EF::two()).eval_at_usize(threshold_half);
    let virtual_4 =
        virtual_geq.fix_last_variable(EF::from_canonical_usize(4)).eval_at_usize(threshold_half);

    xs.push(EF::zero());

    let eq_last_term_factor = EF::one() - last;
    y_0 *= eq_last_term_factor * poly.eq_adjustment;
    y_0 -= poly.padded_row_adjustment * virtual_0 * msb_lagrange_eval * eq_last_term_factor;
    ys.push(y_0);

    // Add the point 1 and it's eval to the xs and ys.
    xs.push(EF::one());

    let y_1 = claim - y_0;
    ys.push(y_1);

    // Add the point 2 and it's eval to the xs and ys.
    xs.push(EF::from_canonical_usize(2));
    let eq_last_term_factor = last * F::from_canonical_usize(3) - EF::one();
    y_2 *= eq_last_term_factor * poly.eq_adjustment;
    y_2 -= poly.padded_row_adjustment * virtual_2 * msb_lagrange_eval * eq_last_term_factor;
    ys.push(y_2);

    // Add the point 4 and it's eval to the xs and ys.
    xs.push(EF::from_canonical_usize(4));
    let eq_last_term_factor = last * F::from_canonical_usize(7) - F::from_canonical_usize(3);
    y_4 *= eq_last_term_factor * poly.eq_adjustment;
    y_4 -= poly.padded_row_adjustment * virtual_4 * msb_lagrange_eval * eq_last_term_factor;
    ys.push(y_4);

    // Add the eq_first_term_root point and it's eval to the xs and ys.
    let point_elements = poly.zeta.to_vec();
    let point_first = point_elements.last().unwrap();
    let b_const = (EF::one() - *point_first) / (EF::one() - point_first.double());
    xs.push(b_const);
    ys.push(EF::zero());

    interpolate_univariate_polynomial(&xs, &ys)
}

/// This function will calculate the column values where the last variable is set to 0, 2, and 4
/// and it's a non-padded variable.
fn interpolate_last_var_non_padded_values<K: Field, const IS_FIRST_ROUND: bool>(
    row_0: &[K],
    row_1: &[K],
    vals_0: &mut [K],
    vals_2: &mut [K],
    vals_4: &mut [K],
) {
    for (i, (row_0_val, row_1_val)) in row_0.iter().zip_eq(row_1.iter()).enumerate() {
        let slope = *row_1_val - *row_0_val;
        let slope_times_2 = slope + slope;
        let slope_times_4 = slope_times_2 + slope_times_2;

        vals_0[i] = *row_0_val;

        vals_2[i] = slope_times_2 + *row_0_val;
        vals_4[i] = slope_times_4 + *row_0_val;
    }
}

/// The data required to produce zerocheck proofs on CPU.
#[derive(Clone, Debug, Copy, Serialize, Deserialize)]
pub struct ZerocheckCpuProverData<A>(PhantomData<A>);

impl<A> Default for ZerocheckCpuProverData<A> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<A> ZerocheckCpuProverData<A> {
    /// Creates a round prover for zerocheck.
    pub fn round_prover<F, EF>(
        air: Arc<A>,
        public_values: Arc<Vec<F>>,
        powers_of_alpha: Arc<Vec<EF>>,
        gkr_powers: Arc<Vec<EF>>,
    ) -> ZerocheckCpuProver<F, EF, A>
    where
        F: Field,
        EF: ExtensionField<F>,
        A: for<'b> Air<ConstraintSumcheckFolder<'b, F, F, EF>>
            + for<'b> Air<ConstraintSumcheckFolder<'b, F, EF, EF>>
            + MachineAir<F>,
    {
        ZerocheckCpuProver::new(air, public_values, powers_of_alpha, gkr_powers)
    }
}

/// This function will calculate the column values where the last variable is set to 0, 2, and 4
/// and it's a padded variable.  The `row_0` values are taken from the values matrix (which should
/// have a height of 1).  The `row_1` values are all zero.
#[must_use]
pub fn interpolate_last_var_padded_values<K: Field>(values: &Mle<K>) -> (Vec<K>, Vec<K>, Vec<K>) {
    let row_0 = values.guts().as_slice().iter();
    let vals_0 = row_0.clone().copied().collect::<Vec<_>>();
    let vals_2 = row_0.clone().map(|val| -(*val)).collect::<Vec<_>>();
    let vals_4 = row_0.clone().map(|val| -K::from_canonical_usize(3) * (*val)).collect::<Vec<_>>();

    (vals_0, vals_2, vals_4)
}

/// This function will increment the y0, y2, and y4 accumulators by the eval of the constraint
/// polynomial at the points 0, 2, and 4.
#[allow(clippy::too_many_arguments)]
pub fn increment_y_values<
    'a,
    K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
    F: Field,
    EF: ExtensionField<F> + From<K> + ExtensionField<F> + AbstractExtensionField<K>,
    A: for<'b> Air<ConstraintSumcheckFolder<'b, F, K, EF>> + MachineAir<F>,
    const IS_FIRST_ROUND: bool,
>(
    public_values: &[F],
    powers_of_alpha: &[EF],
    air: &A,
    y_0: &mut EF,
    y_2: &mut EF,
    y_4: &mut EF,
    preprocessed_column_vals_0: &[K],
    main_column_vals_0: &[K],
    preprocessed_column_vals_2: &[K],
    main_column_vals_2: &[K],
    preprocessed_column_vals_4: &[K],
    main_column_vals_4: &[K],
    interaction_batching_powers: &[EF],
    eq: EF,
) {
    let mut y_0_adjustment = EF::zero();
    // Add to the y_0 accumulator.
    if !IS_FIRST_ROUND {
        let mut folder = ConstraintSumcheckFolder {
            preprocessed: RowMajorMatrixView::new_row(preprocessed_column_vals_0),
            main: RowMajorMatrixView::new_row(main_column_vals_0),
            accumulator: EF::zero(),
            public_values,
            constraint_index: 0,
            powers_of_alpha,
        };
        air.eval(&mut folder);
        y_0_adjustment += folder.accumulator;
    }

    let gkr_adjustment_0 = main_column_vals_0
        .iter()
        .copied()
        .chain(preprocessed_column_vals_0.iter().copied())
        .zip(interaction_batching_powers.iter().copied())
        .map(|(val, power)| power * val)
        .sum::<EF>();

    y_0_adjustment += gkr_adjustment_0;
    *y_0 += y_0_adjustment * eq;

    let mut y_2_adjustment = EF::zero();

    // Add to the y_2 accumulator.
    let mut folder = ConstraintSumcheckFolder {
        preprocessed: RowMajorMatrixView::new_row(preprocessed_column_vals_2),
        main: RowMajorMatrixView::new_row(main_column_vals_2),
        accumulator: EF::zero(),
        public_values,
        constraint_index: 0,
        powers_of_alpha,
    };
    air.eval(&mut folder);

    y_2_adjustment += folder.accumulator;
    let gkr_adjustment_2 = main_column_vals_2
        .iter()
        .copied()
        .chain(preprocessed_column_vals_2.iter().copied())
        .zip(interaction_batching_powers.iter().copied())
        .map(|(val, power)| power * val)
        .sum::<EF>();
    y_2_adjustment += gkr_adjustment_2;
    *y_2 += y_2_adjustment * eq;

    // Add to the y_4 accumulator.
    let mut folder = ConstraintSumcheckFolder {
        preprocessed: RowMajorMatrixView::new_row(preprocessed_column_vals_4),
        main: RowMajorMatrixView::new_row(main_column_vals_4),
        accumulator: EF::zero(),
        public_values,
        constraint_index: 0,
        powers_of_alpha,
    };
    let gkr_adjustment_4 = gkr_adjustment_2 + gkr_adjustment_2 - gkr_adjustment_0;
    air.eval(&mut folder);
    *y_4 += (folder.accumulator + gkr_adjustment_4) * eq;
}
