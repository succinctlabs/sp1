use std::{marker::PhantomData, sync::Arc};

use itertools::Itertools;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::{Backend, Buffer, CpuBackend};
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_multilinear::Point;

use crate::{BranchingProgram, MemoryState};

use super::JaggedEvalSumcheckPoly;

/// A trait for the jagged assist's sum as poly.
pub trait JaggedAssistSumAsPoly<
    F: Field,
    EF: ExtensionField<F>,
    A: Backend,
    Challenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger,
>: Sized + Send + Sync
{
    /// Construct a new sumcheck instance from the parameters.
    fn new(
        z_row: Point<EF>,
        z_index: Point<EF>,
        merged_prefix_sums: Arc<Vec<Point<F>>>,
        z_col_eq_vals: Vec<EF>,
        backend: A,
    ) -> Self;

    #[allow(clippy::too_many_arguments)]
    /// Compute the sum as a polynomial in the last varaible, storing the result in `sum_values`,
    /// then sample randomness, storing the result in `rhos`. Expected to return the evaluation
    /// of the polynomial at the sampled point.
    fn sum_as_poly_and_sample_into_point(
        &self,
        round_num: usize,
        z_col_eq_vals: &Buffer<EF, A>,
        intermediate_eq_full_evals: &Buffer<EF, A>,
        sum_values: &mut Buffer<EF, A>,
        challenger: &mut DeviceChallenger,
        claim: EF,
        rhos: Point<EF, A>,
    ) -> (EF, Point<EF, A>);

    /// Fix the last variable of the polynomial, returning a new polynomial with one less variable.
    /// The zeroth coordinate of randomness_point is used for fixing the last variable.
    fn fix_last_variable(
        poly: JaggedEvalSumcheckPoly<F, EF, Challenger, DeviceChallenger, Self, A>,
    ) -> JaggedEvalSumcheckPoly<F, EF, Challenger, DeviceChallenger, Self, A>;
}

#[derive(Debug, Clone)]
pub struct JaggedAssistSumAsPolyCPUImpl<F: Field, EF: ExtensionField<F>, Challenger> {
    branching_program: BranchingProgram<EF>,
    merged_prefix_sums: Arc<Vec<Point<F>>>,
    prefix_states: Vec<Vec<EF>>,
    suffix_vector: [EF; 8],
    half: EF,
    _marker: PhantomData<Challenger>,
}

impl<F: Field, EF: ExtensionField<F>, Challenger: FieldChallenger<F> + Send + Sync>
    JaggedAssistSumAsPoly<F, EF, CpuBackend, Challenger, Challenger>
    for JaggedAssistSumAsPolyCPUImpl<F, EF, Challenger>
{
    fn new(
        z_row: Point<EF>,
        z_index: Point<EF>,
        merged_prefix_sums: Arc<Vec<Point<F>>>,
        _z_col_eq_vals: Vec<EF>,
        _backend: CpuBackend,
    ) -> Self {
        let branching_program = BranchingProgram::new(z_row, z_index);

        let chunk_size = std::cmp::max(merged_prefix_sums.len() / num_cpus::get(), 1);
        let prefix_states: Vec<Vec<EF>> = merged_prefix_sums
            .par_chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk.iter().map(|ps| {
                    let ps_ef: Point<EF> = ps.iter().map(|x| (*x).into()).collect();
                    branching_program.precompute_prefix_states(&ps_ef)
                })
            })
            .collect();

        let mut suffix_vector = [EF::zero(); 8];
        suffix_vector[MemoryState::initial_state().get_index()] = EF::one();

        Self {
            branching_program,
            merged_prefix_sums,
            prefix_states,
            suffix_vector,
            half: EF::two().inverse(),
            _marker: PhantomData,
        }
    }

    fn sum_as_poly_and_sample_into_point(
        &self,
        round_num: usize,
        z_col_eq_vals: &Buffer<EF>,
        intermediate_eq_full_evals: &Buffer<EF>,
        sum_values: &mut Buffer<EF>,
        challenger: &mut Challenger,
        claim: EF,
        rhos: Point<EF>,
    ) -> (EF, Point<EF>) {
        let mut rhos = rhos.clone();
        // Calculate the partition chunk size.
        let chunk_size = std::cmp::max(z_col_eq_vals.len() / num_cpus::get(), 1);

        // Compute the values at x = 0 and x = 1/2.
        let (y_0, y_half) = self
            .merged_prefix_sums
            .par_chunks(chunk_size)
            .zip_eq(z_col_eq_vals.par_chunks(chunk_size))
            .zip_eq(intermediate_eq_full_evals.par_chunks(chunk_size))
            .zip_eq(self.prefix_states.par_chunks(chunk_size))
            .map(
                |(
                    (
                        (merged_prefix_sum_chunk, z_col_eq_val_chunk),
                        intermediate_eq_full_eval_chunk,
                    ),
                    prefix_states_chunk,
                )| {
                    merged_prefix_sum_chunk
                        .iter()
                        .zip_eq(z_col_eq_val_chunk.iter())
                        .zip_eq(intermediate_eq_full_eval_chunk.iter())
                        .zip_eq(prefix_states_chunk.iter())
                        .map(
                            |(
                                ((merged_prefix_sum, z_col_eq_val), intermediate_eq_full_eval),
                                col_prefix_states,
                            )| {
                                let prefix_sum_dim = merged_prefix_sum.dimension();
                                let eq_prefix_sum_val: EF = (*merged_prefix_sum
                                    .get(prefix_sum_dim - round_num - 1)
                                    .unwrap())
                                .into();

                                // Eq term for lambda = 0.
                                let eq_val_0 = EF::one() - eq_prefix_sum_val;
                                let eq_eval_0 = *intermediate_eq_full_eval * eq_val_0;

                                // Eq term for lambda = 1/2.
                                let eq_eval_half = *intermediate_eq_full_eval * self.half;

                                // BP evaluation using cached prefix + suffix.
                                let offset = (round_num + 1) * 8;
                                let prefix_state = &col_prefix_states[offset..offset + 8];
                                let h_eval_0 = self.branching_program.eval_with_cached(
                                    round_num,
                                    EF::zero(),
                                    prefix_state,
                                    &self.suffix_vector,
                                );
                                let h_eval_half = self.branching_program.eval_with_cached(
                                    round_num,
                                    self.half,
                                    prefix_state,
                                    &self.suffix_vector,
                                );

                                let y_0 = *z_col_eq_val * h_eval_0 * eq_eval_0;
                                let y_half = *z_col_eq_val * h_eval_half * eq_eval_half;

                                (y_0, y_half)
                            },
                        )
                        .fold((EF::zero(), EF::zero()), |(y_0, y_2), (y_0_i, y_2_i)| {
                            (y_0 + y_0_i, y_2 + y_2_i)
                        })
                },
            )
            .reduce(
                || (EF::zero(), EF::zero()),
                |(y_0, y_2), (y_0_i, y_2_i)| (y_0 + y_0_i, y_2 + y_2_i),
            );

        // Store the values in the sum_values buffer.
        sum_values.as_mut_slice()[3 * round_num] = y_0;
        sum_values.as_mut_slice()[3 * round_num + 1] = y_half;
        let y_1 = claim - y_0;
        sum_values.as_mut_slice()[3 * round_num + 2] = y_1;

        // Interpolate the polynomial.
        let poly = interpolate_univariate_polynomial(
            &[EF::zero(), EF::two().inverse(), EF::one()],
            &[y_0, y_half, y_1],
        );

        // Observe and sample new randomness.
        challenger.observe_constant_length_extension_slice(&poly.coefficients);

        let alpha = challenger.sample_ext_element();
        rhos.add_dimension(alpha);

        // Return the new claim for the next round.
        (poly.eval_at_point(alpha), rhos.clone())
    }

    fn fix_last_variable(
        poly: JaggedEvalSumcheckPoly<F, EF, Challenger, Challenger, Self, CpuBackend>,
    ) -> JaggedEvalSumcheckPoly<F, EF, Challenger, Challenger, Self, CpuBackend> {
        // Add alpha to the rho point.
        let alpha = *poly.rho.first().unwrap();

        let merged_prefix_sum_dim = poly.prefix_sum_dimension as usize;

        // Update the intermediate full eq evals.
        let updated_intermediate_eq_full_evals = poly
            .merged_prefix_sums
            .chunks(merged_prefix_sum_dim)
            .zip_eq(poly.intermediate_eq_full_evals.iter())
            .map(|(merged_prefix_sum, intermediate_eq_full_eval)| {
                let x_i =
                    merged_prefix_sum.get(merged_prefix_sum_dim - 1 - poly.round_num).unwrap();
                *intermediate_eq_full_eval
                    * ((alpha * *x_i) + (EF::one() - alpha) * (EF::one() - *x_i))
            })
            .collect_vec();

        // Extend the suffix vector by one layer using the transposed DP.
        let mut bp_batch_eval = poly.bp_batch_eval;
        bp_batch_eval.suffix_vector = bp_batch_eval.branching_program.apply_layer_step_transposed(
            poly.round_num,
            alpha,
            &bp_batch_eval.suffix_vector,
        );

        JaggedEvalSumcheckPoly::new(
            bp_batch_eval,
            poly.rho,
            poly.z_col,
            poly.merged_prefix_sums,
            poly.z_col_eq_vals,
            poly.round_num + 1,
            updated_intermediate_eq_full_evals.into(),
            poly.half,
            poly.prefix_sum_dimension,
        )
    }
}
