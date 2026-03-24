use std::{marker::PhantomData, sync::Arc};

use itertools::Itertools;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::{FieldChallenger, VariableLengthChallenger};
use slop_multilinear::Point;

use crate::{BranchingProgram, MemoryState, WIDE_BRANCHING_PROGRAM_WIDTH};

#[derive(Debug, Clone)]
pub struct JaggedAssistSumAsPolyCPUImpl<F: Field, EF: ExtensionField<F>, Challenger> {
    pub(crate) branching_program: BranchingProgram<EF>,
    merged_prefix_sums: Arc<Vec<Point<F>>>,
    prefix_states: Vec<Vec<EF>>,
    pub(crate) suffix_vector: [EF; WIDE_BRANCHING_PROGRAM_WIDTH],
    half: F,
    _marker: PhantomData<Challenger>,
}

impl<F: Field, EF: ExtensionField<F>, Challenger: FieldChallenger<F> + Send + Sync>
    JaggedAssistSumAsPolyCPUImpl<F, EF, Challenger>
{
    pub fn new(
        z_row: Point<EF>,
        z_index: Point<EF>,
        merged_prefix_sums: Arc<Vec<Point<F>>>,
    ) -> Self {
        let branching_program = BranchingProgram::new(z_row, z_index);

        let chunk_size = std::cmp::max(merged_prefix_sums.len() / num_cpus::get(), 1);
        let prefix_states: Vec<Vec<EF>> = merged_prefix_sums
            .par_chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk.iter().map(|ps| branching_program.precompute_prefix_states(ps))
            })
            .collect();

        let mut suffix_vector = [EF::zero(); WIDE_BRANCHING_PROGRAM_WIDTH];
        suffix_vector[MemoryState::initial_state().get_index()] = EF::one();

        Self {
            branching_program,
            merged_prefix_sums,
            prefix_states,
            suffix_vector,
            half: F::two().inverse(),
            _marker: PhantomData,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sum_as_poly_and_sample_into_point(
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
                                let eq_prefix_sum_val: F =
                                    *merged_prefix_sum.get(prefix_sum_dim - round_num - 1).unwrap();

                                // Eq term for lambda = 0: eq(v, 0) = 1 - v (base field).
                                let eq_val_0: F = F::one() - eq_prefix_sum_val;
                                let eq_eval_0 = *intermediate_eq_full_eval * eq_val_0;

                                // Eq term for lambda = 1/2: eq(v, 1/2) = 1/2 (base field).
                                let eq_eval_half = *intermediate_eq_full_eval * self.half;

                                // BP evaluation using cached prefix + suffix.
                                let w = WIDE_BRANCHING_PROGRAM_WIDTH;
                                let offset = (round_num + 1) * w;
                                let prefix_state = &col_prefix_states[offset..offset + w];
                                let h_eval_0 = self.branching_program.eval_with_cached(
                                    round_num,
                                    None,
                                    false,
                                    prefix_state,
                                    &self.suffix_vector,
                                );
                                let h_eval_half = self.branching_program.eval_with_cached(
                                    round_num,
                                    Some(self.half),
                                    true,
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
}
