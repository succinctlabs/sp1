use std::marker::PhantomData;

use itertools::Itertools;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};
use serde::Serialize;
use slop_algebra::{interpolate_univariate_polynomial, ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_utils::log2_ceil_usize;

use crate::{
    BranchingProgram, JaggedLittlePolynomialProverParams, JaggedSumcheckEvalProof, MemoryState,
    WIDE_BRANCHING_PROGRAM_WIDTH,
};

/// The interleaved layer index `2*psl - 1 - round_num` reads bit
/// `round_num / 2` (LSB-indexed) from `curr` (even rounds) or `next` (odd rounds).
/// This matches the original `merged_prefix_sum[psd - 1 - round_num]` indexing.
#[inline]
fn pair_bit<F: Field>(pair: (usize, usize), round_num: usize) -> F {
    let i = round_num >> 1;
    let bit_src = if round_num & 1 == 0 { pair.0 } else { pair.1 };
    F::from_canonical_usize((bit_src >> i) & 1)
}

/// State the jagged-eval sumcheck mutates across rounds.
///
/// Holds the branching-program batch evaluator (backward-DP prefix states, suffix vector)
/// together with the per-round sumcheck bookkeeping (rho, z_col, eq evaluations).
#[derive(Debug, Clone)]
pub struct JaggedEvalSumcheckPoly<F: Field, EF: ExtensionField<F>> {
    /// The branching program used to evaluate H at the current round.
    branching_program: BranchingProgram<EF>,
    /// Cached backward-DP states, one `Vec<EF>` per column laid out as
    /// `[(layer * WIDE_BRANCHING_PROGRAM_WIDTH) + state]`.
    prefix_states: Vec<Vec<EF>>,
    /// Width-`WIDE_BRANCHING_PROGRAM_WIDTH` suffix vector, extended one layer per round.
    suffix_vector: [EF; WIDE_BRANCHING_PROGRAM_WIDTH],
    /// The random point sampled across sumcheck rounds.
    rho: Point<EF>,
    /// `(curr, next)` prefix-sum integer pairs, one per (condensed) column. Bits are
    /// extracted on demand via [`pair_bit`] to avoid storing
    /// `num_columns * prefix_sum_dimension` field elements.
    prefix_sum_pairs: Vec<(usize, usize)>,
    _f_marker: PhantomData<F>,
    /// `z_col` partial-lagrange weights aggregated per distinct column-pair.
    z_col_eq_vals: Buffer<EF>,
    /// Current sumcheck round number.
    round_num: usize,
    /// Running product of per-column eq evaluations; updated as `rho` extends.
    intermediate_eq_full_evals: Buffer<EF>,
    /// `1/2` in the base field.
    half: F,
    /// Number of variables in each per-column merged prefix sum.
    prefix_sum_dimension: u32,
}

impl<F: Field, EF: ExtensionField<F>> JaggedEvalSumcheckPoly<F, EF> {
    /// Build the sumcheck poly from the minimal input data (the jagged params + the challenge
    /// points `z_row`, `z_col`, `z_index`).
    pub fn new_from_jagged_params(
        z_row: Point<EF>,
        z_col: Point<EF>,
        z_index: Point<EF>,
        prefix_sums: Vec<usize>,
    ) -> Self {
        let prefix_sum_length = log2_ceil_usize(*prefix_sums.last().unwrap()) + 1;

        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(&z_col);
        let z_col_lagrange = z_col_partial_lagrange.guts().as_slice();

        // Condense `(curr, next)` prefix-sum pairs by collapsing runs of identical
        // adjacent pairs (= empty-trace columns) and summing their z_col eq values.
        let mut prefix_sum_pairs: Vec<(usize, usize)> = Vec::with_capacity(prefix_sums.len() - 1);
        let mut z_col_eq_vals_vec: Vec<EF> = Vec::with_capacity(prefix_sums.len() - 1);
        for (window, &eq_val) in prefix_sums.windows(2).zip(z_col_lagrange) {
            let pair = (window[0], window[1]);
            if prefix_sum_pairs.last() == Some(&pair) {
                *z_col_eq_vals_vec.last_mut().unwrap() += eq_val;
            } else {
                prefix_sum_pairs.push(pair);
                z_col_eq_vals_vec.push(eq_val);
            }
        }
        let num_columns = prefix_sum_pairs.len();

        // Branching program + backward-DP prefix states (one per column).
        let branching_program = BranchingProgram::new(z_row, z_index);
        let chunk_size = std::cmp::max(num_columns / num_cpus::get(), 1);
        let prefix_states: Vec<Vec<EF>> = prefix_sum_pairs
            .par_chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk.iter().map(|&(curr, next)| {
                    branching_program.precompute_prefix_states::<F>(curr, next)
                })
            })
            .collect();

        let mut suffix_vector = [EF::zero(); WIDE_BRANCHING_PROGRAM_WIDTH];
        suffix_vector[MemoryState::initial_state().get_index()] = EF::one();

        let z_col_eq_vals: Buffer<EF> = z_col_eq_vals_vec.into();
        let intermediate_eq_full_evals: Buffer<EF> = vec![EF::one(); num_columns].into();

        Self {
            branching_program,
            prefix_states,
            suffix_vector,
            rho: Point::default(),
            prefix_sum_pairs,
            _f_marker: PhantomData,
            z_col_eq_vals,
            round_num: 0,
            intermediate_eq_full_evals,
            half: F::two().inverse(),
            prefix_sum_dimension: (2 * prefix_sum_length) as u32,
        }
    }

    pub fn num_variables(&self) -> u32 {
        self.prefix_sum_dimension
    }

    pub fn get_component_poly_evals(&self) -> Vec<EF> {
        Vec::new()
    }

    /// Fix the last variable of the polynomial by incorporating the sampled randomness.
    /// Updates intermediate eq evals and extends the suffix vector by one layer.
    fn fix_last_variable(&mut self) {
        let alpha = *self.rho.first().unwrap();
        let round_num = self.round_num;

        // Update the intermediate full eq evals.
        for (&pair, intermediate_eq_full_eval) in self
            .prefix_sum_pairs
            .iter()
            .zip(self.intermediate_eq_full_evals.as_mut_slice().iter_mut())
        {
            let x_i: F = pair_bit(pair, round_num);
            *intermediate_eq_full_eval *= (alpha * x_i) + (EF::one() - alpha) * (EF::one() - x_i);
        }

        // Extend the suffix vector by one layer using the transposed DP.
        self.suffix_vector = self.branching_program.apply_layer_step_transposed(
            round_num,
            alpha,
            &self.suffix_vector,
        );

        self.round_num += 1;
    }

    fn sum_as_poly_in_last_t_variables_observe_and_sample<Challenger: FieldChallenger<F>>(
        &mut self,
        claim: Option<EF>,
        sum_values: &mut Buffer<EF>,
        challenger: &mut Challenger,
        t: usize,
    ) -> EF {
        assert_eq!(t, 1);
        self.sum_as_poly_in_last_variable_observe_and_sample(claim, sum_values, challenger)
    }

    fn sum_as_poly_in_last_variable_observe_and_sample<Challenger: FieldChallenger<F>>(
        &mut self,
        claim: Option<EF>,
        sum_values: &mut Buffer<EF>,
        challenger: &mut Challenger,
    ) -> EF {
        let claim = claim.expect("Claim must be provided");

        let round_num = self.round_num;
        let half = self.half;
        let n_cols = self.z_col_eq_vals.len();

        // Calculate the partition chunk size (in columns).
        let chunk_size = std::cmp::max(n_cols / num_cpus::get(), 1);

        // Compute the values at x = 0 and x = 1/2.
        let (y_0, y_half) = self
            .prefix_sum_pairs
            .par_chunks(chunk_size)
            .zip_eq(self.z_col_eq_vals.par_chunks(chunk_size))
            .zip_eq(self.intermediate_eq_full_evals.par_chunks(chunk_size))
            .zip_eq(self.prefix_states.par_chunks(chunk_size))
            .map(
                |(
                    ((pair_chunk, z_col_eq_val_chunk), intermediate_eq_full_eval_chunk),
                    prefix_states_chunk,
                )| {
                    pair_chunk
                        .iter()
                        .zip_eq(z_col_eq_val_chunk.iter())
                        .zip_eq(intermediate_eq_full_eval_chunk.iter())
                        .zip_eq(prefix_states_chunk.iter())
                        .map(
                            |(
                                ((&pair, z_col_eq_val), intermediate_eq_full_eval),
                                col_prefix_states,
                            )| {
                                let eq_prefix_sum_val: F = pair_bit(pair, round_num);

                                // Eq term for lambda = 0: eq(v, 0) = 1 - v (base field).
                                let eq_val_0: F = F::one() - eq_prefix_sum_val;
                                let eq_eval_0 = *intermediate_eq_full_eval * eq_val_0;

                                // Eq term for lambda = 1/2: eq(v, 1/2) = 1/2 (base field).
                                let eq_eval_half = *intermediate_eq_full_eval * half;

                                // BP evaluation using cached prefix + suffix.
                                let w = WIDE_BRANCHING_PROGRAM_WIDTH;
                                let offset = (round_num + 1) * w;
                                let prefix_state = &col_prefix_states[offset..offset + w];
                                let h_eval_0 = self.branching_program.eval_with_cached(
                                    round_num,
                                    F::zero(),
                                    prefix_state,
                                    &self.suffix_vector,
                                );
                                let h_eval_half = self.branching_program.eval_with_cached(
                                    round_num,
                                    half,
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
        for coeff in poly.coefficients.iter() {
            challenger.observe_ext_element(*coeff);
        }

        let alpha = challenger.sample_ext_element();
        self.rho.add_dimension(alpha);

        // Return the new claim for the next round.
        poly.eval_at_point(alpha)
    }
}

/// The standard implementation of the sumcheck prover from an implementation of `SumcheckPoly`
/// makes assumptions about how the Fiat-Shamir challenges are observed and sampled. This function
/// produces a sumcheck proof using a slightly different decomposition of the sumcheck proving into
/// functions. The function signatures are designed to be similar to those of the GPU implementation.
///
///  # Panics
///  Will panic if the polynomial has zero variables.
pub fn prove_jagged_eval_sumcheck<
    F: Field,
    EF: ExtensionField<F> + Send + Sync,
    Challenger: FieldChallenger<F>,
>(
    mut poly: JaggedEvalSumcheckPoly<F, EF>,
    challenger: &mut Challenger,
    claim: EF,
    t: usize,
    sum_values: &mut Buffer<EF>,
) -> PartialSumcheckProof<EF> {
    let num_variables = poly.num_variables();

    // The first round of sumcheck.
    let mut round_claim = poly.sum_as_poly_in_last_t_variables_observe_and_sample(
        Some(claim),
        sum_values,
        challenger,
        t,
    );

    poly.fix_last_variable();

    for _ in t..num_variables as usize {
        round_claim = poly.sum_as_poly_in_last_variable_observe_and_sample(
            Some(round_claim),
            sum_values,
            challenger,
        );

        poly.fix_last_variable();
    }

    let univariate_polys = sum_values
        .as_slice()
        .chunks_exact(3)
        .map(|chunk| {
            // Compute the univariate polynomial message.
            let ys: [EF; 3] = chunk.try_into().unwrap();
            let xs: [EF; 3] = [EF::zero(), EF::two().inverse(), EF::one()];
            interpolate_univariate_polynomial(&xs, &ys)
        })
        .collect::<Vec<_>>();

    let rho_vec = poly.rho.to_vec();

    let final_claim: EF = univariate_polys.last().unwrap().eval_at_point(*rho_vec.first().unwrap());

    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: claim,
        point_and_eval: (rho_vec.into(), final_claim),
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct JaggedEvalSumcheckProver<F, EF, Challenger>(pub PhantomData<(F, EF, Challenger)>);

impl<F, EF, Challenger> Default for JaggedEvalSumcheckProver<F, EF, Challenger> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F, EF, Challenger> JaggedEvalSumcheckProver<F, EF, Challenger>
where
    JaggedEvalSumcheckProver<F, EF, Challenger>: 'static,
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F>,
{
    pub fn prove_jagged_evaluation(
        &self,
        params: &JaggedLittlePolynomialProverParams,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_trace: &Point<EF>,
        challenger: &mut Challenger,
    ) -> JaggedSumcheckEvalProof<EF> {
        // Create sumcheck proof for the jagged eval.
        let jagged_eval_sc_poly = JaggedEvalSumcheckPoly::<F, EF>::new_from_jagged_params(
            z_row.clone(),
            z_col.clone(),
            z_trace.clone(),
            params.col_prefix_sums_usize.clone(),
        );

        // Compute the full eval of the jagged poly.
        let verifier_params = params.clone().into_verifier_params();
        let expected_sum =
            verifier_params.full_jagged_little_polynomial_evaluation(z_row, z_col, z_trace);

        let log_m = log2_ceil_usize(*params.col_prefix_sums_usize.last().unwrap());

        let mut sum_values = Buffer::from(vec![EF::zero(); 6 * (log_m + 1)]);

        challenger.observe_ext_element(expected_sum);

        let partial_sumcheck_proof = prove_jagged_eval_sumcheck(
            jagged_eval_sc_poly,
            challenger,
            expected_sum,
            1,
            &mut sum_values,
        );

        JaggedSumcheckEvalProof { partial_sumcheck_proof }
    }
}
