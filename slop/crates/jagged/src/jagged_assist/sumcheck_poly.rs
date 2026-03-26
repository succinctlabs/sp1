use std::{marker::PhantomData, sync::Arc};

use itertools::Itertools;
use slop_algebra::{ExtensionField, Field};
use slop_alloc::Buffer;
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point};
use slop_utils::log2_ceil_usize;

use crate::interleave_prefix_sums;

use super::JaggedAssistSumAsPolyCPUImpl;

/// A struct that represents the polynomial that is used to evaluate the sumcheck.
pub struct JaggedEvalSumcheckPoly<
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + Send + Sync,
> {
    /// Batch evaluator of the branching program.
    pub bp_batch_eval: JaggedAssistSumAsPolyCPUImpl<F, EF, Challenger>,
    /// The random point generated during the sumcheck proving time.
    pub rho: Point<EF>,
    /// The z_col point.
    pub z_col: Point<EF>,
    /// This is a concatenation of the bitstring of t_c and t_{c+1} for every column c.
    pub merged_prefix_sums: Buffer<F>,
    /// The evaluations of the z_col at the merged prefix sums.
    pub z_col_eq_vals: Buffer<EF>,
    /// The sumcheck round number that this poly is used in.
    pub round_num: usize,
    /// The intermediate full evaluations of the eq polynomials.
    pub intermediate_eq_full_evals: Buffer<EF>,
    /// The half value (1/2 in the base field).
    pub half: F,

    pub prefix_sum_dimension: u32,

    _marker: PhantomData<Challenger>,
}

impl<F: Field, EF: ExtensionField<F>, Challenger: FieldChallenger<F> + Send + Sync>
    JaggedEvalSumcheckPoly<F, EF, Challenger>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bp_batch_eval: JaggedAssistSumAsPolyCPUImpl<F, EF, Challenger>,
        rho: Point<EF>,
        z_col: Point<EF>,
        merged_prefix_sums: Buffer<F>,
        z_col_eq_vals: Buffer<EF>,
        round_num: usize,
        intermediate_eq_full_evals: Buffer<EF>,
        half: F,
        num_variables: u32,
    ) -> Self {
        Self {
            bp_batch_eval,
            rho,
            z_col,
            merged_prefix_sums,
            z_col_eq_vals,
            round_num,
            intermediate_eq_full_evals,
            half,
            prefix_sum_dimension: num_variables,
            _marker: PhantomData,
        }
    }

    /// A constructor for the jagged eval sumcheck polynomial that takes the minimal amount of input
    /// data.
    pub fn new_from_jagged_params(
        z_row: Point<EF>,
        z_col: Point<EF>,
        z_index: Point<EF>,
        prefix_sums: Vec<usize>,
    ) -> Self {
        let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());
        let col_prefix_sums: Vec<Point<F>> =
            prefix_sums.iter().map(|&x| Point::from_usize(x, log_m + 1)).collect();

        // Generate all of the merged prefix sums (interleaved layout).
        let merged_prefix_sums = col_prefix_sums
            .windows(2)
            .map(|prefix_sums| interleave_prefix_sums(&prefix_sums[0], &prefix_sums[1]))
            .collect_vec();

        // Generate all of the z_col partial lagrange mle.
        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(&z_col);

        // Condense the merged_prefix_sums and z_col_eq_vals for empty tables.
        let (merged_prefix_sums, z_col_eq_vals): (Vec<Point<F>>, Vec<EF>) = merged_prefix_sums
            .iter()
            .zip(z_col_partial_lagrange.guts().as_slice())
            .chunk_by(|(merged_prefix_sum, _)| *merged_prefix_sum)
            .into_iter()
            .map(|(merged_prefix_sum, group)| {
                let group_elements =
                    group.into_iter().map(|(_, z_col_eq_val)| *z_col_eq_val).collect_vec();
                (merged_prefix_sum.clone(), group_elements.into_iter().sum::<EF>())
            })
            .unzip();

        let merged_prefix_sums_len = merged_prefix_sums.len();
        let num_variables = merged_prefix_sums[0].dimension();
        assert!(merged_prefix_sums_len == z_col_eq_vals.len());

        let merged_prefix_sums = Arc::new(merged_prefix_sums);

        let half = F::two().inverse();
        let bp_batch_eval =
            JaggedAssistSumAsPolyCPUImpl::new(z_row, z_index, merged_prefix_sums.clone());

        let z_col_eq_vals: Buffer<EF> = z_col_eq_vals.into();

        let merged_prefix_sums_flat: Buffer<F> =
            merged_prefix_sums.iter().flat_map(|point| point.iter()).copied().collect();

        let intermediate_eq_full_evals: Buffer<EF> = vec![EF::one(); merged_prefix_sums_len].into();

        Self {
            bp_batch_eval,
            rho: Point::default(),
            z_col,
            merged_prefix_sums: merged_prefix_sums_flat,
            round_num: 0,
            z_col_eq_vals,
            intermediate_eq_full_evals,
            half,
            prefix_sum_dimension: num_variables as u32,
            _marker: PhantomData,
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
    pub fn fix_last_variable(&mut self) {
        let alpha = *self.rho.first().unwrap();

        let merged_prefix_sum_dim = self.prefix_sum_dimension as usize;

        // Update the intermediate full eq evals.
        for (merged_prefix_sum_chunk, intermediate_eq_full_eval) in self
            .merged_prefix_sums
            .as_slice()
            .chunks(merged_prefix_sum_dim)
            .zip(self.intermediate_eq_full_evals.as_mut_slice().iter_mut())
        {
            let x_i = merged_prefix_sum_chunk[merged_prefix_sum_dim - 1 - self.round_num];
            *intermediate_eq_full_eval *= (alpha * x_i) + (EF::one() - alpha) * (EF::one() - x_i);
        }

        // Extend the suffix vector by one layer using the transposed DP.
        self.bp_batch_eval.suffix_vector = self
            .bp_batch_eval
            .branching_program
            .apply_layer_step_transposed(self.round_num, alpha, &self.bp_batch_eval.suffix_vector);

        self.round_num += 1;
    }

    pub fn sum_as_poly_in_last_t_variables_observe_and_sample(
        &mut self,
        claim: Option<EF>,
        sum_values: &mut Buffer<EF>,
        challenger: &mut Challenger,
        t: usize,
    ) -> EF {
        assert!(t == 1);
        self.sum_as_poly_in_last_variable_observe_and_sample(claim, sum_values, challenger)
    }

    pub fn sum_as_poly_in_last_variable_observe_and_sample(
        &mut self,
        claim: Option<EF>,
        sum_values: &mut Buffer<EF>,
        challenger: &mut Challenger,
    ) -> EF {
        let claim = claim.expect("Claim must be provided");
        let (new_claim, new_point) = self.bp_batch_eval.sum_as_poly_and_sample_into_point(
            self.round_num,
            &self.z_col_eq_vals,
            &self.intermediate_eq_full_evals,
            sum_values,
            challenger,
            claim,
            self.rho.clone(),
        );
        self.rho = new_point;
        new_claim
    }
}
