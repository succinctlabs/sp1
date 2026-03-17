use std::{marker::PhantomData, sync::Arc};

use itertools::Itertools;
use slop_algebra::{ExtensionField, Field};
use slop_alloc::{Backend, Buffer, CanCopyFrom, CpuBackend};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, Point, PointBackend};
use slop_utils::log2_ceil_usize;

use super::JaggedAssistSumAsPoly;

/// A struct that represents the polynomial that is used to evaluate the sumcheck.
pub struct JaggedEvalSumcheckPoly<
    F: Field,
    EF: ExtensionField<F>,
    Challenger: FieldChallenger<F> + Send + Sync,
    DeviceChallenger,
    BPE: JaggedAssistSumAsPoly<F, EF, A, Challenger, DeviceChallenger> + Send + Sync,
    A: Backend,
> {
    /// Batch evaluator of the branching program.
    pub bp_batch_eval: BPE,
    /// The random point generated during the sumcheck proving time.
    pub rho: Point<EF, A>,
    /// The z_col point.
    pub z_col: Point<EF, A>,
    /// This is a concatenation of the bitstring of t_c and t_{c+1} for every column c.
    pub merged_prefix_sums: Buffer<F, A>,
    /// The evaluations of the z_col at the merged prefix sums.
    pub z_col_eq_vals: Buffer<EF, A>,
    /// The sumcheck round number that this poly is used in.
    pub round_num: usize,
    /// The intermediate full evaluations of the eq polynomials.
    pub intermediate_eq_full_evals: Buffer<EF, A>,
    /// The half value.
    pub half: EF,

    pub prefix_sum_dimension: u32,

    _marker: PhantomData<(A, Challenger, DeviceChallenger)>,
}

impl<
        F: Field,
        EF: ExtensionField<F>,
        A: Backend,
        Challenger: FieldChallenger<F> + Send + Sync,
        DeviceChallenger,
        BPE: JaggedAssistSumAsPoly<F, EF, A, Challenger, DeviceChallenger> + Send + Sync,
    > JaggedEvalSumcheckPoly<F, EF, Challenger, DeviceChallenger, BPE, A>
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bp_batch_eval: BPE,
        rho: Point<EF, A>,
        z_col: Point<EF, A>,
        merged_prefix_sums: Buffer<F, A>,
        z_col_eq_vals: Buffer<EF, A>,
        round_num: usize,
        intermediate_eq_full_evals: Buffer<EF, A>,
        half: EF,
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
        backend: A,
    ) -> Self
    where
        A: PointBackend<EF>
            + PointBackend<F>
            + CanCopyFrom<Buffer<EF>, CpuBackend, Output = Buffer<EF, A>>
            + CanCopyFrom<Buffer<F>, CpuBackend, Output = Buffer<F, A>>,
    {
        let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());
        let col_prefix_sums: Vec<Point<F>> =
            prefix_sums.iter().map(|&x| Point::from_usize(x, log_m + 1)).collect();

        // Generate all of the merged prefix sums.
        let merged_prefix_sums = col_prefix_sums
            .windows(2)
            .map(|prefix_sums| {
                let mut merged_prefix_sum = prefix_sums[0].clone();
                merged_prefix_sum.extend(&prefix_sums[1]);
                merged_prefix_sum
            })
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
        let z_col_device = backend.copy_to(&z_col).unwrap();

        let half = EF::two().inverse();
        let bp_batch_eval = BPE::new(
            z_row,
            z_index,
            merged_prefix_sums.clone(),
            z_col_eq_vals.clone(),
            backend.clone(),
        );

        let z_col_eq_vals_device: Buffer<EF, A> =
            backend.copy_into(Buffer::<EF>::from(z_col_eq_vals)).unwrap();

        let merged_prefix_sums_device = backend
            .copy_into(
                merged_prefix_sums
                    .iter()
                    .flat_map(|point| point.iter())
                    .copied()
                    .collect::<Buffer<F>>(),
            )
            .unwrap();

        let intermediate_eq_full_evals = vec![EF::one(); merged_prefix_sums_len];
        let intermediate_eq_full_evals_device =
            backend.copy_into(Buffer::<EF>::from(intermediate_eq_full_evals)).unwrap();

        Self {
            bp_batch_eval,
            rho: Point::new(Buffer::with_capacity_in(0, backend)),
            z_col: z_col_device,
            merged_prefix_sums: merged_prefix_sums_device,
            round_num: 0,
            z_col_eq_vals: z_col_eq_vals_device,
            intermediate_eq_full_evals: intermediate_eq_full_evals_device,
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

    pub fn sum_as_poly_in_last_t_variables_observe_and_sample(
        &mut self,
        claim: Option<EF>,
        sum_values: &mut Buffer<EF, A>,
        challenger: &mut DeviceChallenger,
        t: usize,
    ) -> EF {
        assert!(t == 1);
        self.sum_as_poly_in_last_variable_observe_and_sample(claim, sum_values, challenger)
    }

    pub fn sum_as_poly_in_last_variable_observe_and_sample(
        &mut self,
        claim: Option<EF>,
        sum_values: &mut Buffer<EF, A>,
        challenger: &mut DeviceChallenger,
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
