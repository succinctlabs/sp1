use sp1_gpu_cudart::{
    args,
    sys::v2_kernels::{
        jagged_fix_and_sum, jagged_sum_as_poly,
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding, padded_hadamard_fix_and_sum,
    },
    DeviceMle, DeviceTensor, TaskScope,
};

use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, Field,
    UnivariatePolynomial,
};
use slop_alloc::{Backend, HasBackend};
use slop_challenger::FieldChallenger;
use slop_multilinear::Mle;
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;

use sp1_gpu_utils::{DenseData, Ext, Felt, JaggedTraceMle};

use super::hadamard::{fix_last_variable, fix_last_variable_and_sum_as_poly};

pub struct JaggedFirstRoundPoly<'a, A: Backend = TaskScope> {
    // pub base: Arc<Tensor<Felt, A>>,
    pub base: &'a JaggedTraceMle<Felt, A>,
    pub eq_z_col: Mle<Ext, A>,
    pub eq_z_row: Mle<Ext, A>,
    pub height: usize,
    pub total_number_of_variables: u32,
}

impl<'a, A: Backend> JaggedFirstRoundPoly<'a, A> {
    #[inline]
    pub fn new(
        base: &'a JaggedTraceMle<Felt, A>,
        eq_z_col: Mle<Ext, A>,
        eq_z_row: Mle<Ext, A>,
        height: usize,
    ) -> Self {
        let total_number_of_variables = (base.dense().dense.len()).next_power_of_two().ilog2();
        Self { base, eq_z_col, eq_z_row, height, total_number_of_variables }
    }

    /// # Safety
    ///
    /// See [std::mem::MaybeUninit::assume_init].
    #[inline]
    pub unsafe fn assume_init(&mut self) {
        self.eq_z_col.assume_init();
        self.eq_z_row.assume_init();
    }
}

#[repr(C)]
pub struct JaggedFirstRoundPolyRaw {
    col_index: *const u32,
    start_indices: *const u32,
    base: *const Felt,
    eq_z_col: *const Ext,
    eq_z_row: *const Ext,
    height: usize,
}

#[repr(C)]
pub struct JaggedFirstRoundPolyMutRaw {
    base: *mut Felt,
    eq_z_col: *mut Ext,
    eq_z_row: *mut Ext,
    height: usize,
}

impl<'a, A: Backend> DenseData<A> for JaggedFirstRoundPoly<'a, A> {
    type DenseDataRaw = JaggedFirstRoundPolyRaw;
    fn as_ptr(&self) -> Self::DenseDataRaw {
        JaggedFirstRoundPolyRaw {
            col_index: self.base.col_index.as_ptr(),
            start_indices: self.base.start_indices.as_ptr(),
            base: self.base.dense().dense.as_ptr(),
            eq_z_col: self.eq_z_col.guts().as_ptr(),
            eq_z_row: self.eq_z_row.guts().as_ptr(),
            height: self.height,
        }
    }
}

/// TODO: document
pub fn generate_jagged_sumcheck_poly(
    traces: &'_ JaggedTraceMle<Felt, TaskScope>,
    eq_z_col: DeviceMle<Ext>,
    eq_z_row: DeviceMle<Ext>,
) -> JaggedFirstRoundPoly<'_> {
    let half_len = traces.dense().dense.len() >> 1;
    JaggedFirstRoundPoly::new(traces, eq_z_col.into(), eq_z_row.into(), half_len)
}

fn sum_as_poly_first_round<'a>(
    poly: &JaggedFirstRoundPoly<'a>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let circuit = &poly;

    let height = circuit.height;

    let backend = circuit.base.backend();

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;

    let grid_dim = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
    let mut output = Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_dim], backend.clone());

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        output.assume_init();
        let args = args!(output.as_mut_ptr(), circuit.as_ptr());
        backend
            .launch_kernel(jagged_sum_as_poly(), grid_dim, BLOCK_SIZE, &args, shared_mem)
            .unwrap();
    }

    let output = DeviceTensor::from_raw(output);
    let tensor = output.sum_dim(1).to_host().unwrap();
    let [eval_zero, eval_half] = tensor.as_slice().try_into().unwrap();

    let eval_one = claim - eval_zero;

    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[eval_zero, eval_one, eval_half * Ext::from_canonical_u16(4).inverse()],
    )
}

/// Fix the last variable of the first gkr layer.
fn fix_and_sum_first_round<'a>(
    poly: JaggedFirstRoundPoly<'a>,
    alpha: Ext,
    claim: Ext,
) -> (UnivariatePolynomial<Ext>, Mle<Ext, TaskScope>, Mle<Ext, TaskScope>) {
    let backend = poly.base.backend();
    let height = poly.height;

    // Create a new layer
    let mut output_p: Tensor<Ext, TaskScope> = Tensor::with_sizes_in([1, height], backend.clone());
    let mut output_q: Tensor<Ext, TaskScope> = Tensor::with_sizes_in([1, height], backend.clone());

    // populate the new layer
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE * 2); // * 2 because we are doing 2 fixes per thread.
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_size_x], backend.clone());
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        output_p.assume_init();
        output_q.assume_init();
        evaluations.assume_init();
        let args = args!(
            evaluations.as_mut_ptr(),
            poly.as_ptr(),
            output_p.as_mut_ptr(),
            output_q.as_mut_ptr(),
            alpha
        );
        backend
            .launch_kernel(jagged_fix_and_sum(), grid_size, block_dim, &args, shared_mem)
            .unwrap();
    }

    // Sum the evaluations across all dimensions.
    let evaluations = DeviceTensor::from_raw(evaluations);
    let evaluations = evaluations.sum_dim(1).to_host().unwrap();
    let [eval_zero, eval_half] = evaluations.as_slice().try_into().unwrap();

    let eval_one = claim - eval_zero;

    let uni_poly = interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[eval_zero, eval_one, eval_half * Ext::from_canonical_u16(4).inverse()],
    );

    (uni_poly, Mle::new(output_p), Mle::new(output_q))
}

/// Process a univariate polynomial by observing it with the challenger and sampling the next evaluation point
#[inline]
fn process_univariate_polynomial<C>(
    uni_poly: UnivariatePolynomial<Ext>,
    challenger: &mut C,
    univariate_poly_msgs: &mut Vec<UnivariatePolynomial<Ext>>,
    point: &mut Vec<Ext>,
) -> Ext
where
    C: FieldChallenger<Felt>,
{
    let coefficients =
        uni_poly.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();
    challenger.observe_slice(&coefficients);
    univariate_poly_msgs.push(uni_poly);
    let alpha: Ext = challenger.sample_ext_element();
    point.insert(0, alpha);
    alpha
}

pub fn jagged_sumcheck<C>(
    poly: JaggedFirstRoundPoly<'_>,
    challenger: &mut C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
{
    let num_variables = poly.total_number_of_variables;

    // The first round will process the first t variables, so we need to ensure that there are at least t variables.
    assert!(num_variables >= 1_u32);

    // The point at which the reduced sumcheck proof should be evaluated.
    let mut point = vec![];

    // The univariate poly messages.  This will be a rlc of the polys' univariate polys.
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<Ext>> = vec![];

    let uni_poly = sum_as_poly_first_round(&poly, claim);

    let alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);
    let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);

    let (mut uni_poly, mut p, mut q) = fix_and_sum_first_round(poly, alpha, round_claim);

    let mut alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);

    for _ in 2..num_variables as usize {
        // Get the round claims from the last round's univariate poly messages.
        let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);

        (p, q, uni_poly) = fix_last_variable_and_sum_as_poly(
            p,
            q,
            alpha,
            round_claim,
            padded_hadamard_fix_and_sum,
        );

        alpha = process_univariate_polynomial(
            uni_poly,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
    }

    let (p, q) =
        fix_last_variable(p, q, alpha, mle_fix_last_variable_koala_bear_ext_ext_zero_padding);

    let proof = PartialSumcheckProof {
        univariate_polys: univariate_poly_msgs.clone(),
        claimed_sum: claim,
        point_and_eval: (
            point.clone().into(),
            univariate_poly_msgs.last().unwrap().eval_at_point(alpha),
        ),
    };
    let p_eval_tensor = DeviceTensor::copy_to_host(p.guts()).unwrap();
    let p_eval = Ext::from_base(p_eval_tensor.as_slice()[0]);
    let q_eval_tensor = DeviceTensor::copy_to_host(q.guts()).unwrap();
    let q_eval = q_eval_tensor.as_slice()[0];

    (proof, vec![p_eval, q_eval])
}

#[cfg(test)]
mod tests {
    /// TODO(sync): This test requires async trait implementations (IntoDevice, MleEvaluationBackend,
    /// PartialLagrangeBackend) for TaskScope that were removed in the sync refactor.
    /// The test body is commented out because #[ignore] doesn't prevent compilation.
    #[tokio::test]
    #[ignore = "requires async trait implementations for TaskScope"]
    async fn test_jagged_sumcheck_poly() {
        // Test body commented out - requires async trait implementations that were removed.
        // See the git history for the original test implementation.
    }
}
