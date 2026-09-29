use sp1_gpu_cudart::{
    args,
    sys::kernels::{
        hadamard_sum_as_poly_ext_ext_kernel, jagged_two_round_fix_and_sum,
        jagged_two_round_sum_as_poly, mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
        padded_hadamard_fix_and_two_round_sum, padded_hadamard_two_round_fix_and_two_round_sum,
    },
    DeviceBuffer, DeviceMle, DeviceTensor, TaskScope,
};

use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, Field,
    UnivariatePolynomial,
};
use slop_alloc::{Backend, HasBackend};
use slop_challenger::FieldChallenger;
use slop_multilinear::{Mle, MleBaseBackend};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;

use sp1_gpu_utils::{DenseData, Ext, Felt, JaggedTraceMle};

use super::hadamard::{fix_last_variable, sum_in_last_variable};

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

/// One-pass evaluation of the two-round polynomial `h(X, Y) = Σ_i p(i, X, Y)·q(i, X, Y)`
/// on the grid `{0, 1, ½}²`, where `Y` is the round-1 variable and `X` the round-2
/// variable. Returns the 8 accumulated grid values in the kernel's order — `h(1, 1)` is
/// omitted, since the caller deduces it from the round claim. Midpoint entries carry the
/// unscaled pair sums (`4·h`, and `16·h` for the center); the caller descales.
fn two_round_sum_as_poly<'a>(poly: &JaggedFirstRoundPoly<'a>) -> [Ext; 8] {
    let backend = poly.base.backend();
    let height = poly.height;
    // The kernel consumes two dense pairs per iteration with no bounds checks.
    assert_eq!(height % 2, 0, "the jagged poly height must be a multiple of 2");

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE * 2); // * 2 because each iteration handles 2 pairs.
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([8, grid_size_x], backend.clone());

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        evaluations.assume_init();
        let args = args!(evaluations.as_mut_ptr(), poly.as_ptr());
        backend
            .launch_kernel(
                jagged_two_round_sum_as_poly(),
                grid_size_x,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }

    // Sum the per-block partial sums of each grid value.
    let evaluations = DeviceTensor::from_raw(evaluations);
    let evaluations = evaluations.sum_dim(1).to_host().unwrap();
    evaluations.as_slice().try_into().unwrap()
}

fn fix_last_variable_and_two_round_sum(
    p: Mle<Ext, TaskScope>,
    q: Mle<Ext, TaskScope>,
    alpha: Ext,
) -> (Mle<Ext, TaskScope>, Mle<Ext, TaskScope>, [Ext; 8]) {
    let backend = p.backend();
    let input_height = p.guts().sizes()[1];
    debug_assert_eq!(q.guts().sizes()[1], input_height);
    let output_height = input_height.div_ceil(2);

    let mut p_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    let mut q_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    const BLOCK_SIZE: usize = 256;
    let grid_size_x = output_height.div_ceil(4).div_ceil(BLOCK_SIZE);
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([8, grid_size_x], backend.clone());
    let shared_mem = (BLOCK_SIZE / 32) * std::mem::size_of::<Ext>();

    unsafe {
        p_output.assume_init();
        q_output.assume_init();
        evaluations.assume_init();
        let args = args!(
            p.guts().as_ptr(),
            q.guts().as_ptr(),
            p_output.as_mut_ptr(),
            q_output.as_mut_ptr(),
            alpha,
            evaluations.as_mut_ptr(),
            input_height
        );
        backend
            .launch_kernel(
                padded_hadamard_fix_and_two_round_sum(),
                grid_size_x,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }

    let evaluations = DeviceTensor::from_raw(evaluations).sum_dim(1).to_host().unwrap();
    (Mle::new(p_output), Mle::new(q_output), evaluations.as_slice().try_into().unwrap())
}

fn two_round_second_univariate(
    grid: [Ext; 8],
    alpha_1: Ext,
    round_claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let [h_0_0, h_0_1, h_0_half, _, _, h_half_0, h_half_1, h_half_half] = grid;
    let half = Ext::from_canonical_u16(2).inverse();
    let quarter = Ext::from_canonical_u16(4).inverse();
    let grid_points = [Ext::zero(), Ext::one(), half];
    let column_at_alpha_1 = |h_x_0: Ext, h_x_1: Ext, h_x_half: Ext| {
        interpolate_univariate_polynomial(&grid_points, &[h_x_0, h_x_1, h_x_half])
            .eval_at_point(alpha_1)
    };
    let eval_zero = column_at_alpha_1(h_0_0, h_0_1, h_0_half * quarter);
    let eval_half =
        column_at_alpha_1(h_half_0 * quarter, h_half_1 * quarter, h_half_half * quarter * quarter);

    interpolate_univariate_polynomial(
        &grid_points,
        &[eval_zero, round_claim - eval_zero, eval_half],
    )
}

fn two_round_first_univariate(grid: [Ext; 8], claim: Ext) -> UnivariatePolynomial<Ext> {
    let [h_0_0, h_0_1, h_0_half, h_1_0, h_1_half, _, _, _] = grid;
    let half = Ext::from_canonical_u16(2).inverse();
    let quarter = Ext::from_canonical_u16(4).inverse();
    let h_1_1 = claim - h_0_0 - h_0_1 - h_1_0;
    interpolate_univariate_polynomial(
        &[Ext::zero(), Ext::one(), half],
        &[h_0_0 + h_1_0, h_0_1 + h_1_1, (h_0_half + h_1_half) * quarter],
    )
}

fn process_two_round_grid<C: FieldChallenger<Felt>>(
    grid: [Ext; 8],
    claim: Ext,
    challenger: &mut C,
    univariate_poly_msgs: &mut Vec<UnivariatePolynomial<Ext>>,
    point: &mut Vec<Ext>,
) -> (Ext, Ext, Ext) {
    let uni_poly = two_round_first_univariate(grid, claim);
    let alpha_1 = process_univariate_polynomial(uni_poly, challenger, univariate_poly_msgs, point);
    let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha_1);
    let uni_poly = two_round_second_univariate(grid, alpha_1, round_claim);
    let alpha_2 = process_univariate_polynomial(uni_poly, challenger, univariate_poly_msgs, point);
    let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha_2);
    (alpha_1, alpha_2, round_claim)
}

#[cfg(debug_assertions)]
fn assert_two_round_grid(
    p: &Mle<Ext, TaskScope>,
    q: &Mle<Ext, TaskScope>,
    grid: [Ext; 8],
    claim: Ext,
    folds_done: usize,
) {
    if p.num_variables() == 0 {
        return;
    }
    let expected = sum_in_last_variable(p, q, claim, hadamard_sum_as_poly_ext_ext_kernel);
    assert_eq!(
        two_round_first_univariate(grid, claim),
        expected,
        "paired grid mismatch after {folds_done} folds"
    );
}

fn fix_last_two_variables_and_two_round_sum(
    p: Mle<Ext, TaskScope>,
    q: Mle<Ext, TaskScope>,
    alpha_1: Ext,
    alpha_2: Ext,
) -> (Mle<Ext, TaskScope>, Mle<Ext, TaskScope>, [Ext; 8]) {
    let backend = p.backend();
    let input_height = p.guts().sizes()[1];
    debug_assert_eq!(q.guts().sizes()[1], input_height);
    let output_height = input_height.div_ceil(4);

    let mut p_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    let mut q_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    const BLOCK_SIZE: usize = 256;
    let grid_size_x = output_height.div_ceil(4).div_ceil(BLOCK_SIZE);
    let shared_mem = (BLOCK_SIZE / 32) * std::mem::size_of::<Ext>();
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([8, grid_size_x], backend.clone());

    unsafe {
        p_output.assume_init();
        q_output.assume_init();
        evaluations.assume_init();
        let args = args!(
            p.guts().as_ptr(),
            q.guts().as_ptr(),
            p_output.as_mut_ptr(),
            q_output.as_mut_ptr(),
            alpha_1,
            alpha_2,
            evaluations.as_mut_ptr(),
            input_height
        );
        backend
            .launch_kernel(
                padded_hadamard_two_round_fix_and_two_round_sum(),
                grid_size_x,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }

    let evaluations = DeviceTensor::from_raw(evaluations).sum_dim(1).to_host().unwrap();
    (Mle::new(p_output), Mle::new(q_output), evaluations.as_slice().try_into().unwrap())
}

/// Fold the first two sumcheck challenges into the jagged first-round poly in a single
/// pass, materializing `(p, q)` at a quarter of the dense size. The same pass
/// computes the bivariate grid for the next two rounds.
fn fix_two_and_sum_first_rounds<'a>(
    poly: JaggedFirstRoundPoly<'a>,
    alpha_1: Ext,
    alpha_2: Ext,
) -> ([Ext; 8], Mle<Ext, TaskScope>, Mle<Ext, TaskScope>) {
    let backend = poly.base.backend();
    let height = poly.height;
    // The kernel folds eight consecutive dense pairs per output quad with no bounds checks.
    assert_eq!(height % 8, 0, "the jagged poly height must be a multiple of 8");

    // Create the doubly-folded layer.
    let output_height = height >> 1;
    let mut output_p: Tensor<Ext, TaskScope> =
        Tensor::with_sizes_in([1, output_height], backend.clone());
    let mut output_q: Tensor<Ext, TaskScope> =
        Tensor::with_sizes_in([1, output_height], backend.clone());

    // populate the new layer
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE * 8);
    let mut evaluations =
        Tensor::<Ext, TaskScope>::with_sizes_in([8, grid_size_x], backend.clone());

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
            alpha_1,
            alpha_2
        );
        backend
            .launch_kernel(
                jagged_two_round_fix_and_sum(),
                grid_size_x,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }

    // Sum the evaluations across all dimensions.
    let evaluations = DeviceTensor::from_raw(evaluations);
    let evaluations = evaluations.sum_dim(1).to_host().unwrap();
    (evaluations.as_slice().try_into().unwrap(), Mle::new(output_p), Mle::new(output_q))
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

/// Runs the jagged sumcheck. In addition to the sumcheck proof, also returns intermediately-computed
/// evals needed for the later stacked PCS. This requires passing in the log stacking height
pub fn jagged_sumcheck<C>(
    poly: JaggedFirstRoundPoly<'_>,
    challenger: &mut C,
    claim: Ext,
    log_stacking_height: usize,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>, DeviceBuffer<Ext>)
where
    C: FieldChallenger<Felt>,
{
    let num_variables = poly.total_number_of_variables;
    let task = poly.base.backend().clone();

    // The first pair uses the jagged trace layout. Later pairs use dense
    // extension-field MLEs after the stacked PCS snapshot.
    assert!(num_variables >= 3_u32);
    assert!(log_stacking_height >= 3, "stacked evals are snapshotted inside the round loop");
    assert!(log_stacking_height < num_variables as usize);

    // The point at which the reduced sumcheck proof should be evaluated.
    let mut point = vec![];

    // The univariate poly messages.  This will be a rlc of the polys' univariate polys.
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<Ext>> = vec![];

    // A single pass over the trace yields the two-round polynomial
    // `h(X, Y) = Σ_i p(i, X, Y)·q(i, X, Y)` on the grid `{0, 1, ½}²`, from which the
    // first two round messages are derived on the host with no further device work.
    let grid = two_round_sum_as_poly(&poly);
    let [h_0_0, h_0_1, h_0_half, h_1_0, h_1_half, _, _, _] = grid;

    // Descale the midpoint accumulators and deduce `h(1, 1)` from the claim.
    let quarter = Ext::from_canonical_u16(4).inverse();
    let h_0_half = h_0_half * quarter;
    let h_1_half = h_1_half * quarter;
    let h_1_1 = claim - h_0_0 - h_0_1 - h_1_0;

    let grid_points = [
        Ext::from_canonical_u16(0),
        Ext::from_canonical_u16(1),
        Ext::from_canonical_u16(2).inverse(),
    ];

    // Round 1: `g₁(Y) = h(0, Y) + h(1, Y)`.
    let uni_poly = interpolate_univariate_polynomial(
        &grid_points,
        &[h_0_0 + h_1_0, h_0_1 + h_1_1, h_0_half + h_1_half],
    );
    let alpha_1 =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);

    let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha_1);
    let uni_poly = two_round_second_univariate(grid, alpha_1, round_claim);
    let alpha_2 =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);
    let mut round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha_2);

    // The data polynomial is p and the jagged polynomial is q, materialized after folding
    // both challenges in a single pass over the trace.
    let (mut grid, mut p, mut q) = fix_two_and_sum_first_rounds(poly, alpha_1, alpha_2);

    let mut stacked_evals =
        DeviceBuffer::with_capacity_in(1 << (num_variables as usize - log_stacking_height), task);
    let mut folds_done = 2;

    #[cfg(debug_assertions)]
    assert_two_round_grid(&p, &q, grid, round_claim, folds_done);

    while folds_done + 2 <= log_stacking_height {
        let (alpha_1, alpha_2, next_claim) = process_two_round_grid(
            grid,
            round_claim,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
        (p, q, grid) = fix_last_two_variables_and_two_round_sum(p, q, alpha_1, alpha_2);
        round_claim = next_claim;
        folds_done += 2;
        #[cfg(debug_assertions)]
        assert_two_round_grid(&p, &q, grid, round_claim, folds_done);
    }

    if folds_done < log_stacking_height {
        let uni_poly = two_round_first_univariate(grid, round_claim);
        let alpha = process_univariate_polynomial(
            uni_poly,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
        round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);
        (p, q, grid) = fix_last_variable_and_two_round_sum(p, q, alpha);
        folds_done += 1;
        #[cfg(debug_assertions)]
        assert_two_round_grid(&p, &q, grid, round_claim, folds_done);
    }

    debug_assert_eq!(folds_done, log_stacking_height);
    stacked_evals.extend_from_device_slice(p.guts().as_buffer()).unwrap();

    let mut remaining = num_variables as usize - folds_done;
    while remaining >= 2 {
        let (alpha_1, alpha_2, next_claim) = process_two_round_grid(
            grid,
            round_claim,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
        (p, q, grid) = fix_last_two_variables_and_two_round_sum(p, q, alpha_1, alpha_2);
        round_claim = next_claim;
        remaining -= 2;
        #[cfg(debug_assertions)]
        assert_two_round_grid(&p, &q, grid, round_claim, num_variables as usize - remaining);
    }

    if remaining == 1 {
        let uni_poly = two_round_first_univariate(grid, round_claim);
        let alpha = process_univariate_polynomial(
            uni_poly,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
        round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);
        (p, q) =
            fix_last_variable(p, q, alpha, mle_fix_last_variable_koala_bear_ext_ext_zero_padding);
    }

    let proof = PartialSumcheckProof {
        univariate_polys: univariate_poly_msgs.clone(),
        claimed_sum: claim,
        point_and_eval: (point.clone().into(), round_claim),
    };
    let p_eval_tensor = DeviceTensor::copy_to_host(p.guts()).unwrap();
    let p_eval = Ext::from_base(p_eval_tensor.as_slice()[0]);
    let q_eval_tensor = DeviceTensor::copy_to_host(q.guts()).unwrap();
    let q_eval = q_eval_tensor.as_slice()[0];

    (proof, vec![p_eval, q_eval], stacked_evals)
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
