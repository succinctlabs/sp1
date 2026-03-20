use itertools::Itertools;
use num_bigint::BigUint;
use slop_algebra::{interpolate_univariate_polynomial, AbstractField, Field};
use slop_algebra::{AbstractExtensionField, UnivariatePolynomial};
use slop_challenger::FieldChallenger;
use slop_multilinear::Mle;
use slop_multilinear::MleBaseBackend;
use sp1_gpu_challenger::FromHostChallengerSync;
use sp1_gpu_cudart::sys::runtime::Dim3;
use sp1_gpu_cudart::sys::runtime::KernelPtr;
use sp1_gpu_cudart::sys::sumcheck::{
    sumcheck_observe_and_sample_quadratic_duplex,
    sumcheck_observe_and_sample_quadratic_multi_field_32,
};
use sp1_gpu_cudart::sys::v2_kernels::hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel;
use sp1_gpu_cudart::sys::v2_kernels::hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel;
use sp1_gpu_cudart::sys::v2_kernels::hadamard_sum_as_poly_base_ext_kernel;
use sp1_gpu_cudart::sys::v2_kernels::hadamard_sum_as_poly_ext_ext_kernel;
use sp1_gpu_cudart::sys::v2_kernels::mle_fix_last_variable_koala_bear_ext_ext_zero_padding;
use sp1_gpu_cudart::sys::v2_kernels::padded_hadamard_fix_and_sum;
use sp1_gpu_cudart::TaskScope;
use sp1_gpu_cudart::{args, DeviceBuffer, DeviceTensor};
use sp1_gpu_utils::{Ext, Felt};

use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;

/// Trait for types that can provide a mutable raw pointer representation for GPU kernels.
/// This mirrors the `AsMutRawChallenger` trait from jagged_assist.
pub trait AsMutRawChallenger {
    type ChallengerRawMut;

    fn as_mut_raw(&mut self) -> Self::ChallengerRawMut;
}

impl<F> AsMutRawChallenger for sp1_gpu_challenger::DuplexChallenger<F, TaskScope> {
    type ChallengerRawMut = sp1_gpu_challenger::DuplexChallengerRawMut<F>;

    fn as_mut_raw(&mut self) -> Self::ChallengerRawMut {
        sp1_gpu_challenger::DuplexChallenger::as_mut_raw(self)
    }
}

impl<F, PF> AsMutRawChallenger for sp1_gpu_challenger::MultiField32Challenger<F, PF, TaskScope> {
    type ChallengerRawMut = sp1_gpu_challenger::MultiField32ChallengerRawMut<F, PF>;

    fn as_mut_raw(&mut self) -> Self::ChallengerRawMut {
        sp1_gpu_challenger::MultiField32Challenger::as_mut_raw(self)
    }
}

/// Trait for selecting the appropriate GPU observe-and-sample kernel based on challenger type.
///
/// # Safety
///
/// The kernel pointer returned must match the challenger type's raw representation.
pub unsafe trait ObserveAndSampleKernel {
    fn observe_and_sample_quadratic_kernel() -> KernelPtr;
}

unsafe impl<F> ObserveAndSampleKernel for sp1_gpu_challenger::DuplexChallenger<F, TaskScope> {
    fn observe_and_sample_quadratic_kernel() -> KernelPtr {
        unsafe { sumcheck_observe_and_sample_quadratic_duplex() }
    }
}

unsafe impl<F, PF> ObserveAndSampleKernel
    for sp1_gpu_challenger::MultiField32Challenger<F, PF, TaskScope>
{
    fn observe_and_sample_quadratic_kernel() -> KernelPtr {
        unsafe { sumcheck_observe_and_sample_quadratic_multi_field_32() }
    }
}

/// Generic helper for sum in last variable operations.
fn sum_in_last_variable<F>(
    poly_base: &Mle<F, TaskScope>,
    poly_ext: &Mle<Ext, TaskScope>,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> UnivariatePolynomial<Ext>
where
    F: Field,
{
    let num_variables = poly_base.num_variables();
    let num_polys = poly_base.num_polynomials();
    let scope = poly_base.backend();

    debug_assert!(num_variables >= 1);
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;

    let output_height = 1usize << (num_variables - 1);

    let grid_dim: Dim3 = (output_height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE), num_polys, 1).into();

    let mut univariate_evals = Tensor::<Ext, TaskScope>::with_sizes_in(
        [2, grid_dim.y as usize, grid_dim.x as usize],
        scope.clone(),
    );
    let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();
    let num_variables_minus_one: usize = num_variables as usize - 1;
    unsafe {
        let args = args!(
            univariate_evals.as_mut_ptr(),
            poly_base.guts().as_ptr(),
            poly_ext.guts().as_ptr(),
            num_variables_minus_one,
            num_polys
        );
        univariate_evals.assume_init();
        scope.launch_kernel(kernel(), grid_dim, BLOCK_SIZE, &args, shared_mem).unwrap();
    }
    let univariate_evals = DeviceTensor::from_raw(univariate_evals);
    let univariate_evals = univariate_evals.sum_dim(2).sum_dim(1);
    let host_evals = univariate_evals.to_host().unwrap();
    let [component_eval_zero, component_eval_half] = host_evals.as_slice().try_into().unwrap();
    let eval_zero = component_eval_zero;
    let eval_half = component_eval_half;

    let eval_one = claim - eval_zero;

    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[eval_zero, eval_one, eval_half * Felt::from_canonical_u16(4).inverse()],
    )
}

/// Like `sum_in_last_variable`, but returns the reduced evals as a device tensor
/// with shape [2] containing [eval_zero, eval_half] instead of interpolating on CPU.
/// Used by the GPU challenger path.
fn sum_in_last_variable_device<F>(
    poly_base: &Mle<F, TaskScope>,
    poly_ext: &Mle<Ext, TaskScope>,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> DeviceTensor<Ext>
where
    F: Field,
{
    let num_variables = poly_base.num_variables();
    let num_polys = poly_base.num_polynomials();
    let scope = poly_base.backend();

    debug_assert!(num_variables >= 1);
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;

    let output_height = 1usize << (num_variables - 1);

    let grid_dim: Dim3 = (output_height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE), num_polys, 1).into();

    let mut univariate_evals = Tensor::<Ext, TaskScope>::with_sizes_in(
        [2, grid_dim.y as usize, grid_dim.x as usize],
        scope.clone(),
    );
    let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();
    let num_variables_minus_one: usize = num_variables as usize - 1;
    unsafe {
        let args = args!(
            univariate_evals.as_mut_ptr(),
            poly_base.guts().as_ptr(),
            poly_ext.guts().as_ptr(),
            num_variables_minus_one,
            num_polys
        );
        univariate_evals.assume_init();
        scope.launch_kernel(kernel(), grid_dim, BLOCK_SIZE, &args, shared_mem).unwrap();
    }
    let univariate_evals = DeviceTensor::from_raw(univariate_evals);
    // Reduce to shape [2] (eval_zero, eval_half) on device.
    univariate_evals.sum_dim(2).sum_dim(1)
}

pub fn fix_last_variable<F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    alpha: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (Mle<Ext, TaskScope>, Mle<Ext, TaskScope>)
where
    F: Field,
{
    let base = fix_last_variable_inner(&base, alpha, kernel);
    let ext =
        fix_last_variable_inner(&ext, alpha, mle_fix_last_variable_koala_bear_ext_ext_zero_padding);

    (base, ext)
}

fn fix_last_variable_inner<F>(
    mle: &Mle<F, TaskScope>,
    alpha: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> Mle<Ext, TaskScope>
where
    F: Field,
{
    let num_polynomials = 1;
    let input_height = mle.guts().sizes()[1];
    assert!(input_height > 0);
    let output_height = input_height.div_ceil(2);
    let mut output: Tensor<Ext, TaskScope> =
        mle.backend().uninit_mle(num_polynomials, output_height);

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;
    let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE);
    let grid_size_y = num_polynomials;
    let grid_size = (grid_size_x, grid_size_y, 1);

    let args =
        args!(mle.guts().as_ptr(), output.as_mut_ptr(), alpha, input_height, num_polynomials);

    unsafe {
        output.assume_init();
        mle.backend().launch_kernel(kernel(), grid_size, BLOCK_SIZE, &args, 0).unwrap();
    }

    Mle::new(output)
}

// returns (base_output, ext_output, next_univariate)
pub fn fix_last_variable_and_sum_as_poly<F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    alpha: Ext,
    claim: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (Mle<Ext, TaskScope>, Mle<Ext, TaskScope>, UnivariatePolynomial<Ext>)
where
    F: Field,
{
    let input_height = base.guts().sizes()[1];
    let output_height = input_height.div_ceil(2);
    let backend = base.backend();
    let mut base_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    let mut ext_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;

    let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE);

    let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    let mut univariate_evals =
        Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_size_x], backend.clone());

    unsafe {
        let null_ptr: *mut Ext = std::ptr::null_mut();
        let args = args!(
            base.guts().as_ptr(),
            ext.guts().as_ptr(),
            base_output.as_mut_ptr(),
            ext_output.as_mut_ptr(),
            alpha,
            univariate_evals.as_mut_ptr(),
            input_height,
            null_ptr
        );
        univariate_evals.assume_init();
        base_output.assume_init();
        ext_output.assume_init();
        backend.launch_kernel(kernel(), grid_size_x, BLOCK_SIZE, &args, shared_mem).unwrap();
    }

    // Sum the univariate evals and interpolate into a degree-2 univariate
    let univariate_evals = DeviceTensor::from_raw(univariate_evals);
    let host_evals = univariate_evals.sum_dim(1).to_host().unwrap();

    let [component_eval_zero, component_eval_half] = host_evals.as_slice().try_into().unwrap();
    let eval_zero = component_eval_zero;
    let eval_half = component_eval_half;

    let eval_one = claim - eval_zero;

    let uni_poly = interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
        ],
        &[eval_zero, eval_one, eval_half * Felt::from_canonical_u16(4).inverse()],
    );

    (Mle::new(base_output), Mle::new(ext_output), uni_poly)
}

/// Like `fix_last_variable_and_sum_as_poly`, but returns the reduced evals as a device tensor
/// with shape [2] containing [eval_zero, eval_half] instead of interpolating on CPU.
/// Used by the GPU challenger path.
pub(crate) fn fix_last_variable_and_sum_as_poly_device<F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    alpha: Ext,
    kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (Mle<Ext, TaskScope>, Mle<Ext, TaskScope>, DeviceTensor<Ext>)
where
    F: Field,
{
    let input_height = base.guts().sizes()[1];
    let output_height = input_height.div_ceil(2);
    let backend = base.backend();
    let mut base_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);
    let mut ext_output: Tensor<Ext, TaskScope> = backend.uninit_mle(1, output_height);

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 1;

    let grid_size_x = output_height.div_ceil(BLOCK_SIZE * STRIDE);

    let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    let mut univariate_evals =
        Tensor::<Ext, TaskScope>::with_sizes_in([2, grid_size_x], backend.clone());

    unsafe {
        let null_ptr: *mut Ext = std::ptr::null_mut();
        let args = args!(
            base.guts().as_ptr(),
            ext.guts().as_ptr(),
            base_output.as_mut_ptr(),
            ext_output.as_mut_ptr(),
            alpha,
            univariate_evals.as_mut_ptr(),
            input_height,
            null_ptr
        );
        univariate_evals.assume_init();
        base_output.assume_init();
        ext_output.assume_init();
        backend.launch_kernel(kernel(), grid_size_x, BLOCK_SIZE, &args, shared_mem).unwrap();
    }

    // Reduce to shape [2] (eval_zero, eval_half) on device, don't transfer to host.
    let univariate_evals = DeviceTensor::from_raw(univariate_evals);
    let reduced_evals = univariate_evals.sum_dim(1);

    (Mle::new(base_output), Mle::new(ext_output), reduced_evals)
}

/// Launch the GPU observe-and-sample kernel for a quadratic sumcheck round.
///
/// This single-thread kernel reads the reduced evals [eval_zero, eval_half] from device memory,
/// performs interpolation, observes the polynomial coefficients with the device challenger,
/// samples alpha, evaluates p(alpha) for next_claim, and writes alpha + next_claim to device
/// buffers.
pub(crate) fn launch_observe_and_sample<DC: AsMutRawChallenger + ObserveAndSampleKernel>(
    reduced_evals: &DeviceTensor<Ext>,
    device_challenger: &mut DC,
    alpha_buf: &mut DeviceBuffer<Ext>,
    next_claim_buf: &mut DeviceBuffer<Ext>,
    claim: Ext,
    backend: &TaskScope,
) {
    let challenger_raw = device_challenger.as_mut_raw();
    unsafe {
        let args = args!(
            reduced_evals.as_ptr(),
            challenger_raw,
            alpha_buf.as_mut_ptr(),
            claim,
            next_claim_buf.as_mut_ptr()
        );
        backend
            .launch_kernel(DC::observe_and_sample_quadratic_kernel(), 1usize, 1usize, &args, 0)
            .unwrap();
    }
}

/// A simpler hadamard sumcheck. Avoids using the complex slop traits, and prioritizes a simple,
/// readable implementation.
pub fn hadamard_sumcheck<C, F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    mut challenger: C,
    initial_claim: Ext,
    base_ext_sum_as_poly_kernel: unsafe extern "C" fn() -> KernelPtr,
    base_ext_fix_and_sum_kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    F: Field,
{
    let mut uni_polys = vec![];
    let initial_univariate =
        sum_in_last_variable::<F>(&base, &ext, initial_claim, base_ext_sum_as_poly_kernel);
    let coefficients = initial_univariate
        .coefficients
        .iter()
        .flat_map(|x| x.as_base_slice())
        .copied()
        .collect_vec();
    challenger.observe_slice(&coefficients);

    uni_polys.push(initial_univariate);

    let num_variables = base.num_variables();

    let alpha = challenger.sample_ext_element();

    let mut point = vec![alpha];

    // For the first round, use base-ext kernels.
    let round_claim = uni_polys.last().unwrap().eval_at_point(*point.first().unwrap());
    let (mut base, mut ext, uni_poly) = fix_last_variable_and_sum_as_poly(
        base,
        ext,
        alpha,
        round_claim,
        base_ext_fix_and_sum_kernel,
    );

    let coefficients =
        uni_poly.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();

    challenger.observe_slice(&coefficients);

    uni_polys.push(uni_poly);

    let alpha: Ext = challenger.sample_ext_element();
    point.insert(0, alpha);

    // The multi-variate polynomial used at the start of each sumcheck round.
    for _ in 2..num_variables as usize {
        // Get the round claims from the last round's univariate poly messages.
        let round_claim = uni_polys.last().unwrap().eval_at_point(*point.first().unwrap());

        let uni_poly;
        (base, ext, uni_poly) = fix_last_variable_and_sum_as_poly(
            base,
            ext,
            *point.first().unwrap(),
            round_claim,
            padded_hadamard_fix_and_sum,
        );

        let coefficients =
            uni_poly.coefficients.iter().flat_map(|x| x.as_base_slice()).copied().collect_vec();

        challenger.observe_slice(&coefficients);

        uni_polys.push(uni_poly);

        let alpha: Ext = challenger.sample_ext_element();
        point.insert(0, alpha);
    }

    // Perform the final fix last variable operation to get the final base and extension evaluations.
    let (base, ext) = fix_last_variable(
        base,
        ext,
        *point.first().unwrap(),
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    );

    let proof = PartialSumcheckProof {
        univariate_polys: uni_polys.clone(),
        claimed_sum: initial_claim,
        point_and_eval: (
            point.clone().into(),
            uni_polys.last().unwrap().eval_at_point(*point.first().unwrap()),
        ),
    };
    let base_eval_tensor = DeviceTensor::copy_to_host(base.guts()).unwrap();
    let base_eval = Ext::from_base(base_eval_tensor.as_slice()[0]);
    let ext_eval_tensor = DeviceTensor::copy_to_host(ext.guts()).unwrap();
    let ext_eval = ext_eval_tensor.as_slice()[0];
    (proof, vec![base_eval, ext_eval])
}

/// Hadamard sumcheck with GPU-side Fiat-Shamir challenger.
///
/// Instead of transferring polynomial evaluations to the CPU for interpolation and challenger
/// operations each round, this keeps the reduced evals on device and launches a single-thread
/// GPU kernel that does interpolation + observe + sample. Only the resulting alpha (16 bytes)
/// and next_claim (16 bytes) are transferred D2H per round.
///
/// The reduced eval device tensors are saved during the main loop and batch-transferred to CPU
/// at the end to reconstruct the polynomial coefficients. The CPU challenger state is then
/// synced via transcript replay.
#[allow(clippy::too_many_arguments)]
pub fn hadamard_sumcheck_gpu_challenger<C, F, DC>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    challenger: &mut C,
    initial_claim: Ext,
    base_ext_sum_as_poly_kernel: unsafe extern "C" fn() -> KernelPtr,
    base_ext_fix_and_sum_kernel: unsafe extern "C" fn() -> KernelPtr,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    F: Field,
    DC: AsMutRawChallenger + ObserveAndSampleKernel + FromHostChallengerSync<C>,
{
    let num_variables = base.num_variables();
    let backend = base.backend().clone();

    // Create device challenger from the current CPU challenger state.
    let mut device_challenger = DC::from_host_challenger_sync(challenger, &backend);

    // Allocate reusable device buffers for alpha and next_claim (16 bytes each).
    let mut alpha_buf = DeviceBuffer::<Ext>::with_capacity_in(1, backend.clone());
    let mut next_claim_buf = DeviceBuffer::<Ext>::with_capacity_in(1, backend.clone());
    unsafe {
        alpha_buf.set_len(1);
        next_claim_buf.set_len(1);
    }

    // Save reduced evals device tensors for batch D2H at the end.
    let mut saved_reduced_evals: Vec<DeviceTensor<Ext>> =
        Vec::with_capacity(num_variables as usize);

    let mut point: Vec<Ext> = Vec::with_capacity(num_variables as usize);
    let mut claim = initial_claim;

    // --- Round 0: sum_in_last_variable (first round, base-ext kernel) ---
    let reduced_evals = sum_in_last_variable_device::<F>(&base, &ext, base_ext_sum_as_poly_kernel);

    launch_observe_and_sample(
        &reduced_evals,
        &mut device_challenger,
        &mut alpha_buf,
        &mut next_claim_buf,
        claim,
        &backend,
    );

    saved_reduced_evals.push(reduced_evals);

    let alpha = alpha_buf.to_host().unwrap()[0];
    claim = next_claim_buf.to_host().unwrap()[0];
    point.push(alpha);

    // --- Round 1: fix_last_variable_and_sum_as_poly (first round, base-ext kernel) ---
    let (mut base_mle, mut ext_mle, reduced_evals) =
        fix_last_variable_and_sum_as_poly_device(base, ext, alpha, base_ext_fix_and_sum_kernel);

    launch_observe_and_sample(
        &reduced_evals,
        &mut device_challenger,
        &mut alpha_buf,
        &mut next_claim_buf,
        claim,
        &backend,
    );

    saved_reduced_evals.push(reduced_evals);

    let alpha = alpha_buf.to_host().unwrap()[0];
    claim = next_claim_buf.to_host().unwrap()[0];
    point.insert(0, alpha);

    // --- Rounds 2..num_variables: fix_last_variable_and_sum_as_poly (padded hadamard) ---
    for _ in 2..num_variables as usize {
        let current_alpha = *point.first().unwrap();

        let reduced_evals;
        (base_mle, ext_mle, reduced_evals) = fix_last_variable_and_sum_as_poly_device(
            base_mle,
            ext_mle,
            current_alpha,
            padded_hadamard_fix_and_sum,
        );

        launch_observe_and_sample(
            &reduced_evals,
            &mut device_challenger,
            &mut alpha_buf,
            &mut next_claim_buf,
            claim,
            &backend,
        );

        saved_reduced_evals.push(reduced_evals);

        let alpha = alpha_buf.to_host().unwrap()[0];
        claim = next_claim_buf.to_host().unwrap()[0];
        point.insert(0, alpha);
    }

    // --- Batch D2H of reduced evals and reconstruct uni_polys ---
    // For each round we saved [eval_zero, eval_half] on device. Transfer and interpolate.
    let mut uni_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(num_variables as usize);

    // Replay the claim sequence: claim_0 = initial_claim, claim_{i+1} = p_i(alpha_i).
    let mut replay_claim = initial_claim;
    for (round, saved_evals) in saved_reduced_evals.iter().enumerate() {
        let host_evals = saved_evals.to_host().unwrap();
        let [eval_zero, eval_half]: [Ext; 2] = host_evals.as_slice().try_into().unwrap();

        let eval_one = replay_claim - eval_zero;

        let uni_poly = interpolate_univariate_polynomial(
            &[
                Ext::from_canonical_u16(0),
                Ext::from_canonical_u16(1),
                Ext::from_canonical_u16(2).inverse(),
            ],
            &[eval_zero, eval_one, eval_half * Felt::from_canonical_u16(4).inverse()],
        );

        // Point is [alpha_{n-1}, ..., alpha_1, alpha_0]. Alpha for round i is at
        // index (num_rounds - 1 - i).
        let num_rounds = saved_reduced_evals.len();
        let alpha = point[num_rounds - 1 - round];

        replay_claim = uni_poly.eval_at_point(alpha);

        uni_polys.push(uni_poly);
    }

    // --- Replay CPU challenger for state sync ---
    for poly in &uni_polys {
        let coefficients: Vec<Felt> =
            poly.coefficients.iter().flat_map(|c| c.as_base_slice()).copied().collect();
        challenger.observe_slice(&coefficients);
        let _: Ext = challenger.sample_ext_element();
    }

    // --- Final fix_last_variable to get evaluations ---
    let (base_final, ext_final) = fix_last_variable(
        base_mle,
        ext_mle,
        *point.first().unwrap(),
        mle_fix_last_variable_koala_bear_ext_ext_zero_padding,
    );

    let proof = PartialSumcheckProof {
        univariate_polys: uni_polys.clone(),
        claimed_sum: initial_claim,
        point_and_eval: (
            point.clone().into(),
            uni_polys.last().unwrap().eval_at_point(*point.first().unwrap()),
        ),
    };

    let base_eval_tensor = DeviceTensor::copy_to_host(base_final.guts()).unwrap();
    let base_eval = Ext::from_base(base_eval_tensor.as_slice()[0]);
    let ext_eval_tensor = DeviceTensor::copy_to_host(ext_final.guts()).unwrap();
    let ext_eval = ext_eval_tensor.as_slice()[0];

    (proof, vec![base_eval, ext_eval])
}

pub fn simple_hadamard_sumcheck<C, F>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    challenger: C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    F: Field,
{
    if F::order() > BigUint::from(0x7f000001u32) {
        hadamard_sumcheck(
            base,
            ext,
            challenger,
            claim,
            hadamard_sum_as_poly_ext_ext_kernel,
            hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel,
        )
    } else {
        hadamard_sumcheck(
            base,
            ext,
            challenger,
            claim,
            hadamard_sum_as_poly_base_ext_kernel,
            hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel,
        )
    }
}

/// Like `simple_hadamard_sumcheck` but uses GPU-side Fiat-Shamir challenger.
///
/// Takes a mutable reference to the CPU challenger rather than consuming it,
/// and syncs the challenger state at the end via transcript replay.
pub fn simple_hadamard_sumcheck_gpu_challenger<C, F, DC>(
    base: Mle<F, TaskScope>,
    ext: Mle<Ext, TaskScope>,
    challenger: &mut C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    F: Field,
    DC: AsMutRawChallenger + ObserveAndSampleKernel + FromHostChallengerSync<C>,
{
    if F::order() > BigUint::from(0x7f000001u32) {
        hadamard_sumcheck_gpu_challenger::<C, F, DC>(
            base,
            ext,
            challenger,
            claim,
            hadamard_sum_as_poly_ext_ext_kernel,
            hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel,
        )
    } else {
        hadamard_sumcheck_gpu_challenger::<C, F, DC>(
            base,
            ext,
            challenger,
            claim,
            hadamard_sum_as_poly_base_ext_kernel,
            hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel,
        )
    }
}

#[cfg(test)]
mod tests {
    /// Compares our simple hadamard sumcheck implementation with the slop implementation, which is more complicated and supports batching.
    /// TODO(sync): This test requires async trait implementations (IntoDevice, MleEvaluationBackend)
    /// for TaskScope that were removed in the sync refactor.
    /// The test body is commented out because #[ignore] doesn't prevent compilation.
    #[tokio::test]
    #[ignore = "requires async trait implementations for TaskScope"]
    async fn test_hadamard_sumcheck() {
        // Test body commented out - requires async trait implementations that were removed.
        // See the git history for the original test implementation.
    }
}
