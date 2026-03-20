//! Gkr is composed of rounds. Each round corresponds to a layer. Each round is a sumcheck.
//! For the first layer, the numerator is a base field element and the denominator over extension field elements, so it requires some special treatment.
use itertools::Itertools;
use slop_algebra::{
    interpolate_univariate_polynomial, AbstractExtensionField, AbstractField, Field,
    UnivariatePolynomial,
};
use slop_alloc::{Buffer, HasBackend};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::PartialSumcheckProof;
use slop_tensor::Tensor;
use sp1_gpu_cudart::DevicePoint;
use sp1_gpu_cudart::{
    args,
    sys::v2_kernels::{
        logup_gkr_first_sum_as_poly_circuit_layer as first_sum_as_poly_layer_circuit_layer_kernel,
        logup_gkr_fix_and_sum_circuit_layer as fix_and_sum_circuit_layer_kernel,
        logup_gkr_fix_and_sum_first_layer as fix_and_sum_first_layer_kernel,
        logup_gkr_fix_and_sum_interactions_layer as fix_and_sum_interactions_layer_kernel,
        logup_gkr_fix_and_sum_last_circuit_layer as fix_and_sum_last_circuit_layer_kernel,
        logup_gkr_fix_last_variable_interactions_layer as fix_last_variable_interactions_layer_kernel,
        logup_gkr_fix_last_variable_last_circuit_layer as fix_last_row_last_circuit_layer_kernel,
        logup_gkr_sum_as_poly_circuit_layer as sum_as_poly_circuit_layer_kernel,
        logup_gkr_sum_as_poly_first_layer as sum_as_poly_first_layer_kernel,
    },
    DeviceBuffer, DeviceTensor, TaskScope,
};

use crate::{
    layer::JaggedGkrLayer,
    utils::{
        generate_test_data, jagged_gkr_layer_to_device, FirstLayerPolynomial, GkrLayer,
        GkrTestData, LogupRoundPolynomial, PolynomialLayer,
    },
};
use rayon::prelude::*;
use slop_sumcheck::partially_verify_sumcheck_proof;
use sp1_gpu_utils::{DenseData, Ext, Felt, JaggedMle};

pub fn get_component_poly_evals(poly: &LogupRoundPolynomial) -> Vec<Ext> {
    match &poly.layer {
        PolynomialLayer::InteractionsLayer(guts) => {
            debug_assert_eq!(guts.sizes(), [4, 1]);
            DeviceBuffer::from_raw(guts.as_buffer().clone()).to_host().unwrap().to_vec()
        }
        PolynomialLayer::CircuitLayer(_) => unreachable!(),
    }
}

/// Reduce the raw per-block univariate evaluations to a single [3]-shaped device tensor.
/// This performs `sum_dim(1)` on the GPU without transferring data to the host.
fn reduce_univariate_evals(univariate_evals: Tensor<Ext, TaskScope>) -> DeviceTensor<Ext> {
    DeviceTensor::from_raw(univariate_evals).sum_dim(1)
}

/// Finalize the raw reduced evaluations into a univariate polynomial on the CPU.
/// Takes the [3]-shaped reduced evals from `reduce_univariate_evals`.
fn finalize_univariate_from_reduced(
    poly: &LogupRoundPolynomial,
    reduced_evals: &DeviceTensor<Ext>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let evals = reduced_evals.to_host().unwrap();
    let mut eval_zero: Ext = *evals[[0]];
    let mut eval_half: Ext = *evals[[1]];
    let eq_sum = *evals[[2]];
    let point_last = *poly.point.last().unwrap();

    // Correct the evaluations by the sum of the eq polynomial, which accounts for the
    // contribution of padded row for the denominator expression
    // `\Sum_i eq * denominator_0 * denominator_1`.
    let eq_correction_term = poly.padding_adjustment - eq_sum;
    // The evaluation at zero just gets the eq correction term.
    eval_zero += eq_correction_term * (Ext::one() - point_last);
    // The evaluation at 1/2 gets the eq correction term times 4, since the denominators
    // have a 1/2 in them for the rest of the evaluations (so we multiply by 2 twice).
    eval_half += eq_correction_term * Ext::from_canonical_u16(4);

    // Since the sumcheck polynomial is homogeneous of degree 3, we need to divide by
    // 8 = 2^3 to account for the evaluations at 1/2 to be double their true value.
    let eval_half = eval_half * Ext::from_canonical_u16(8).inverse();

    let eval_zero = eval_zero * poly.eq_adjustment;
    let eval_half = eval_half * poly.eq_adjustment;

    // Get the root of the eq polynomial which gives an evaluation of zero.
    let b_const = (Ext::one() - point_last) / (Ext::one() - point_last.double());

    let eval_one = claim - eval_zero;

    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
            b_const,
        ],
        &[eval_zero, eval_one, eval_half, Ext::zero()],
    )
}

fn finalize_univariate(
    poly: &LogupRoundPolynomial,
    univariate_evals: Tensor<Ext, TaskScope>,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let reduced = reduce_univariate_evals(univariate_evals);
    finalize_univariate_from_reduced(poly, &reduced, claim)
}

/// Evaluates the first layer polynomial and eq polynomial at 0 and 1/2.
fn sum_as_poly_first_layer(poly: &FirstLayerPolynomial, claim: Ext) -> UnivariatePolynomial<Ext> {
    let circuit = &poly.layer.jagged_mle;

    let height = circuit.dense_data.height >> 1;

    let scope = circuit.backend();

    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;

    let grid_dim = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
    let mut output = Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_dim], scope.clone());

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        output.assume_init();
        let args = args!(
            output.as_mut_ptr(),
            circuit.as_raw(),
            poly.eq_row.guts().as_ptr(),
            poly.eq_interaction.guts().as_ptr(),
            poly.lambda
        );
        scope
            .launch_kernel(
                sum_as_poly_first_layer_kernel(),
                grid_dim,
                BLOCK_SIZE,
                &args,
                shared_mem,
            )
            .unwrap();
    }
    let evals = DeviceTensor::from_raw(output).sum_dim(1).to_host().unwrap();

    let mut eval_zero: Ext = *evals[[0]];
    let mut eval_half: Ext = *evals[[1]];
    let eq_sum = *evals[[2]];

    // Correct the evaluations by the sum of the eq polynomial, which accounts for the
    // contribution of padded row for the denominator expression
    // `\Sum_i eq * denominator_0 * denominator_1`.
    let eq_correction_term = Ext::one() - eq_sum;
    // The evaluation at zero just gets the eq correction term.
    eval_zero += eq_correction_term * (Ext::one() - *poly.point.last().unwrap());
    // The evaluation at 1/2 gets the eq correction term times 4, since the denominators
    // have a 1/2 in them for the rest of the evaluations (so we multiply by 2 twice).
    eval_half += eq_correction_term * Ext::from_canonical_u16(4);

    // Since the sumcheck polynomial is homogeneous of degree 3, we need to divide by
    // 8 = 2^3 to account for the evaluations at 1/2 to be double their true value.
    let eval_half = eval_half * Ext::from_canonical_u16(8).inverse();

    // Get the root of the eq polynomial which gives an evaluation of zero.
    let point_last = poly.point.last().unwrap();
    let b_const = (Ext::one() - *point_last) / (Ext::one() - point_last.double());

    let eval_one = claim - eval_zero;
    interpolate_univariate_polynomial(
        &[
            Ext::from_canonical_u16(0),
            Ext::from_canonical_u16(1),
            Ext::from_canonical_u16(2).inverse(),
            b_const,
        ],
        &[eval_zero, eval_one, eval_half, Ext::zero()],
    )
}

fn fix_last_variable_materialized_round(
    mut poly: LogupRoundPolynomial,
    alpha: Ext,
) -> LogupRoundPolynomial {
    // Remove the last coordinate from the point
    let last_coordinate = poly.point.remove_last_coordinate();
    let padding_adjustment = poly.padding_adjustment
        * (last_coordinate * alpha + (Ext::one() - last_coordinate) * (Ext::one() - alpha));

    match &poly.layer {
        PolynomialLayer::InteractionsLayer(guts) => {
            let height = guts.sizes()[1];
            let output_height = height.div_ceil(2);
            let backend = guts.backend();

            let mut output = Tensor::with_sizes_in([4, output_height], backend.clone());

            const BLOCK_SIZE: usize = 256;
            const STRIDE: usize = 32;
            let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE);
            let grid_size = (grid_size_x, 1, 1);

            unsafe {
                let args = args!(guts.as_ptr(), output.as_mut_ptr(), alpha, height, output_height);
                output.assume_init();
                backend
                    .launch_kernel(
                        fix_last_variable_interactions_layer_kernel(),
                        grid_size,
                        BLOCK_SIZE,
                        &args,
                        0,
                    )
                    .unwrap();
            }

            let layer = PolynomialLayer::InteractionsLayer(output);

            let eq_interaction =
                poly.eq_interaction.fix_last_variable_constant_padding(alpha, Ext::zero());

            LogupRoundPolynomial {
                layer,
                eq_row: poly.eq_row,
                eq_interaction,
                lambda: poly.lambda,
                point: poly.point,
                eq_adjustment: poly.eq_adjustment,
                padding_adjustment,
            }
        }
        PolynomialLayer::CircuitLayer(circuit) => {
            let backend = circuit.jagged_mle.backend();
            let height = circuit.jagged_mle.dense_data.height;
            // If this is the last layer, we need to fix the last variable and create an
            // interaction layer.
            if circuit.num_row_variables == 1 {
                let height = height >> 1;
                let mut output: Tensor<Ext, TaskScope> =
                    Tensor::with_sizes_in([4, height], backend.clone());

                const BLOCK_SIZE: usize = 256;
                const STRIDE: usize = 32;
                let stride = height.div_ceil(STRIDE);
                let grid_size_x = height.div_ceil(BLOCK_SIZE * stride);
                let grid_size = (grid_size_x, 1, 1);
                unsafe {
                    let args = args!(circuit.jagged_mle.dense_data.as_ptr(), output.as_mut_ptr());
                    output.assume_init();
                    backend
                        .launch_kernel(
                            fix_last_row_last_circuit_layer_kernel(),
                            grid_size,
                            BLOCK_SIZE,
                            &args,
                            0,
                        )
                        .unwrap();
                }
                let eq_row = poly.eq_row.fix_last_variable_constant_padding(alpha, Ext::zero());

                return LogupRoundPolynomial {
                    layer: PolynomialLayer::InteractionsLayer(output),
                    eq_row,
                    eq_interaction: poly.eq_interaction,
                    lambda: poly.lambda,
                    point: poly.point,
                    eq_adjustment: padding_adjustment,
                    padding_adjustment: Ext::one(),
                };
            }
            unreachable!();
        }
    }
}

fn fix_and_sum_first_layer(
    mut poly: FirstLayerPolynomial,
    alpha: Ext,
    claim: Ext,
) -> (UnivariatePolynomial<Ext>, LogupRoundPolynomial) {
    let last_coordinate = poly.point.remove_last_coordinate();
    let padding_adjustment =
        last_coordinate * alpha + (Ext::one() - last_coordinate) * (Ext::one() - alpha);

    let backend = poly.layer.jagged_mle.backend();
    let height = poly.layer.jagged_mle.dense_data.height >> 1;

    // Compute the next layer's start indices and column heights.
    let (output_interaction_start_indices, output_interaction_row_counts) =
        poly.layer.jagged_mle.next_start_indices_and_column_heights();
    let output_height = output_interaction_start_indices.last().copied().unwrap() as usize;
    let output_interaction_start_indices =
        DeviceBuffer::from_host(&output_interaction_start_indices, backend).unwrap().into_inner();

    // Create a new layer
    let output_layer: Tensor<Ext, TaskScope> =
        Tensor::with_sizes_in([4, 1, output_height * 2], backend.clone());
    let output_col_index: Buffer<u32, TaskScope> =
        Buffer::with_capacity_in(output_height, backend.clone());

    let output_jagged_layer = JaggedGkrLayer::new(output_layer, output_height);
    let mut output_jagged_mle = JaggedMle::new(
        output_jagged_layer,
        output_col_index,
        output_interaction_start_indices,
        output_interaction_row_counts,
    );

    // Fix the eq_row variables
    let eq_row = poly.eq_row.fix_last_variable_constant_padding(alpha, Ext::zero());

    // populate the new layer
    const BLOCK_SIZE: usize = 256;
    const STRIDE: usize = 32;
    let grid_size_x = height.div_ceil(BLOCK_SIZE * STRIDE);
    let mut univariate_evals =
        Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
    let grid_size = (grid_size_x, 1, 1);
    let block_dim = BLOCK_SIZE;

    let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
    let shared_mem = num_tiles * std::mem::size_of::<Ext>();

    unsafe {
        univariate_evals.assume_init();
        output_jagged_mle.dense_data.assume_init();
        output_jagged_mle.col_index.assume_init();
        let args = args!(
            univariate_evals.as_mut_ptr(),
            poly.layer.jagged_mle.as_raw(),
            output_jagged_mle.as_mut_raw(),
            eq_row.guts().as_ptr(),
            poly.eq_interaction.guts().as_ptr(),
            poly.lambda,
            alpha
        );
        backend
            .launch_kernel(
                fix_and_sum_first_layer_kernel(),
                grid_size,
                block_dim,
                &args,
                shared_mem,
            )
            .unwrap();
    }

    let output_layer = GkrLayer {
        jagged_mle: output_jagged_mle,
        num_row_variables: poly.layer.num_row_variables - 1,
        num_interaction_variables: poly.layer.num_interaction_variables,
    };

    let result_poly = LogupRoundPolynomial {
        layer: PolynomialLayer::CircuitLayer(output_layer),
        eq_row,
        eq_interaction: poly.eq_interaction,
        lambda: poly.lambda,
        point: poly.point,
        eq_adjustment: Ext::one(),
        padding_adjustment,
    };
    let univariate_evals = finalize_univariate(&result_poly, univariate_evals, claim);
    (univariate_evals, result_poly)
}

/// Compute the raw per-block univariate evaluations for a materialized round.
/// Returns the unreduced tensor of shape [3, grid_dim].
fn sum_as_poly_materialized_round_raw(poly: &LogupRoundPolynomial) -> Tensor<Ext, TaskScope> {
    match &poly.layer {
        PolynomialLayer::CircuitLayer(circuit) => {
            let height = circuit.jagged_mle.dense_data.height;
            let scope = circuit.jagged_mle.backend();

            const BLOCK_SIZE: usize = 256;
            const STRIDE: usize = 32;
            let grid_dim = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
            let mut output = Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_dim], scope.clone());
            let num_tiles = BLOCK_SIZE.checked_div(STRIDE).unwrap_or(1);
            let shared_mem = num_tiles * std::mem::size_of::<Ext>();
            unsafe {
                let kernel = if poly.eq_row.guts().total_len() == 2 {
                    first_sum_as_poly_layer_circuit_layer_kernel()
                } else {
                    sum_as_poly_circuit_layer_kernel()
                };
                output.assume_init();
                let args = args!(
                    output.as_mut_ptr(),
                    circuit.jagged_mle.as_raw(),
                    poly.eq_row.guts().as_ptr(),
                    poly.eq_interaction.guts().as_ptr(),
                    poly.lambda
                );
                scope.launch_kernel(kernel, grid_dim, BLOCK_SIZE, &args, shared_mem).unwrap();
            }
            output
        }
        PolynomialLayer::InteractionsLayer(_guts) => {
            unreachable!("first sum_as_poly should always be circuit layer")
        }
    }
}

fn sum_as_poly_materialized_round(
    poly: &LogupRoundPolynomial,
    claim: Ext,
) -> UnivariatePolynomial<Ext> {
    let univariate_evals = sum_as_poly_materialized_round_raw(poly);
    finalize_univariate(poly, univariate_evals, claim)
}

/// Fix last variable and compute raw (unreduced) univariate evaluations.
/// Returns the raw tensor of shape [3, grid_dim] and the updated polynomial.
/// The caller is responsible for reducing (sum_dim) and finalizing.
fn fix_and_sum_materialized_round_raw(
    mut poly: LogupRoundPolynomial,
    alpha: Ext,
) -> (Tensor<Ext, TaskScope>, LogupRoundPolynomial) {
    // Remove the last coordinate from the point
    let last_coordinate = poly.point.remove_last_coordinate();
    let padding_adjustment = poly.padding_adjustment
        * (last_coordinate * alpha + (Ext::one() - last_coordinate) * (Ext::one() - alpha));

    match &poly.layer {
        PolynomialLayer::InteractionsLayer(guts) => {
            // First, fix_last_variable on the eq_interaction
            let eq_interaction =
                poly.eq_interaction.fix_last_variable_constant_padding(alpha, Ext::zero());
            let height = guts.sizes()[1];
            let output_height = height.div_ceil(2);
            let backend = guts.backend();

            let mut output = Tensor::with_sizes_in([4, output_height], backend.clone());

            const BLOCK_SIZE: usize = 256;
            const STRIDE: usize = 32;
            let grid_size_x = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
            let grid_size = (grid_size_x, 1, 1);
            let mut univariate_evals =
                Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
            let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
            let shared_mem = num_tiles * std::mem::size_of::<Ext>();

            unsafe {
                univariate_evals.assume_init();
                output.assume_init();
                let null_ptr: *mut Ext = std::ptr::null_mut();
                let args = args!(
                    univariate_evals.as_mut_ptr(),
                    guts.as_ptr(),
                    output.as_mut_ptr(),
                    alpha,
                    height,
                    output_height,
                    eq_interaction.guts().as_ptr(),
                    poly.lambda,
                    null_ptr
                );
                backend
                    .launch_kernel(
                        fix_and_sum_interactions_layer_kernel(),
                        grid_size,
                        BLOCK_SIZE,
                        &args,
                        shared_mem,
                    )
                    .unwrap();
            }

            let layer = PolynomialLayer::InteractionsLayer(output);

            let poly = LogupRoundPolynomial {
                layer,
                eq_row: poly.eq_row,
                eq_interaction,
                lambda: poly.lambda,
                point: poly.point,
                eq_adjustment: poly.eq_adjustment,
                padding_adjustment,
            };
            (univariate_evals, poly)
        }
        PolynomialLayer::CircuitLayer(circuit) => {
            let backend = circuit.jagged_mle.backend();
            let height = circuit.jagged_mle.dense_data.height;
            // If this is the last layer, we need to fix the last variable and create an
            // interaction layer.
            if circuit.num_row_variables == 1 {
                let height = height >> 1;
                let mut output: Tensor<Ext, TaskScope> =
                    Tensor::with_sizes_in([4, height], backend.clone());

                let eq_row = poly.eq_row.fix_last_variable_constant_padding(alpha, Ext::zero());

                const BLOCK_SIZE: usize = 256;
                const STRIDE: usize = 32;
                let grid_size_x = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
                let grid_size = (grid_size_x, 1, 1);
                let mut univariate_evals =
                    Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
                let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
                let shared_mem = num_tiles * std::mem::size_of::<Ext>();

                unsafe {
                    univariate_evals.assume_init();
                    output.assume_init();
                    let null_ptr: *mut Ext = std::ptr::null_mut();
                    let args = args!(
                        univariate_evals.as_mut_ptr(),
                        circuit.jagged_mle.dense_data.as_ptr(),
                        alpha,
                        output.as_mut_ptr(),
                        poly.eq_interaction.guts().as_ptr(),
                        poly.lambda,
                        null_ptr
                    );
                    backend
                        .launch_kernel(
                            fix_and_sum_last_circuit_layer_kernel(),
                            grid_size,
                            BLOCK_SIZE,
                            &args,
                            shared_mem,
                        )
                        .unwrap();
                }
                let poly = LogupRoundPolynomial {
                    layer: PolynomialLayer::InteractionsLayer(output),
                    eq_row,
                    eq_interaction: poly.eq_interaction,
                    lambda: poly.lambda,
                    point: poly.point,
                    eq_adjustment: padding_adjustment,
                    padding_adjustment: Ext::one(),
                };
                (univariate_evals, poly)
            } else {
                let eq_row = poly.eq_row.fix_last_variable_constant_padding(alpha, Ext::zero());

                let (output_interaction_start_indices, output_interaction_row_counts) =
                    circuit.jagged_mle.next_start_indices_and_column_heights();
                let output_height =
                    output_interaction_start_indices.last().copied().unwrap() as usize;
                let output_interaction_start_indices =
                    DeviceBuffer::from_host(&output_interaction_start_indices, backend)
                        .unwrap()
                        .into_inner();

                // Create a new layer
                let output_layer: Tensor<Ext, TaskScope> =
                    Tensor::with_sizes_in([4, 1, output_height * 2], backend.clone());
                let output_col_index: Buffer<u32, TaskScope> =
                    Buffer::with_capacity_in(output_height, backend.clone());

                let output_jagged_layer = JaggedGkrLayer::new(output_layer, output_height);
                let mut output_jagged_mle = JaggedMle::new(
                    output_jagged_layer,
                    output_col_index,
                    output_interaction_start_indices,
                    output_interaction_row_counts,
                );

                // populate the new layer
                const BLOCK_SIZE: usize = 256;
                const STRIDE: usize = 32;
                let grid_size_x = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
                let grid_size = (grid_size_x, 1, 1);
                let block_dim = BLOCK_SIZE;

                let mut univariate_evals =
                    Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
                let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
                let shared_mem = num_tiles * std::mem::size_of::<Ext>();

                unsafe {
                    univariate_evals.assume_init();
                    output_jagged_mle.dense_data.assume_init();
                    output_jagged_mle.col_index.assume_init();
                    let null_ptr: *mut Ext = std::ptr::null_mut();
                    let args = args!(
                        univariate_evals.as_mut_ptr(),
                        circuit.jagged_mle.as_raw(),
                        output_jagged_mle.as_mut_raw(),
                        alpha,
                        eq_row.guts().as_ptr(),
                        poly.eq_interaction.guts().as_ptr(),
                        poly.lambda,
                        null_ptr
                    );
                    backend
                        .launch_kernel(
                            fix_and_sum_circuit_layer_kernel(),
                            grid_size,
                            block_dim,
                            &args,
                            shared_mem,
                        )
                        .unwrap();
                }

                let output_layer = GkrLayer {
                    jagged_mle: output_jagged_mle,
                    num_row_variables: circuit.num_row_variables - 1,
                    num_interaction_variables: circuit.num_interaction_variables,
                };

                let poly = LogupRoundPolynomial {
                    layer: PolynomialLayer::CircuitLayer(output_layer),
                    eq_row,
                    eq_interaction: poly.eq_interaction,
                    lambda: poly.lambda,
                    point: poly.point,
                    eq_adjustment: poly.eq_adjustment,
                    padding_adjustment,
                };

                (univariate_evals, poly)
            }
        }
    }
}

/// Fix last variable and compute raw (unreduced) univariate evaluations, with fused atomic
/// reduction. Each block atomically adds its partial sum into `reduced_output` (shape `[3]`),
/// eliminating the need for a separate `sum_dim` kernel launch.
///
/// The `reduced_output` tensor must be pre-zeroed before the kernel launch.
/// The unreduced `[3, grid_dim]` tensor is still produced for proof transcript reconstruction.
fn fix_and_sum_materialized_round_raw_with_reduction(
    mut poly: LogupRoundPolynomial,
    alpha: Ext,
    reduced_output: &mut Tensor<Ext, TaskScope>,
) -> (Tensor<Ext, TaskScope>, LogupRoundPolynomial) {
    // Remove the last coordinate from the point
    let last_coordinate = poly.point.remove_last_coordinate();
    let padding_adjustment = poly.padding_adjustment
        * (last_coordinate * alpha + (Ext::one() - last_coordinate) * (Ext::one() - alpha));

    match &poly.layer {
        PolynomialLayer::InteractionsLayer(guts) => {
            // First, fix_last_variable on the eq_interaction
            let eq_interaction =
                poly.eq_interaction.fix_last_variable_constant_padding(alpha, Ext::zero());
            let height = guts.sizes()[1];
            let output_height = height.div_ceil(2);
            let backend = guts.backend();

            let mut output = Tensor::with_sizes_in([4, output_height], backend.clone());

            const BLOCK_SIZE: usize = 256;
            const STRIDE: usize = 32;
            let grid_size_x = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
            let grid_size = (grid_size_x, 1, 1);
            let mut univariate_evals =
                Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
            let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
            let shared_mem = num_tiles * std::mem::size_of::<Ext>();

            unsafe {
                univariate_evals.assume_init();
                output.assume_init();
                let args = args!(
                    univariate_evals.as_mut_ptr(),
                    guts.as_ptr(),
                    output.as_mut_ptr(),
                    alpha,
                    height,
                    output_height,
                    eq_interaction.guts().as_ptr(),
                    poly.lambda,
                    reduced_output.as_mut_ptr()
                );
                backend
                    .launch_kernel(
                        fix_and_sum_interactions_layer_kernel(),
                        grid_size,
                        BLOCK_SIZE,
                        &args,
                        shared_mem,
                    )
                    .unwrap();
            }

            let layer = PolynomialLayer::InteractionsLayer(output);

            let poly = LogupRoundPolynomial {
                layer,
                eq_row: poly.eq_row,
                eq_interaction,
                lambda: poly.lambda,
                point: poly.point,
                eq_adjustment: poly.eq_adjustment,
                padding_adjustment,
            };
            (univariate_evals, poly)
        }
        PolynomialLayer::CircuitLayer(circuit) => {
            let backend = circuit.jagged_mle.backend();
            let height = circuit.jagged_mle.dense_data.height;
            // If this is the last layer, we need to fix the last variable and create an
            // interaction layer.
            if circuit.num_row_variables == 1 {
                let height = height >> 1;
                let mut output: Tensor<Ext, TaskScope> =
                    Tensor::with_sizes_in([4, height], backend.clone());

                let eq_row = poly.eq_row.fix_last_variable_constant_padding(alpha, Ext::zero());

                const BLOCK_SIZE: usize = 256;
                const STRIDE: usize = 32;
                let grid_size_x = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
                let grid_size = (grid_size_x, 1, 1);
                let mut univariate_evals =
                    Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
                let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
                let shared_mem = num_tiles * std::mem::size_of::<Ext>();

                unsafe {
                    univariate_evals.assume_init();
                    output.assume_init();
                    let args = args!(
                        univariate_evals.as_mut_ptr(),
                        circuit.jagged_mle.dense_data.as_ptr(),
                        alpha,
                        output.as_mut_ptr(),
                        poly.eq_interaction.guts().as_ptr(),
                        poly.lambda,
                        reduced_output.as_mut_ptr()
                    );
                    backend
                        .launch_kernel(
                            fix_and_sum_last_circuit_layer_kernel(),
                            grid_size,
                            BLOCK_SIZE,
                            &args,
                            shared_mem,
                        )
                        .unwrap();
                }
                let poly = LogupRoundPolynomial {
                    layer: PolynomialLayer::InteractionsLayer(output),
                    eq_row,
                    eq_interaction: poly.eq_interaction,
                    lambda: poly.lambda,
                    point: poly.point,
                    eq_adjustment: padding_adjustment,
                    padding_adjustment: Ext::one(),
                };
                (univariate_evals, poly)
            } else {
                let eq_row = poly.eq_row.fix_last_variable_constant_padding(alpha, Ext::zero());

                let (output_interaction_start_indices, output_interaction_row_counts) =
                    circuit.jagged_mle.next_start_indices_and_column_heights();
                let output_height =
                    output_interaction_start_indices.last().copied().unwrap() as usize;
                let output_interaction_start_indices =
                    DeviceBuffer::from_host(&output_interaction_start_indices, backend)
                        .unwrap()
                        .into_inner();

                // Create a new layer
                let output_layer: Tensor<Ext, TaskScope> =
                    Tensor::with_sizes_in([4, 1, output_height * 2], backend.clone());
                let output_col_index: Buffer<u32, TaskScope> =
                    Buffer::with_capacity_in(output_height, backend.clone());

                let output_jagged_layer = JaggedGkrLayer::new(output_layer, output_height);
                let mut output_jagged_mle = JaggedMle::new(
                    output_jagged_layer,
                    output_col_index,
                    output_interaction_start_indices,
                    output_interaction_row_counts,
                );

                // populate the new layer
                const BLOCK_SIZE: usize = 256;
                const STRIDE: usize = 32;
                let grid_size_x = height.div_ceil(BLOCK_SIZE).div_ceil(STRIDE);
                let grid_size = (grid_size_x, 1, 1);
                let block_dim = BLOCK_SIZE;

                let mut univariate_evals =
                    Tensor::<Ext, TaskScope>::with_sizes_in([3, grid_size_x], backend.clone());
                let num_tiles = BLOCK_SIZE.checked_div(32).unwrap_or(1);
                let shared_mem = num_tiles * std::mem::size_of::<Ext>();

                unsafe {
                    univariate_evals.assume_init();
                    output_jagged_mle.dense_data.assume_init();
                    output_jagged_mle.col_index.assume_init();
                    let args = args!(
                        univariate_evals.as_mut_ptr(),
                        circuit.jagged_mle.as_raw(),
                        output_jagged_mle.as_mut_raw(),
                        alpha,
                        eq_row.guts().as_ptr(),
                        poly.eq_interaction.guts().as_ptr(),
                        poly.lambda,
                        reduced_output.as_mut_ptr()
                    );
                    backend
                        .launch_kernel(
                            fix_and_sum_circuit_layer_kernel(),
                            grid_size,
                            block_dim,
                            &args,
                            shared_mem,
                        )
                        .unwrap();
                }

                let output_layer = GkrLayer {
                    jagged_mle: output_jagged_mle,
                    num_row_variables: circuit.num_row_variables - 1,
                    num_interaction_variables: circuit.num_interaction_variables,
                };

                let poly = LogupRoundPolynomial {
                    layer: PolynomialLayer::CircuitLayer(output_layer),
                    eq_row,
                    eq_interaction: poly.eq_interaction,
                    lambda: poly.lambda,
                    point: poly.point,
                    eq_adjustment: poly.eq_adjustment,
                    padding_adjustment,
                };

                (univariate_evals, poly)
            }
        }
    }
}

// returns (next univariate, next round polynomial)
fn fix_and_sum_materialized_round(
    poly: LogupRoundPolynomial,
    alpha: Ext,
    claim: Ext,
) -> (UnivariatePolynomial<Ext>, LogupRoundPolynomial) {
    let (univariate_evals, poly) = fix_and_sum_materialized_round_raw(poly, alpha);
    let univariate = finalize_univariate(&poly, univariate_evals, claim);
    (univariate, poly)
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

pub fn first_round_sumcheck<C>(
    poly: FirstLayerPolynomial,
    challenger: &mut C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
{
    // Check that all the polynomials have the same number of variables.
    let num_variables = poly.num_variables();

    // The first round will process the first t variables, so we need to ensure that there are at least t variables.
    assert!(num_variables >= 1_u32);

    // The point at which the reduced sumcheck proof should be evaluated.
    let mut point = vec![];

    // The univariate poly messages.  This will be a rlc of the polys' univariate polys.
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<Ext>> = vec![];

    let uni_poly = sum_as_poly_first_layer(&poly, claim);

    let mut alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);

    let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(*point.first().unwrap());

    let (mut uni_poly, mut poly) = fix_and_sum_first_layer(poly, alpha, round_claim);

    alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);

    for _ in 2..num_variables as usize {
        // Get the round claims from the last round's univariate poly messages.
        let round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);

        (uni_poly, poly) = fix_and_sum_materialized_round(poly, alpha, round_claim);

        alpha = process_univariate_polynomial(
            uni_poly,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
    }

    poly = fix_last_variable_materialized_round(poly, *point.first().unwrap());

    let evals = univariate_poly_msgs.last().unwrap().eval_at_point(*point.first().unwrap());

    let component_poly_evals = get_component_poly_evals(&poly);

    (
        PartialSumcheckProof {
            univariate_polys: univariate_poly_msgs,
            claimed_sum: claim,
            point_and_eval: (point.into(), evals),
        },
        component_poly_evals,
    )
}

pub fn materialized_round_sumcheck<C: FieldChallenger<Felt>>(
    mut poly: LogupRoundPolynomial,
    challenger: &mut C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>) {
    let num_variables = poly.num_variables();
    assert!(num_variables >= 1_u32);

    let mut point = Vec::with_capacity(num_variables as usize);
    let mut univariate_poly_msgs = Vec::with_capacity(num_variables as usize);

    // First round: compute initial univariate polynomial
    let uni_poly = sum_as_poly_materialized_round(&poly, claim);
    let alpha =
        process_univariate_polynomial(uni_poly, challenger, &mut univariate_poly_msgs, &mut point);

    // Early return for single variable case
    if num_variables == 1 {
        poly = fix_last_variable_materialized_round(poly, alpha);
        let eval = univariate_poly_msgs[0].eval_at_point(alpha);
        let component_poly_evals = get_component_poly_evals(&poly);

        return (
            PartialSumcheckProof {
                univariate_polys: univariate_poly_msgs,
                claimed_sum: claim,
                point_and_eval: (point.into(), eval),
            },
            component_poly_evals,
        );
    }

    // Process remaining rounds
    let mut round_claim = univariate_poly_msgs[0].eval_at_point(alpha);

    for _round in 1..num_variables as usize {
        let (uni_poly, next_poly) = fix_and_sum_materialized_round(poly, point[0], round_claim);
        poly = next_poly;

        let alpha = process_univariate_polynomial(
            uni_poly,
            challenger,
            &mut univariate_poly_msgs,
            &mut point,
        );
        round_claim = univariate_poly_msgs.last().unwrap().eval_at_point(alpha);
    }

    // Final fix_last_variable
    poly = fix_last_variable_materialized_round(poly, point[0]);

    // Compute final evaluation
    let eval = univariate_poly_msgs.last().unwrap().eval_at_point(point[0]);
    let component_poly_evals = get_component_poly_evals(&poly);

    (
        PartialSumcheckProof {
            univariate_polys: univariate_poly_msgs,
            claimed_sum: claim,
            point_and_eval: (point.into(), eval),
        },
        component_poly_evals,
    )
}

// Re-use AsMutRawChallenger from jagged_sumcheck to avoid trait duplication.
pub use sp1_gpu_jagged_sumcheck::AsMutRawChallenger;

/// Trait for selecting the appropriate GPU cubic observe-and-sample kernel.
///
/// # Safety
///
/// The kernel pointer returned must match the challenger type's raw representation.
pub unsafe trait ObserveAndSampleCubicKernel {
    fn observe_and_sample_cubic_kernel() -> sp1_gpu_cudart::sys::runtime::KernelPtr;
}

unsafe impl<F> ObserveAndSampleCubicKernel for sp1_gpu_challenger::DuplexChallenger<F, TaskScope> {
    fn observe_and_sample_cubic_kernel() -> sp1_gpu_cudart::sys::runtime::KernelPtr {
        unsafe { sp1_gpu_cudart::sys::sumcheck::sumcheck_observe_and_sample_cubic_duplex() }
    }
}

unsafe impl<F, PF> ObserveAndSampleCubicKernel
    for sp1_gpu_challenger::MultiField32Challenger<F, PF, TaskScope>
{
    fn observe_and_sample_cubic_kernel() -> sp1_gpu_cudart::sys::runtime::KernelPtr {
        unsafe { sp1_gpu_cudart::sys::sumcheck::sumcheck_observe_and_sample_cubic_multi_field_32() }
    }
}

/// Launch the GPU observe-and-sample kernel for a cubic (degree-3) LogUp-GKR sumcheck round.
///
/// This single-thread kernel reads the reduced evals [eval_zero, eval_half, eq_sum] from device,
/// applies eq corrections using the provided scalar parameters, interpolates the degree-3
/// polynomial, observes coefficients with the device challenger, samples alpha, evaluates
/// p(alpha) for next_claim, and writes alpha + next_claim to device buffers.
#[allow(clippy::too_many_arguments)]
fn launch_observe_and_sample_cubic<DC: AsMutRawChallenger + ObserveAndSampleCubicKernel>(
    reduced_evals: &DeviceTensor<Ext>,
    device_challenger: &mut DC,
    alpha_buf: &mut DeviceBuffer<Ext>,
    next_claim_buf: &mut DeviceBuffer<Ext>,
    claim: Ext,
    padding_adjustment: Ext,
    eq_adjustment: Ext,
    point_last: Ext,
    backend: &TaskScope,
) {
    let challenger_raw = device_challenger.as_mut_raw();
    unsafe {
        let args = args!(
            reduced_evals.as_ptr(),
            challenger_raw,
            alpha_buf.as_mut_ptr(),
            claim,
            next_claim_buf.as_mut_ptr(),
            padding_adjustment,
            eq_adjustment,
            point_last
        );
        backend
            .launch_kernel(DC::observe_and_sample_cubic_kernel(), 1usize, 1usize, &args, 0)
            .unwrap();
    }
}

/// LogUp-GKR materialized round sumcheck with GPU-side Fiat-Shamir challenger.
///
/// Instead of transferring reduced evaluations to the CPU for correction, interpolation,
/// and challenger operations each round, this keeps the reduced evals on device and launches
/// a single-thread GPU kernel that does correction + interpolation + observe + sample.
///
/// Per round, only alpha (16 bytes) and next_claim (16 bytes) are transferred D2H.
/// The reduced eval device tensors are saved during the main loop and batch-transferred
/// to CPU at the end to reconstruct the polynomial coefficients for the proof.
/// The CPU challenger state is then synced via transcript replay.
pub fn materialized_round_sumcheck_gpu_challenger<C, DC>(
    mut poly: LogupRoundPolynomial,
    challenger: &mut C,
    claim: Ext,
) -> (PartialSumcheckProof<Ext>, Vec<Ext>)
where
    C: FieldChallenger<Felt>,
    DC: AsMutRawChallenger
        + ObserveAndSampleCubicKernel
        + sp1_gpu_challenger::FromHostChallengerSync<C>,
{
    let num_variables = poly.num_variables();
    assert!(num_variables >= 1_u32);

    // Get a backend reference from the polynomial's layer for device operations.
    let backend = match &poly.layer {
        PolynomialLayer::CircuitLayer(circuit) => circuit.jagged_mle.backend().clone(),
        PolynomialLayer::InteractionsLayer(guts) => guts.backend().clone(),
    };

    // Create device challenger from the current CPU challenger state.
    let mut device_challenger = DC::from_host_challenger_sync(challenger, &backend);

    // Allocate reusable device buffers for alpha and next_claim (16 bytes each).
    let mut alpha_buf = DeviceBuffer::<Ext>::with_capacity_in(1, backend.clone());
    let mut next_claim_buf = DeviceBuffer::<Ext>::with_capacity_in(1, backend.clone());
    unsafe {
        alpha_buf.set_len(1);
        next_claim_buf.set_len(1);
    }

    // Save reduced evals and poly snapshots for batch D2H at the end.
    let mut saved_reduced_evals: Vec<DeviceTensor<Ext>> =
        Vec::with_capacity(num_variables as usize);
    // Save the correction parameters for each round (needed for CPU-side replay).
    let mut saved_params: Vec<RoundParams> = Vec::with_capacity(num_variables as usize);

    let mut point: Vec<Ext> = Vec::with_capacity(num_variables as usize);
    let mut current_claim = claim;
    let mut gpu_claims: Vec<Ext> = Vec::with_capacity(num_variables as usize);

    // --- Round 0: sum_as_poly (first round, no fix_last_variable) ---
    {
        let raw_evals = sum_as_poly_materialized_round_raw(&poly);
        let reduced_evals = reduce_univariate_evals(raw_evals);

        let point_last = *poly.point.last().unwrap();
        saved_params.push(RoundParams {
            padding_adjustment: poly.padding_adjustment,
            eq_adjustment: poly.eq_adjustment,
            point_last,
        });

        launch_observe_and_sample_cubic(
            &reduced_evals,
            &mut device_challenger,
            &mut alpha_buf,
            &mut next_claim_buf,
            current_claim,
            poly.padding_adjustment,
            poly.eq_adjustment,
            point_last,
            &backend,
        );

        saved_reduced_evals.push(reduced_evals);

        let alpha = alpha_buf.to_host().unwrap()[0];
        current_claim = next_claim_buf.to_host().unwrap()[0];
        gpu_claims.push(current_claim);
        point.push(alpha);
    }

    // Early return for single variable case
    if num_variables == 1 {
        poly = fix_last_variable_materialized_round(poly, point[0]);

        // Batch D2H and reconstruct uni_polys
        let (uni_polys, _) =
            replay_and_reconstruct(&saved_reduced_evals, &saved_params, &point, claim, &gpu_claims);

        let eval = uni_polys[0].eval_at_point(point[0]);
        let component_poly_evals = get_component_poly_evals(&poly);

        // Replay CPU challenger
        replay_cpu_challenger(challenger, &uni_polys);

        return (
            PartialSumcheckProof {
                univariate_polys: uni_polys,
                claimed_sum: claim,
                point_and_eval: (point.into(), eval),
            },
            component_poly_evals,
        );
    }

    // --- Remaining rounds: fix_and_sum with standard sum_dim reduction ---
    for _round in 1..num_variables as usize {
        let current_alpha = point[0];

        let (raw_evals, next_poly) = fix_and_sum_materialized_round_raw(
            poly,
            current_alpha,
        );
        poly = next_poly;

        // Reduce the [3, grid_dim] tensor to [3] via sum_dim.
        let reduced_evals = reduce_univariate_evals(raw_evals);

        let point_last = *poly.point.last().unwrap();
        saved_params.push(RoundParams {
            padding_adjustment: poly.padding_adjustment,
            eq_adjustment: poly.eq_adjustment,
            point_last,
        });

        launch_observe_and_sample_cubic(
            &reduced_evals,
            &mut device_challenger,
            &mut alpha_buf,
            &mut next_claim_buf,
            current_claim,
            poly.padding_adjustment,
            poly.eq_adjustment,
            point_last,
            &backend,
        );

        saved_reduced_evals.push(reduced_evals);

        let alpha = alpha_buf.to_host().unwrap()[0];
        current_claim = next_claim_buf.to_host().unwrap()[0];
        gpu_claims.push(current_claim);
        point.insert(0, alpha);
    }

    // Final fix_last_variable
    poly = fix_last_variable_materialized_round(poly, point[0]);

    // --- Batch D2H of reduced evals and reconstruct uni_polys ---
    let (uni_polys, _) = replay_and_reconstruct(&saved_reduced_evals, &saved_params, &point, claim, &gpu_claims);

    // Compute final evaluation
    let eval = uni_polys.last().unwrap().eval_at_point(point[0]);
    let component_poly_evals = get_component_poly_evals(&poly);

    // Replay CPU challenger for state sync
    replay_cpu_challenger(challenger, &uni_polys);

    (
        PartialSumcheckProof {
            univariate_polys: uni_polys,
            claimed_sum: claim,
            point_and_eval: (point.into(), eval),
        },
        component_poly_evals,
    )
}

/// Batch-transfer reduced evals from device and reconstruct univariate polynomials on CPU.
/// Returns the vector of univariate polynomials and the final claim.
fn replay_and_reconstruct(
    saved_reduced_evals: &[DeviceTensor<Ext>],
    saved_params: &[RoundParams],
    point: &[Ext],
    initial_claim: Ext,
    gpu_claims: &[Ext],
) -> (Vec<UnivariatePolynomial<Ext>>, Ext) {
    let num_rounds = saved_reduced_evals.len();
    let mut uni_polys: Vec<UnivariatePolynomial<Ext>> = Vec::with_capacity(num_rounds);
    let mut replay_claim = initial_claim;

    for (round, (saved_evals, params)) in
        saved_reduced_evals.iter().zip(saved_params.iter()).enumerate()
    {
        let host_evals = saved_evals.to_host().unwrap();
        let mut eval_zero: Ext = *host_evals[[0]];
        let mut eval_half: Ext = *host_evals[[1]];
        let eq_sum: Ext = *host_evals[[2]];

        // Apply the same corrections as finalize_univariate
        let eq_correction_term = params.padding_adjustment - eq_sum;
        eval_zero += eq_correction_term * (Ext::one() - params.point_last);
        eval_half += eq_correction_term * Ext::from_canonical_u16(4);
        let eval_half = eval_half * Ext::from_canonical_u16(8).inverse();
        let eval_zero = eval_zero * params.eq_adjustment;
        let eval_half = eval_half * params.eq_adjustment;

        let b_const = (Ext::one() - params.point_last) / (Ext::one() - params.point_last.double());
        let eval_one = replay_claim - eval_zero;

        let uni_poly = interpolate_univariate_polynomial(
            &[
                Ext::from_canonical_u16(0),
                Ext::from_canonical_u16(1),
                Ext::from_canonical_u16(2).inverse(),
                b_const,
            ],
            &[eval_zero, eval_one, eval_half, Ext::zero()],
        );

        // The alpha for this round is stored in reverse order in the point vector.
        let alpha = point[num_rounds - 1 - round];
        replay_claim = uni_poly.eval_at_point(alpha);

        // Diagnostic: compare GPU next_claim with CPU-replayed next_claim.
        if round < gpu_claims.len() && replay_claim != gpu_claims[round] {
            eprintln!("[GPU_CHALLENGER_DEBUG] MISMATCH at round {round}");
        }

        uni_polys.push(uni_poly);
    }

    (uni_polys, replay_claim)
}

/// Replay the CPU challenger with the reconstructed polynomials for state synchronization.
fn replay_cpu_challenger<C: FieldChallenger<Felt>>(
    challenger: &mut C,
    uni_polys: &[UnivariatePolynomial<Ext>],
) {
    for poly in uni_polys {
        let coefficients: Vec<Felt> =
            poly.coefficients.iter().flat_map(|c| c.as_base_slice()).copied().collect();
        challenger.observe_slice(&coefficients);
        let _: Ext = challenger.sample_ext_element();
    }
}

/// Correction parameters for a single sumcheck round.
/// Saved during the GPU path for batch CPU-side replay at the end.
struct RoundParams {
    padding_adjustment: Ext,
    eq_adjustment: Ext,
    point_last: Ext,
}

pub fn bench_materialized_sumcheck<GC: IopCtx>(
    interaction_row_counts: Vec<u32>,
    rng: &mut impl rand::Rng,
    num_row_variables: Option<u32>,
) where
    GC::Challenger: FieldChallenger<Felt>,
{
    let get_challenger = move || GC::default_challenger();
    let now = std::time::Instant::now();

    let (layer, test_data) = generate_test_data(rng, interaction_row_counts, num_row_variables);

    println!("generate test data took {}s", now.elapsed().as_secs_f64());

    let GkrTestData { numerator_0, numerator_1, denominator_0, denominator_1 } = test_data;

    let GkrLayer { jagged_mle, num_interaction_variables, num_row_variables } = layer;

    println!("num_row_variables: {num_row_variables}");
    println!("num_interaction_variables: {num_interaction_variables}");
    let poly_point = Point::<Ext>::rand(rng, num_row_variables + num_interaction_variables);
    let (interaction_point, row_point) = poly_point.split_at(num_interaction_variables as usize);

    let lambda = rng.gen::<Ext>();

    sp1_gpu_cudart::run_sync_in_place(move |t| {
        let now = std::time::Instant::now();
        let jagged_mle = jagged_gkr_layer_to_device(jagged_mle, &t);

        let row_point = DevicePoint::from_host(&row_point, &t).unwrap().into_inner();
        let interaction_point =
            DevicePoint::from_host(&interaction_point, &t).unwrap().into_inner();

        let eq_row = DevicePoint::new(row_point).partial_lagrange();
        let eq_interaction = DevicePoint::new(interaction_point).partial_lagrange();

        println!("moving to device took {}s", now.elapsed().as_secs_f64());

        let layer = GkrLayer { jagged_mle, num_interaction_variables, num_row_variables };

        let polynomial = LogupRoundPolynomial {
            layer: PolynomialLayer::CircuitLayer(layer),
            eq_row,
            eq_interaction,
            lambda,
            eq_adjustment: Ext::one(),
            padding_adjustment: Ext::one(),
            point: poly_point.clone(),
        };

        let host_eq = Mle::blocking_partial_lagrange(&poly_point);
        let now = std::time::Instant::now();
        let claim = numerator_0
            .guts()
            .as_slice()
            .par_iter()
            .zip_eq(numerator_1.guts().as_slice().par_iter())
            .zip_eq(denominator_0.guts().as_slice().par_iter())
            .zip_eq(denominator_1.guts().as_slice().par_iter())
            .zip_eq(host_eq.guts().as_slice().par_iter())
            .map(|((((n_0, n_1), d_0), d_1), eq)| {
                let numerator_eval = *n_0 * *d_1 + *n_1 * *d_0;
                let denominator_eval = *d_0 * *d_1;
                *eq * (numerator_eval * lambda + denominator_eval)
            })
            .sum::<Ext>();

        let mut challenger = get_challenger();
        t.synchronize_blocking().unwrap();
        println!(
            "time for claim on host is {}, now starting sumcheck",
            now.elapsed().as_secs_f64()
        );

        let poly = polynomial.clone();
        let now = std::time::Instant::now();
        let (mut proof, mut evals) = materialized_round_sumcheck(poly, &mut challenger, claim);
        println!("time for sumcheck: {}", now.elapsed().as_secs_f64());

        for _ in 0..2 {
            let poly = polynomial.clone();
            let now = std::time::Instant::now();
            t.synchronize_blocking().unwrap();
            let mut challenger = get_challenger();
            (proof, evals) = materialized_round_sumcheck(poly, &mut challenger, claim);
            println!("time for sumcheck: {}", now.elapsed().as_secs_f64());
        }

        let mut challenger = get_challenger();
        partially_verify_sumcheck_proof(
            &proof,
            &mut challenger,
            (num_row_variables + num_interaction_variables) as usize,
            3,
        )
        .unwrap();

        let (point, expected_final_eval) = proof.point_and_eval;

        // Assert that the point has the expected dimension.
        assert_eq!(point.dimension() as u32, num_row_variables + num_interaction_variables);

        // Calculate the expected evaluations at the point.
        let [n_0, n_1, d_0, d_1] = evals.try_into().unwrap();
        let eq_eval = Mle::full_lagrange_eval(&poly_point, &point);

        let expected_numerator_eval = n_0 * d_1 + n_1 * d_0;
        let expected_denominator_eval = d_0 * d_1;
        let eval = expected_numerator_eval * lambda + expected_denominator_eval;
        let final_eval = eq_eval * eval;

        // Assert that the final eval is correct.
        assert_eq!(final_eval, expected_final_eval);
    })
    .unwrap();
}

#[cfg(test)]
mod tests {
    use crate::utils::{generate_test_data, GkrTestData};
    use slop_multilinear::Point;
    use sp1_gpu_cudart::DevicePoint;
    use sp1_gpu_utils::TestGC;

    use super::*;

    use rand::{rngs::StdRng, Rng, SeedableRng as _};

    /// Since we don't ever *only* fix last variable on a normal circuit layer, this unit test does fix_and_sum with a dummy claim.q
    #[test]
    fn test_logup_round_polynomial_fix_last_variable() {
        let mut rng = StdRng::seed_from_u64(0);

        let interaction_row_counts: Vec<u32> =
            vec![(1 << 8) + 2, (1 << 10) + 2, 1 << 8, 1 << 6, 1 << 10, 1 << 8, (1 << 6) + 2];
        let (layer, test_data) = generate_test_data(&mut rng, interaction_row_counts, None);
        let GkrTestData { numerator_0, numerator_1, denominator_0, denominator_1 } = test_data;

        let GkrLayer { jagged_mle, num_interaction_variables, num_row_variables } = layer;

        let poly_point =
            Point::<Ext>::rand(&mut rng, num_row_variables + num_interaction_variables + 1);
        let (interaction_point, row_point) =
            poly_point.split_at(num_interaction_variables as usize);

        let random_point =
            Point::<Ext>::rand(&mut rng, num_row_variables + num_interaction_variables);

        let lambda = rng.gen::<Ext>();

        sp1_gpu_cudart::run_sync_in_place(move |t| {
            let jagged_mle = jagged_gkr_layer_to_device(jagged_mle, &t);

            let row_point = DevicePoint::from_host(&row_point, &t).unwrap().into_inner();
            let interaction_point =
                DevicePoint::from_host(&interaction_point, &t).unwrap().into_inner();

            let eq_row = DevicePoint::new(row_point).partial_lagrange();
            let eq_interaction = DevicePoint::new(interaction_point).partial_lagrange();

            let layer = GkrLayer { jagged_mle, num_interaction_variables, num_row_variables };

            let mut polynomial = LogupRoundPolynomial {
                layer: PolynomialLayer::CircuitLayer(layer),
                eq_row,
                eq_interaction,
                lambda,
                eq_adjustment: Ext::one(),
                padding_adjustment: Ext::one(),
                point: poly_point,
            };

            // Get the expected evaluations using host-side computation
            let numerator_0_eval = numerator_0.eval_at(&random_point)[0];
            let numerator_1_eval = numerator_1.eval_at(&random_point)[0];
            let denominator_0_eval = denominator_0.eval_at(&random_point)[0];
            let denominator_1_eval = denominator_1.eval_at(&random_point)[0];

            for alpha in random_point.iter().rev() {
                let _uni_poly;
                (_uni_poly, polynomial) =
                    fix_and_sum_materialized_round(polynomial, *alpha, Ext::zero());
            }
            let component_poly_evals = get_component_poly_evals(&polynomial);

            // Get the values from the sumcheck polynomial
            let [n_0, n_1, d_0, d_1] = component_poly_evals.try_into().unwrap();
            assert_eq!(numerator_0_eval, n_0);
            assert_eq!(numerator_1_eval, n_1);
            assert_eq!(denominator_0_eval, d_0);
            assert_eq!(denominator_1_eval, d_1);
        })
        .unwrap();
    }

    #[test]
    fn test_logup_round_sumcheck_polynomial() {
        let mut rng = StdRng::seed_from_u64(0);
        let interaction_row_counts: Vec<u32> = vec![92, 100, 278, 220, 82, 82];

        bench_materialized_sumcheck::<TestGC>(interaction_row_counts, &mut rng, None);
    }
}
