use rayon::prelude::*;
use std::{cmp::max, sync::Arc};

use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_tensor::Tensor;

use crate::{eval_mle_at_point, num_polynomials, MleEval, Point};

/// Fix the last variable of an MLE with generic padding values.
pub fn mle_fix_last_variable<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    alpha: EF,
    padding_values: Arc<MleEval<F, CpuBackend>>,
) -> Tensor<EF, CpuBackend>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let num_polynomials = num_polynomials(mle);
    let num_non_zero_elements_out = mle.sizes()[0].div_ceil(2);
    let result_size = num_non_zero_elements_out * num_polynomials;

    let mut result: Vec<EF> = Vec::with_capacity(result_size);

    #[allow(clippy::uninit_vec)]
    unsafe {
        result.set_len(result_size);
    }

    let result_chunk_size =
        max(num_non_zero_elements_out / num_cpus::get() * num_polynomials, num_polynomials);
    let mle_slice = mle.as_slice();

    result.par_chunks_mut(result_chunk_size).enumerate().for_each(|(chunk_idx, result_chunk)| {
        let mle_offset = chunk_idx * result_chunk_size * 2;
        let num_result_rows = result_chunk.len() / num_polynomials;

        (0..num_result_rows).for_each(|i| {
            (0..num_polynomials).for_each(|j| {
                let x = mle_slice[mle_offset + (2 * i) * num_polynomials + j];
                let y = mle_slice
                    .get(mle_offset + (2 * i + 1) * num_polynomials + j)
                    .copied()
                    .unwrap_or_else(|| padding_values[j]);
                // return alpha * y + (EF::one() - alpha) * x, but in a more efficient
                // way that minimizes extension field multiplications.
                result_chunk[i * num_polynomials + j] = alpha * (y - x) + x;
            });
        });
    });

    Tensor::from(result).reshape([num_non_zero_elements_out, num_polynomials])
}

/// Fix the last variable of an MLE with constant padding.
pub fn mle_fix_last_variable_constant_padding<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    alpha: EF,
    padding_value: F,
) -> Tensor<EF, CpuBackend>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let padding_values: MleEval<_> = vec![padding_value; num_polynomials(mle)].into();
    mle_fix_last_variable(mle, alpha, Arc::new(padding_values))
}

/// Compute the evaluation at a point where the last variable is fixed to zero.
pub fn mle_fixed_at_zero<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend>
where
    F: Field,
    EF: ExtensionField<F>,
{
    // TODO: A smarter way to do this is pre-cache the partial_lagrange_evals that are implicit
    // in `eval_at_point` so we don't recompute it at every step of BaseFold.
    let even_values = mle.as_slice().par_iter().step_by(2).copied().collect::<Vec<_>>();
    eval_mle_at_point(&Tensor::from(even_values), point)
}
