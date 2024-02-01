use itertools::izip;
use p3_field::{AbstractExtensionField, Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use p3_util::log2_strict_usize;

use super::StarkConfig;

/// Computes the multiplicative inverse of each element in the given vector.
///
/// In other words, given elements e_1, ..., e_n returns 1/e_i if e_i != 0 and 0 otherwise.
pub fn batch_multiplicative_inverse<F: Field>(values: Vec<F>) -> Vec<F> {
    // Check if values are zero and construct a new vector with only nonzero values.
    let mut nonzero_values = Vec::with_capacity(values.len());
    let mut indices = Vec::with_capacity(values.len());
    for (i, value) in values.iter().cloned().enumerate() {
        if value.is_zero() {
            continue;
        }
        nonzero_values.push(value);
        indices.push(i);
    }

    // Compute the multiplicative inverse of nonzero values.
    let inverse_nonzero_values = p3_field::batch_multiplicative_inverse(&nonzero_values);

    // Reconstruct the original vector.
    let mut result = values.clone();
    for (i, index) in indices.into_iter().enumerate() {
        result[index] = inverse_nonzero_values[i];
    }

    result
}

// A generalization of even-odd decomposition.
fn decompose<F: TwoAdicField>(poly: Vec<F>, shift: F, log_chunks: usize) -> Vec<Vec<F>> {
    // For now, we use a naive recursive method.
    // A more optimized method might look similar to a decimation-in-time FFT,
    // but only the first `log_chunks` layers. It should also be parallelized.

    if log_chunks == 0 {
        return vec![poly];
    }

    let n = poly.len();
    debug_assert!(n > 1);
    let log_n = log2_strict_usize(n);
    let half_n = poly.len() / 2;
    let g_inv = F::two_adic_generator(log_n).inverse();

    let mut even = Vec::with_capacity(half_n);
    let mut odd = Vec::with_capacity(half_n);

    // Note that
    //     p_e(g^(2i)) = (p(g^i) + p(g^(n/2 + i))) / 2
    //     p_o(g^(2i)) = (p(g^i) - p(g^(n/2 + i))) / (2 s g^i)

    //     p_e(g^(2i)) = (a + b) / 2
    //     p_o(g^(2i)) = (a - b) / (2 s g^i)
    let one_half = F::two().inverse();
    let (first, second) = poly.split_at(half_n);
    for (g_inv_power, &a, &b) in izip!(g_inv.shifted_powers(shift.inverse()), first, second) {
        let sum = a + b;
        let diff = a - b;
        even.push(sum * one_half);
        odd.push(diff * one_half * g_inv_power);
    }

    let mut combined = decompose(even, shift.square(), log_chunks - 1);
    combined.extend(decompose(odd, shift.square(), log_chunks - 1));
    combined
}

/// Decompose the quotient polynomial into chunks using a generalization of even-odd decomposition.
/// Then, arrange the results in a row-major matrix, so that each chunk of the decomposed polynomial
/// becomes `D` columns of the resulting matrix, where `D` is the field extension degree.
pub fn decompose_and_flatten<SC: StarkConfig>(
    quotient_poly: Vec<SC::Challenge>,
    shift: SC::Challenge,
    log_chunks: usize,
) -> RowMajorMatrix<SC::Val> {
    let chunks: Vec<Vec<SC::Challenge>> = decompose(quotient_poly, shift, log_chunks);
    let degree = chunks[0].len();
    let quotient_chunks_flattened: Vec<SC::Val> = (0..degree)
        .into_par_iter()
        .flat_map_iter(|row| {
            chunks
                .iter()
                .flat_map(move |chunk| chunk[row].as_base_slice().iter().copied())
        })
        .collect();
    let challenge_ext_degree = <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
    RowMajorMatrix::new(
        quotient_chunks_flattened,
        challenge_ext_degree << log_chunks,
    )
}
