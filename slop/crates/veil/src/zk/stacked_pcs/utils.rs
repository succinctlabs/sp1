use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::Mle;
use thiserror::Error;

/// Reshapes a flat MLE into a stacked MLE with `2^log_stacking_height` columns.
///
/// The flat MLE's data is reinterpreted as a matrix with `2^log_stacking_height` columns,
/// effectively splitting one large polynomial into multiple smaller polynomials.
///
/// # Panics
/// Panics if the MLE's total length is not divisible by `2^log_stacking_height`.
pub fn stack_mle<F: Copy + Send + Sync>(mle: Mle<F>, log_stacking_height: usize) -> Mle<F> {
    let data = mle.into_guts().into_buffer().into_vec();
    Mle::new(RowMajorMatrix::new(data, 1 << log_stacking_height).into())
}

#[derive(Debug, Error, Clone)]
pub enum PaddingComputationError {
    #[error("Security level unreachable for given code parameters: inverse_rate={inverse_rate}, codeword_length={codeword_length}, security_bits={security_bits}")]
    SecurityLevelUnreachable { inverse_rate: usize, codeword_length: usize, security_bits: usize },
}

/// Computes the padding amount needed for padded commitments.
///
/// Note that padding the input by `q` increases the effective rate of the code:
/// `ρ = ρ_0 + q / L`, where `L` is the codeword length.
///
/// For `b` bits of security, we solve:
/// `q >= -b/log_2(1/2 + ρ_0/2 + q/2L)` with `2L` large.
///
/// Taylor expanding with `λ = log_2(1/2 + ρ_0/2)`:
/// `q >= -b/λ (1 - b/L(1 + ρ) ln(2) λ^2)^(-1)`
///
/// # Errors
///
/// Returns [`PaddingComputationError::SecurityLevelUnreachable`] if the message length is too
/// low to achieve the requested security level with this strategy.
pub fn compute_padding_amount(
    inverse_rate: usize,
    codeword_length: usize,
    security_bits: usize,
) -> Result<usize, PaddingComputationError> {
    let rho = (inverse_rate as f64).recip();
    let b = security_bits as f64;
    let l = codeword_length as f64;
    const LN_2: f64 = std::f64::consts::LN_2;

    let lambda = -(0.5 + 0.5 * rho).log2();
    let correction_factor = 1.0 - b / ((l * LN_2 * lambda * lambda) * (1.0 + rho));
    if correction_factor <= 0.0 {
        return Err(PaddingComputationError::SecurityLevelUnreachable {
            inverse_rate,
            codeword_length,
            security_bits,
        });
    }
    let out64 = b / lambda * correction_factor.recip();

    Ok(out64.ceil() as usize)
}
