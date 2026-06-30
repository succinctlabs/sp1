//! ZK rate-correction analysis for the stacked PCS.
//!
//! The ZK commit appends one random hiding row per base-PCS query to each committed polynomial
//! (see the `zk_commit_mles` logic in [`super::prover`]): a message of `2^k` rows becomes `2^k + q`
//! rows, zero-padded to `2^(k+1)` and encoded at `log_blowup - 1` so the codeword length `L =
//! 2^(k + log_blowup)` is unchanged. The committed code therefore has a slightly *higher* rate
//! than the base PCS's nominal `ρ₀ = 2^(-log_blowup)`:
//!
//! ```text
//! ρ_eff = (2^k + q) / L = ρ₀ + q/L
//! ```
//!
//! A higher rate means fewer bits of security per FRI query, so in principle veil needs slightly
//! *more* queries than the base PCS to hit the same security level (see the veil paper,
//! <https://eprint.iacr.org/2026/683>). [`compute_padding_amount`] solves the self-consistent
//! requirement (the padding *is* the query count, so `q` appears on both sides):
//!
//! ```text
//! q ≥ b / λ(ρ₀ + q/L),    λ(ρ) = -log₂((1 + ρ)/2)
//! ```
//!
//! [`VEIL_EXTRA_QUERIES`] is the number of extra queries veil adds on top of the base PCS's
//! count to cover this; the ignored test below double-checks the value against the production
//! parameters.

use thiserror::Error;

/// Extra base-PCS queries (and hiding rows) veil uses on top of the base PCS's `num_queries`, to
/// compensate for the rate shift described in the [module docs](self). Every use of the base
/// PCS's query count inside veil goes through `num_zk_queries = num_queries + VEIL_EXTRA_QUERIES`
/// rather than `num_queries` directly, so this constant is the single knob.
///
/// **Why 0:** at production parameters (`log_blowup = 1`, stacking height `2^21`, codeword
/// length `2^22`, ~100-bit target) the self-consistent count exceeds the naive `⌈b/λ(ρ₀)⌉` by
/// only ~0.03 queries, which the ceiling's own rounding slack (~0.06 queries) absorbs — the
/// integer query count does not change. Equivalently, holding the query count fixed instead, the
/// rate shift costs well under 0.01 bits of security there. The margin is parameter-dependent
/// (at stacking height `2^16` the corrected count is genuinely ~1–3 queries higher), so re-run
/// `check_veil_extra_queries` (`cargo test -p slop-veil -- --ignored check_veil_extra_queries`)
/// when changing the FRI config, the security target, or the minimum stacking height.
pub const VEIL_EXTRA_QUERIES: usize = 0;

#[derive(Debug, Error, Clone)]
pub enum PaddingComputationError {
    #[error("Security level unreachable for given code parameters: inverse_rate={inverse_rate}, codeword_length={codeword_length}, security_bits={security_bits}")]
    SecurityLevelUnreachable { inverse_rate: usize, codeword_length: usize, security_bits: usize },
}

/// Computes the number of queries (= hiding/padding rows) needed for `security_bits` bits of
/// proximity-test security on the *padded* code, accounting for the rate shift the padding itself
/// causes (see the [module docs](self)).
///
/// Padding the message by `q` rows raises the effective rate to `ρ = ρ₀ + q/L`, where `L` is the
/// (unchanged) codeword length. For `b` bits of security under the unique-decoding per-query
/// bound `(1 + ρ)/2`, we solve the self-consistent
///
/// ```text
/// q ≥ b / -log₂(1/2 + ρ₀/2 + q/2L)
/// ```
///
/// by Taylor expansion around `λ = -log₂(1/2 + ρ₀/2)`:
///
/// ```text
/// q ≥ (b/λ) · (1 - b / (L·ln2·λ²·(1 + ρ₀)))⁻¹
/// ```
///
/// (accurate to well under one query for codeword lengths of interest). Compare against the
/// naive `⌈b/λ⌉` to decide [`VEIL_EXTRA_QUERIES`].
///
/// # Errors
///
/// Returns [`PaddingComputationError::SecurityLevelUnreachable`] if the codeword is too short to
/// achieve the requested security level with this strategy.
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

#[cfg(test)]
mod tests {
    use super::*;
    use slop_basefold::FriConfig;
    use slop_koala_bear::KoalaBear;

    /// Diagnostic check for [`VEIL_EXTRA_QUERIES`] — deliberately `#[ignore]`d so it is not part
    /// of the standard suite; it exists only to re-validate the constant when parameters change:
    ///
    /// ```text
    /// cargo test -p slop-veil -- --ignored check_veil_extra_queries
    /// ```
    ///
    /// Asserts that at production-scale parameters (default FRI config, stacking heights ≥ 2^21,
    /// 100-bit target) the rate-corrected query count exceeds the naive `⌈b/λ(ρ₀)⌉` by at most
    /// `VEIL_EXTRA_QUERIES` — i.e. the correction is absorbed by the ceiling's rounding slack.
    /// Also demonstrates that the issue is real: at small stacking heights the corrected count is
    /// strictly larger, so the constant cannot be assumed 0 for arbitrary parameters.
    #[test]
    #[ignore = "diagnostic for VEIL_EXTRA_QUERIES; re-run when changing FRI/security parameters"]
    fn check_veil_extra_queries() {
        let fri_config = FriConfig::<KoalaBear>::default_fri_config();
        let inverse_rate = 1usize << fri_config.log_blowup;
        let security_bits = 100usize;

        // Naive count, ignoring the rate shift.
        let rho = (inverse_rate as f64).recip();
        let lambda = -(0.5 + 0.5 * rho).log2();
        let naive = (security_bits as f64 / lambda).ceil() as usize;

        // At production stacking heights (CORE_LOG_STACKING_HEIGHT = 21 and up), the correction
        // must be covered by VEIL_EXTRA_QUERIES.
        for log_stacking_height in 21..=24 {
            let codeword_length = 1usize << (log_stacking_height + fri_config.log_blowup);
            let corrected =
                compute_padding_amount(inverse_rate, codeword_length, security_bits).unwrap();
            eprintln!(
                "stacking height 2^{log_stacking_height}: naive {naive}, corrected {corrected}"
            );
            assert!(
                corrected <= naive + VEIL_EXTRA_QUERIES,
                "rate correction at stacking height 2^{log_stacking_height} needs \
                 {corrected} queries > naive {naive} + VEIL_EXTRA_QUERIES {VEIL_EXTRA_QUERIES}; \
                 increase VEIL_EXTRA_QUERIES"
            );
        }

        // Sanity check that the correction is real: at a small stacking height it costs extra
        // queries, so VEIL_EXTRA_QUERIES = 0 is a parameter-dependent fact, not a theorem.
        let small_codeword_length = 1usize << (16 + fri_config.log_blowup);
        let corrected_small =
            compute_padding_amount(inverse_rate, small_codeword_length, security_bits).unwrap();
        eprintln!("stacking height 2^16: naive {naive}, corrected {corrected_small}");
        assert!(corrected_small > naive, "expected a visible correction at small heights");
    }
}
