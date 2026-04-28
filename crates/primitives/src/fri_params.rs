use slop_primitives::FriConfig;

use crate::SP1Field;

pub const CORE_LOG_BLOWUP: usize = 2;
pub const RECURSION_LOG_BLOWUP: usize = 2;
pub const SP1_SHRINK_WRAP_POW_BITS: usize = 22;

pub fn core_fri_config() -> FriConfig<SP1Field> {
    FriConfig::new(
        CORE_LOG_BLOWUP,
        unique_decoding_queries(CORE_LOG_BLOWUP),
        SP1_PROOF_OF_WORK_BITS,
    )
}

pub const SHRINK_LOG_BLOWUP: usize = 3;
pub const WRAP_LOG_BLOWUP: usize = 3;

pub fn recursion_fri_config() -> FriConfig<SP1Field> {
    FriConfig::new(
        RECURSION_LOG_BLOWUP,
        unique_decoding_queries(RECURSION_LOG_BLOWUP),
        SP1_PROOF_OF_WORK_BITS,
    )
}

pub fn shrink_fri_config() -> FriConfig<SP1Field> {
    FriConfig::new(
        SHRINK_LOG_BLOWUP,
        unique_decoding_queries_with_custom_grinding(SHRINK_LOG_BLOWUP, SP1_SHRINK_WRAP_POW_BITS),
        SP1_SHRINK_WRAP_POW_BITS,
    )
}

pub fn wrap_fri_config() -> FriConfig<SP1Field> {
    FriConfig::new(
        WRAP_LOG_BLOWUP,
        unique_decoding_queries_with_custom_grinding(WRAP_LOG_BLOWUP, SP1_SHRINK_WRAP_POW_BITS),
        SP1_SHRINK_WRAP_POW_BITS,
    )
}

pub const SP1_TARGET_BITS_OF_SECURITY: usize = 100;
pub const SP1_PROOF_OF_WORK_BITS: usize = 16;

pub fn unique_decoding_queries(log_blowup: usize) -> usize {
    unique_decoding_queries_with_custom_grinding(log_blowup, SP1_PROOF_OF_WORK_BITS)
}
pub fn unique_decoding_queries_with_custom_grinding(
    log_blowup: usize,
    grinding_bits: usize,
) -> usize {
    // For unique decoding, we need to query at least half the symbols in the codeword.
    let rate = 1.0 / (1 << log_blowup) as f64;
    let half_rate_plus_half = 0.5 + (rate / 2.0);
    (-((SP1_TARGET_BITS_OF_SECURITY - grinding_bits) as f64) / half_rate_plus_half.log2()).ceil()
        as usize
}
