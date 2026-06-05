use std::ffi::c_void;

use crate::runtime::{CudaRustError, CudaStreamHandle, KernelPtr};

extern "C" {
    // Sum kernels
    pub fn sum_kernel_u32() -> KernelPtr;
    pub fn sum_kernel_felt() -> KernelPtr;
    pub fn sum_kernel_ext() -> KernelPtr;

    // Tracegen kernels
    pub fn generate_col_index() -> KernelPtr;
    pub fn generate_start_indices() -> KernelPtr;
    pub fn fill_buffer() -> KernelPtr;
    pub fn count_and_add_kernel() -> KernelPtr;
    pub fn sum_to_trace_kernel() -> KernelPtr;

    // Reduce kernels
    pub fn reduce_kernel_felt() -> KernelPtr;
    pub fn reduce_kernel_ext() -> KernelPtr;

    // JaggedMLE kernels
    pub fn jagged_eval_kernel_chunked_felt() -> KernelPtr;
    pub fn jagged_eval_kernel_chunked_ext() -> KernelPtr;

    // JaggedInfo kernels
    pub fn initialize_jagged_info() -> KernelPtr;
    pub fn fix_last_variable_jagged_info() -> KernelPtr;

    // Basic jagged fix last variable
    pub fn fix_last_variable_jagged_felt() -> KernelPtr;
    pub fn fix_last_variable_jagged_ext() -> KernelPtr;

    // Jagged Zerocheck Kernels
    pub fn jagged_constraint_poly_eval_32_koala_bear_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_64_koala_bear_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_128_koala_bear_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_256_koala_bear_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_512_koala_bear_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_1024_koala_bear_kernel() -> KernelPtr;

    pub fn jagged_constraint_poly_eval_32_koala_bear_extension_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_64_koala_bear_extension_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_128_koala_bear_extension_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_256_koala_bear_extension_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_512_koala_bear_extension_kernel() -> KernelPtr;
    pub fn jagged_constraint_poly_eval_1024_koala_bear_extension_kernel() -> KernelPtr;

    // Zerocheck kernels
    pub fn zerocheck_sum_as_poly_base_ext_kernel() -> KernelPtr;
    pub fn zerocheck_sum_as_poly_ext_ext_kernel() -> KernelPtr;

    pub fn zerocheck_fix_last_variable_and_sum_as_poly_base_ext_kernel() -> KernelPtr;
    pub fn zerocheck_fix_last_variable_and_sum_as_poly_ext_ext_kernel() -> KernelPtr;

    // Hadamard kernels
    pub fn hadamard_sum_as_poly_base_ext_kernel() -> KernelPtr;
    pub fn hadamard_sum_as_poly_ext_ext_kernel() -> KernelPtr;

    pub fn hadamard_fix_last_variable_and_sum_as_poly_base_ext_kernel() -> KernelPtr;
    pub fn hadamard_fix_last_variable_and_sum_as_poly_ext_ext_kernel() -> KernelPtr;

    pub fn fix_last_variable_felt_ext_kernel() -> KernelPtr;
    pub fn fix_last_variable_ext_ext_kernel() -> KernelPtr;
    pub fn mle_fix_last_variable_koala_bear_base_base_constant_padding() -> KernelPtr;
    pub fn mle_fix_last_variable_koala_bear_base_extension_constant_padding() -> KernelPtr;
    pub fn mle_fix_last_variable_koala_bear_ext_ext_constant_padding() -> KernelPtr;

    pub fn mle_fix_last_variable_koala_bear_ext_ext_zero_padding() -> KernelPtr;
    pub fn mle_fix_last_variable_koala_bear_base_extension_zero_padding() -> KernelPtr;

    // Product sumcheck round-0 sum-as-poly kernels (base-field input only).
    pub fn product_sumcheck_sum_as_poly_base_2_kernel() -> KernelPtr;
    pub fn product_sumcheck_sum_as_poly_base_4_kernel() -> KernelPtr;
    pub fn product_sumcheck_sum_as_poly_base_8_kernel() -> KernelPtr;
    pub fn product_sumcheck_sum_as_poly_base_16_kernel() -> KernelPtr;
    pub fn product_sumcheck_sum_as_poly_base_32_kernel() -> KernelPtr;
    pub fn product_sumcheck_sum_as_poly_base_64_kernel() -> KernelPtr;

    // Simple (thread-per-x_top) fused fix-and-sum, used for small K (K ∈ {2, 4, 8}).
    pub fn product_sumcheck_fix_and_sum_base_2_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_base_4_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_base_8_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_ext_2_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_ext_4_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_ext_8_kernel() -> KernelPtr;

    // Cooperative (K-threads-per-tile, TPB = 256/K) fused fix-and-sum, used for large K
    // (K ∈ {16, 32, 64}) where the simple kernel spills.
    pub fn product_sumcheck_fix_and_sum_coop_base_16_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_coop_base_32_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_coop_base_64_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_coop_ext_16_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_coop_ext_32_kernel() -> KernelPtr;
    pub fn product_sumcheck_fix_and_sum_coop_ext_64_kernel() -> KernelPtr;

    // Eq-prefixed product sumcheck (K=64) — Option 1 of the two-stage-GKR shape.
    pub fn eq_product_sum_as_poly_base_64_coop_kernel() -> KernelPtr;
    pub fn eq_product_sum_as_poly_ext_64_coop_kernel() -> KernelPtr;
    pub fn eq_prefix_fold_kernel() -> KernelPtr;
    pub fn eq_product_fix_and_sum_base_64_coop_kernel() -> KernelPtr;
    pub fn eq_product_fix_and_sum_ext_64_coop_kernel() -> KernelPtr;

    // Two-stage-GKR Option 2 — all five (K_1, K_2) splits of K = 64.
    pub fn build_b_mles_2_32_kernel() -> KernelPtr;
    pub fn build_b_mles_4_16_kernel() -> KernelPtr;
    pub fn build_b_mles_8_8_kernel() -> KernelPtr;
    pub fn build_b_mles_16_4_kernel() -> KernelPtr;
    pub fn build_b_mles_32_2_kernel() -> KernelPtr;

    pub fn two_stage_stage1_sum_as_poly_ext_2_kernel() -> KernelPtr;
    pub fn two_stage_stage1_fix_and_sum_ext_2_kernel() -> KernelPtr;
    pub fn two_stage_stage1_sum_as_poly_ext_4_kernel() -> KernelPtr;
    pub fn two_stage_stage1_fix_and_sum_ext_4_kernel() -> KernelPtr;
    pub fn two_stage_stage1_sum_as_poly_ext_8_kernel() -> KernelPtr;
    pub fn two_stage_stage1_fix_and_sum_ext_8_kernel() -> KernelPtr;
    pub fn two_stage_stage1_sum_as_poly_ext_16_kernel() -> KernelPtr;
    pub fn two_stage_stage1_fix_and_sum_ext_16_kernel() -> KernelPtr;
    pub fn two_stage_stage1_sum_as_poly_ext_32_kernel() -> KernelPtr;
    pub fn two_stage_stage1_fix_and_sum_ext_32_kernel() -> KernelPtr;

    pub fn two_stage_stage2_sum_as_poly_base_2_32_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_base_2_32_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_ext_2_32_kernel() -> KernelPtr;
    pub fn two_stage_stage2_sum_as_poly_base_4_16_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_base_4_16_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_ext_4_16_kernel() -> KernelPtr;
    pub fn two_stage_stage2_sum_as_poly_base_8_8_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_base_8_8_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_ext_8_8_kernel() -> KernelPtr;
    pub fn two_stage_stage2_sum_as_poly_base_16_4_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_base_16_4_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_ext_16_4_kernel() -> KernelPtr;
    pub fn two_stage_stage2_sum_as_poly_base_32_2_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_base_32_2_kernel() -> KernelPtr;
    pub fn two_stage_stage2_fix_and_sum_ext_32_2_kernel() -> KernelPtr;

    // ******** LogUp GKR kernels - Round operations ********
    pub fn logup_gkr_sum_as_poly_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_first_sum_as_poly_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_fix_last_variable_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_fix_last_variable_last_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_sum_as_poly_interactions_layer() -> KernelPtr;
    pub fn logup_gkr_fix_last_variable_interactions_layer() -> KernelPtr;

    // LogUp GKR kernels - First layer operations
    pub fn logup_gkr_fix_last_variable_first_layer() -> KernelPtr;
    pub fn logup_gkr_fix_and_sum_first_layer() -> KernelPtr;
    pub fn logup_gkr_sum_as_poly_first_layer() -> KernelPtr;
    pub fn logup_gkr_first_layer_transition() -> KernelPtr;

    // LogUp GKR kernels - Execution operations
    pub fn logup_gkr_circuit_transition() -> KernelPtr;
    pub fn logup_gkr_populate_last_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_extract_output() -> KernelPtr;

    // Logup GKR kernels - Fused fix and sum kernels
    pub fn logup_gkr_fix_and_sum_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_fix_and_sum_last_circuit_layer() -> KernelPtr;
    pub fn logup_gkr_fix_and_sum_interactions_layer() -> KernelPtr;

    // ******** Jagged sumcheck kernels ********
    pub fn jagged_sum_as_poly() -> KernelPtr;
    pub fn jagged_fix_and_sum() -> KernelPtr;
    pub fn padded_hadamard_fix_and_sum() -> KernelPtr;

    // ******** Boolean-batched sumcheck kernels ********
    pub fn boolean_inc_table_kernel() -> KernelPtr;
    pub fn boolean_sum_as_poly_half_kernel() -> KernelPtr;
    pub fn boolean_curr_bits_ext_kernel() -> KernelPtr;

    // ******** Two-to-one Option-2 sumcheck kernels ********
    pub fn two_to_one_sum_as_poly_zero_kernel() -> KernelPtr;

    // Populate restrict eq
    pub fn populate_restrict_eq_host(
        src: *const c_void,
        len: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;
    pub fn populate_restrict_eq_device(
        src: *const c_void,
        len: usize,
        stream: CudaStreamHandle,
    ) -> CudaRustError;

    // ******** Hadamard look ahead kernels ********
    // Look ahead kernels - FIX_TILE=32
    pub fn round_kernel_1_32_2_2_false() -> KernelPtr;
    pub fn round_kernel_2_32_2_2_true() -> KernelPtr;
    pub fn round_kernel_2_32_2_2_false() -> KernelPtr;
    pub fn round_kernel_4_32_2_2_true() -> KernelPtr;
    pub fn round_kernel_4_32_2_2_false() -> KernelPtr;
    pub fn round_kernel_8_32_2_2_true() -> KernelPtr;
    pub fn round_kernel_8_32_2_2_false() -> KernelPtr;

    // Look ahead kernels - FIX_TILE=64
    pub fn round_kernel_1_64_2_2_false() -> KernelPtr;
    pub fn round_kernel_2_64_2_2_true() -> KernelPtr;
    pub fn round_kernel_2_64_2_2_false() -> KernelPtr;
    pub fn round_kernel_4_64_2_2_true() -> KernelPtr;
    pub fn round_kernel_4_64_2_2_false() -> KernelPtr;
    pub fn round_kernel_8_64_2_2_true() -> KernelPtr;
    pub fn round_kernel_8_64_2_2_false() -> KernelPtr;

    // Look ahead kernels - NUM_POINTS=3, FIX_TILE=32
    pub fn round_kernel_1_32_2_3_false() -> KernelPtr;
    pub fn round_kernel_2_32_2_3_true() -> KernelPtr;
    pub fn round_kernel_2_32_2_3_false() -> KernelPtr;
    pub fn round_kernel_4_32_2_3_true() -> KernelPtr;
    pub fn round_kernel_4_32_2_3_false() -> KernelPtr;
    pub fn round_kernel_8_32_2_3_true() -> KernelPtr;
    pub fn round_kernel_8_32_2_3_false() -> KernelPtr;

    // Look ahead kernels - NUM_POINTS=3, FIX_TILE=64
    pub fn round_kernel_1_64_2_3_false() -> KernelPtr;
    pub fn round_kernel_1_64_4_8_false() -> KernelPtr;
    pub fn round_kernel_2_64_2_3_true() -> KernelPtr;
    pub fn round_kernel_2_64_2_3_false() -> KernelPtr;
    pub fn round_kernel_4_64_2_3_true() -> KernelPtr;
    pub fn round_kernel_4_64_2_3_false() -> KernelPtr;
    pub fn round_kernel_4_64_4_8_true() -> KernelPtr;
    pub fn round_kernel_4_64_4_8_false() -> KernelPtr;
    pub fn round_kernel_8_64_2_3_true() -> KernelPtr;
    pub fn round_kernel_8_64_2_3_false() -> KernelPtr;

    // Look ahead kernels - FIX_TILE=128
    pub fn round_kernel_1_128_4_8_false() -> KernelPtr;
}
