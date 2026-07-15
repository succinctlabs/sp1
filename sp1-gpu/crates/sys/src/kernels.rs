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

    // Fused dispatch: one launch per non-empty tier handles every
    // Sequential chunk in a round. The launcher's per-block dispatch
    // descriptor maps each block to its `(chunk_id, row_offset, n_rows)`.
    pub fn zerocheck_fused_sequential_kb_32_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_kb_64_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_kb_128_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_kb_256_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_kb_512_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_kb_1024_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_ext_32_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_ext_64_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_ext_128_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_ext_256_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_ext_512_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_ext_1024_kernel() -> KernelPtr;

    // zerocheck (DAG-native): bivariate variants for the fused
    // first-two-rounds evaluation. Eval nodes on blockIdx.z (12 non-boolean
    // grid nodes of {0,1,2,4}^2), quadruple row consumption, output stride
    // 12. Round 0 only — base-field trace.
    pub fn zerocheck_fused_sequential_bivariate_kb_32_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_bivariate_kb_64_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_bivariate_kb_128_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_bivariate_kb_256_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_bivariate_kb_512_kernel() -> KernelPtr;
    pub fn zerocheck_fused_sequential_bivariate_kb_1024_kernel() -> KernelPtr;

    // zerocheck (DAG-native): ColumnTile lowering kernels.
    pub fn zerocheck_column_tile_kb_kernel() -> KernelPtr;
    pub fn zerocheck_column_tile_ext_kernel() -> KernelPtr;

    // zerocheck (DAG-native): per-chip geq correction. One block per chip,
    // writes 3 ext_t partials per chip (one per eval point) that the host
    // aggregation sums into the round's totals.
    pub fn zerocheck_geq_corrections_kernel() -> KernelPtr;

    // zerocheck (DAG-native): bivariate geq correction for the fused
    // first-two-rounds. One block per geq chip, 12 ext_t partials per chip
    // (one per non-boolean grid node).
    pub fn zerocheck_geq_corrections_bivariate_kernel() -> KernelPtr;

    // zerocheck (DAG-native): apply `VirtualGeq::fix_last_variable(alpha)`
    // in place to each chip's geq state. One thread per chip.
    pub fn zerocheck_fix_geq_state_kernel() -> KernelPtr;

    // zerocheck (DAG-native): aggregate per-block partials into the 3
    // per-eval-point totals via a single-block grid-stride reduction. The
    // host then only downloads the 3 totals instead of the full partials.
    pub fn zerocheck_aggregate_partials_kernel() -> KernelPtr;

    // zerocheck (DAG-native): strided aggregation for the fused
    // first-two-rounds partials ([group][e] layout with `stride` slots per
    // group). Launched with gridDim.x == stride.
    pub fn zerocheck_aggregate_partials_strided_kernel() -> KernelPtr;

    // zerocheck (DAG-native): per-chip GKR column sweep. Decoupled from the
    // sequential constraint kernel so wide chips can parallelise the column
    // reduction across a warp's lanes. One block per (chip, row-tile).
    pub fn zerocheck_gkr_sweep_kb_kernel() -> KernelPtr;
    pub fn zerocheck_gkr_sweep_ext_kernel() -> KernelPtr;

    // zerocheck (DAG-native): GKR corner sweep for the fused
    // first-two-rounds — the opening batch at the four boolean grid corners
    // (raw rows of each quadruple, no interpolation). Output stride 4.
    pub fn zerocheck_gkr_corner_sweep_kb_kernel() -> KernelPtr;

    // zerocheck (DAG-native): per-chunk padded_row_adjustment via the
    // bytecode interpreter at the all-zero trace. One thread per chunk;
    // output is one ext_t per chunk, summed by chip on the host into the
    // per-chip `padded_row_adjustment`. Tiered by MAX_REGS like
    // `fused_sequential`.
    pub fn zerocheck_pad_adj_32_kernel() -> KernelPtr;
    pub fn zerocheck_pad_adj_64_kernel() -> KernelPtr;
    pub fn zerocheck_pad_adj_128_kernel() -> KernelPtr;
    pub fn zerocheck_pad_adj_256_kernel() -> KernelPtr;
    pub fn zerocheck_pad_adj_512_kernel() -> KernelPtr;
    pub fn zerocheck_pad_adj_1024_kernel() -> KernelPtr;

    // JaggedMle fold-metadata: one fused multi-block kernel reads
    // `column_heights`, writes `new_column_heights` (= `h.div_ceil(4)*2`
    // element-wise) and `new_start_indices` (= exclusive prefix sum) — all
    // on device, no host round-trip. Uses decoupled-lookback to handle any
    // n_columns. See `include/jagged_assist/fold_metadata.cuh` for the
    // caller-init contract on `block_counter`, `flags`, `scan_values`.
    pub fn jagged_fold_metadata_kernel() -> KernelPtr;
    pub fn jagged_fold_metadata_block_dim() -> u32;
    pub fn jagged_fold_metadata_section_size() -> u32;

    // JaggedMle chip-layouts: reads `start_indices` + `column_heights` at
    // the sparse per-chip positions described by `ChipColumnLayoutEntry`,
    // writes per-chip `ChipLayout[chip_idx]` + `chip_heights[chip_idx]`.
    // One thread per chip. See `include/jagged_assist/chip_layouts.cuh`.
    pub fn jagged_chip_layouts_kernel() -> KernelPtr;

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
