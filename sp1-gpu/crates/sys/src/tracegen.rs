use crate::runtime::KernelPtr;

extern "C" {
    pub fn riscv_global_generate_trace_decompress_kernel() -> KernelPtr;
    pub fn riscv_global_generate_trace_finalize_kernel() -> KernelPtr;
    pub fn recursion_base_alu_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_base_alu_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_ext_alu_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_ext_alu_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_poseidon2_wide_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_poseidon2_wide_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_select_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_select_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_prefix_sum_checks_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_convert_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_convert_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_linear_layer_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_linear_layer_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_sbox_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_sbox_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn witgen_interp_koala_bear_kernel() -> KernelPtr;
    pub fn witgen_lookup_koala_bear_kernel() -> KernelPtr;
    pub fn witgen_fused_koala_bear_kernel() -> KernelPtr;
    // Slot-indexed (register-allocated) variants for WIDE gadgets (Mul/DivRem):
    // per-thread wire array bounded by max-live slots, not one cell per op.
    pub fn witgen_interp_slots_koala_bear_kernel() -> KernelPtr;
    pub fn witgen_lookup_slots_koala_bear_kernel() -> KernelPtr;
    pub fn witgen_fused_slots_koala_bear_kernel() -> KernelPtr;
    // Streaming store-through fused kernel with shared-memory wires (cap 24).
    pub fn witgen_fused_streaming_smem_koala_bear_kernel() -> KernelPtr;
    pub fn witgen_fused_streaming_koala_bear_kernel() -> KernelPtr;
    pub fn hist_to_trace_koala_bear_kernel() -> KernelPtr;
    pub fn hist_trace_scatter_koala_bear_kernel() -> KernelPtr;
    // Padding-template broadcast over a trace's padding rows (H2 device fill).
    pub fn witgen_template_fill_koala_bear_kernel() -> KernelPtr;
}
