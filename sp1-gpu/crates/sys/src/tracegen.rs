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
}
