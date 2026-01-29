use crate::runtime::KernelPtr;

extern "C" {
    pub fn jagged_koala_bear_extension_populate() -> KernelPtr;

    pub fn jagged_koala_bear_base_ext_sum_as_poly() -> KernelPtr;
    pub fn jagged_koala_bear_extension_virtual_fix_last_variable() -> KernelPtr;

    pub fn branching_program_kernel() -> KernelPtr;

    pub fn interpolateAndObserve_kernel_duplex() -> KernelPtr;

    pub fn interpolateAndObserve_kernel_multi_field_32() -> KernelPtr;

    pub fn transition_kernel() -> KernelPtr;

    pub fn fixLastVariable_kernel() -> KernelPtr;
}
