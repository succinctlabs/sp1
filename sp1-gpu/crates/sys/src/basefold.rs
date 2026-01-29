use crate::runtime::KernelPtr;

extern "C" {
    pub fn batch_koala_bear_base_ext_kernel() -> KernelPtr;
    pub fn batch_koala_bear_base_ext_kernel_flattened() -> KernelPtr;
    pub fn transpose_even_odd_koala_bear_base_ext_kernel() -> KernelPtr;
    pub fn flatten_to_base_koala_bear_base_ext_kernel() -> KernelPtr;
}
