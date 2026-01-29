use crate::runtime::KernelPtr;

extern "C" {
    pub fn addKernelu32Ptr() -> KernelPtr;
    pub fn add_koala_bear_kernel() -> KernelPtr;
    pub fn add_koala_bear_ext_ext_kernel() -> KernelPtr;
    pub fn add_koala_bear_base_ext_kernel() -> KernelPtr;
    pub fn add_assign_koala_bear_kernel() -> KernelPtr;
    pub fn add_assign_koala_bear_ext_kernel() -> KernelPtr;
}
