use crate::runtime::KernelPtr;

extern "C" {
    pub fn single_block_scan_kernel_large_bb31_septic_curve() -> KernelPtr;
    pub fn scan_kernel_large_bb31_septic_curve() -> KernelPtr;
}
