use sp1_gpu_sys::runtime::KernelPtr;
use sp1_primitives::SP1Field;

use crate::TaskScope;

/// # Safety
pub unsafe trait ScanKernel<F> {
    fn single_block_scan_kernel_large_bb31_septic_curve() -> KernelPtr;
    fn scan_kernel_large_bb31_septic_curve() -> KernelPtr;
}

unsafe impl ScanKernel<SP1Field> for TaskScope {
    fn single_block_scan_kernel_large_bb31_septic_curve() -> KernelPtr {
        unsafe { sp1_gpu_sys::scan::single_block_scan_kernel_large_bb31_septic_curve() }
    }
    fn scan_kernel_large_bb31_septic_curve() -> KernelPtr {
        unsafe { sp1_gpu_sys::scan::scan_kernel_large_bb31_septic_curve() }
    }
}
