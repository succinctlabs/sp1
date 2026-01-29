use sp1_gpu_sys::{
    algebra::{
        add_assign_koala_bear_ext_kernel, add_assign_koala_bear_kernel,
        add_koala_bear_base_ext_kernel, add_koala_bear_ext_ext_kernel, add_koala_bear_kernel,
    },
    runtime::KernelPtr,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
// AddAssignBackend and AddBackend removed - using DeviceTensor methods instead

use crate::{args, DeviceCopy, DeviceTensor, TaskScope};

///
/// # Safety
pub unsafe trait AddKernel<U: DeviceCopy, T: DeviceCopy> {
    fn add_kernel() -> KernelPtr;
}

/// # Safety
/// The implementor must ensure the kernel performs element-wise add-assign correctly.
#[allow(dead_code)]
pub unsafe trait AddAssignKernel<T: DeviceCopy> {
    fn add_assign_kernel() -> KernelPtr;
}

impl<T: DeviceCopy> DeviceTensor<T> {
    pub fn add<U: DeviceCopy>(&self, other: &DeviceTensor<U>) -> DeviceTensor<T>
    where
        TaskScope: AddKernel<U, T>,
    {
        let mut dst = Self::with_sizes_in(self.sizes(), self.backend().clone());
        unsafe {
            dst.assume_init();
        }
        const BLOCK_SIZE: usize = 256;
        const GRID_STRIDE: usize = 1;
        unsafe {
            let grid_dim = self.total_len().div_ceil(BLOCK_SIZE).div_ceil(GRID_STRIDE);
            let args = args!(self.as_ptr(), other.as_ptr(), dst.as_ptr(), self.total_len());
            self.backend()
                .launch_kernel(TaskScope::add_kernel(), grid_dim, BLOCK_SIZE, &args, 0)
                .unwrap();
        }
        dst
    }
}

unsafe impl AddKernel<SP1Field, SP1Field> for TaskScope {
    fn add_kernel() -> KernelPtr {
        unsafe { add_koala_bear_kernel() }
    }
}

unsafe impl AddKernel<SP1ExtensionField, SP1Field> for TaskScope {
    fn add_kernel() -> KernelPtr {
        unsafe { add_koala_bear_base_ext_kernel() }
    }
}

unsafe impl AddKernel<SP1ExtensionField, SP1ExtensionField> for TaskScope {
    fn add_kernel() -> KernelPtr {
        unsafe { add_koala_bear_ext_ext_kernel() }
    }
}

unsafe impl AddAssignKernel<SP1Field> for TaskScope {
    fn add_assign_kernel() -> KernelPtr {
        unsafe { add_assign_koala_bear_kernel() }
    }
}

unsafe impl AddAssignKernel<SP1ExtensionField> for TaskScope {
    fn add_assign_kernel() -> KernelPtr {
        unsafe { add_assign_koala_bear_ext_kernel() }
    }
}
