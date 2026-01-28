use crate::{CudaError, TaskScope};
use slop_alloc::{mem::CopyError, CopyIntoBackend, CopyToBackend, CpuBackend};
use sp1_gpu_sys::runtime::cuda_mem_get_info;

pub trait DeviceCopy: Copy + 'static + Sized {}

impl<T: Copy + 'static + Sized> DeviceCopy for T {}

/// Returns a pair `(free, total)` of the amount of free and total memory on the device.
pub fn cuda_memory_info() -> Result<(usize, usize), CudaError> {
    let mut free: usize = 0;
    let mut total: usize = 0;
    CudaError::result_from_ffi(unsafe { cuda_mem_get_info(&mut free, &mut total) })?;
    Ok((free, total))
}

pub trait IntoDevice: CopyIntoBackend<TaskScope, CpuBackend> + Sized {
    fn into_device_in(self, backend: &TaskScope) -> Result<Self::Output, CopyError> {
        self.copy_into_backend(backend)
    }
}

impl<T> IntoDevice for T where T: CopyIntoBackend<TaskScope, CpuBackend> + Sized {}

pub trait ToDevice: CopyToBackend<TaskScope, CpuBackend> + Sized {
    fn to_device_in(&self, backend: &TaskScope) -> Result<Self::Output, CopyError> {
        self.copy_to_backend(backend)
    }
}

impl<T> ToDevice for T where T: CopyToBackend<TaskScope, CpuBackend> + Sized {}

#[macro_export]
macro_rules! args {
    ($($arg:expr),*) => {
        [
            $(
                &$arg as *const _ as *mut std::ffi::c_void
            ),*
        ]
    };
}
