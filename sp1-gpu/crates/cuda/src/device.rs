use std::{
    ffi::{c_char, CStr},
    sync::OnceLock,
};

use crate::{CudaError, TaskScope};
use slop_alloc::{mem::CopyError, CopyIntoBackend, CopyToBackend, CpuBackend};
use sp1_gpu_sys::runtime::{cuda_get_device_name, cuda_mem_get_info};

pub trait DeviceCopy: Copy + 'static + Sized {}

impl<T: Copy + 'static + Sized> DeviceCopy for T {}

/// Returns a pair `(free, total)` of the amount of free and total memory on the device.
pub fn cuda_memory_info() -> Result<(usize, usize), CudaError> {
    let mut free: usize = 0;
    let mut total: usize = 0;
    CudaError::result_from_ffi(unsafe { cuda_mem_get_info(&mut free, &mut total) })?;
    Ok((free, total))
}

/// Returns the name of the CUDA device the calling thread is bound to, e.g. `"NVIDIA L4"`.
///
/// The name is queried once and cached for the lifetime of the process, because the underlying
/// `cudaGetDeviceProperties` call materializes the whole device property struct and costs tens of
/// milliseconds on the first call. Errors are never cached, so a failed query may be retried.
pub fn cuda_device_name() -> Result<&'static str, CudaError> {
    static DEVICE_NAME: OnceLock<String> = OnceLock::new();
    if let Some(name) = DEVICE_NAME.get() {
        return Ok(name);
    }

    // `cudaDeviceProp::name` is a 256 byte NUL terminated buffer, and the shim NUL terminates
    // whatever it writes, so a NUL is always present within the buffer.
    let mut name = [0u8; 256];
    CudaError::result_from_ffi(unsafe {
        cuda_get_device_name(name.as_mut_ptr().cast::<c_char>(), name.len())
    })?;
    let name = CStr::from_bytes_until_nul(&name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();

    Ok(DEVICE_NAME.get_or_init(|| name))
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
