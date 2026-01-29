use core::fmt;
use std::ffi::CStr;

use sp1_gpu_sys::runtime::{
    CudaRustError, CUDA_ERROR_NOT_READY_SLOP, CUDA_OUT_OF_MEMORY, CUDA_SUCCESS_CSL,
};
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OtherError(CudaRustError);

#[derive(Clone, Debug, Copy, PartialEq, Eq, Error)]
pub enum CudaError {
    #[error("out of GPU memory")]
    OutOfMemory,
    #[error("not ready")]
    NotReady,
    #[error("other CUDA error: {0}")]
    Other(#[from] OtherError),
}

unsafe impl Send for CudaError {}
unsafe impl Sync for CudaError {}

impl CudaError {
    /// Get a result from a [CudaRustError].
    ///
    /// The [CudaRustError] is the FFI representation of the cuda runtime result enum which could
    /// signal a success or an error. In case of success, this method returns `Ok(())`. In case of
    /// an error, this method returns an error of the appropriate type.
    #[inline]
    pub fn result_from_ffi(maybe_error: CudaRustError) -> Result<(), Self> {
        // # Safety
        // These constants are well defined in the sys crate.
        unsafe {
            match maybe_error {
                e if e == CUDA_SUCCESS_CSL => Ok(()),
                e if e == CUDA_OUT_OF_MEMORY => Err(Self::OutOfMemory),
                e if e == CUDA_ERROR_NOT_READY_SLOP => Err(Self::NotReady),
                _ => Err(Self::Other(OtherError(maybe_error))),
            }
        }
    }
}

impl fmt::Debug for OtherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // # Safety
        // This is safe because the error came from a well formed CudaRustError type.
        let message = unsafe { CStr::from_ptr(self.0.message).to_str().map_err(|_| fmt::Error)? };
        write!(f, "CudaRustError: {message}")
    }
}

impl fmt::Display for OtherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for OtherError {}
