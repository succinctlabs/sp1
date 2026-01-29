use std::ptr;

use sp1_gpu_sys::runtime::{
    cuda_event_create, cuda_event_destroy, cuda_event_query, cuda_event_synchronize,
    CudaEventHandle,
};

use super::CudaError;

#[derive(Debug)]
#[repr(transparent)]
pub struct CudaEvent(pub(crate) CudaEventHandle);

unsafe impl Send for CudaEvent {}
unsafe impl Sync for CudaEvent {}

impl CudaEvent {
    #[inline]
    pub fn create() -> Result<Self, CudaError> {
        let mut ptr = CudaEventHandle(ptr::null_mut());
        CudaError::result_from_ffi(unsafe { cuda_event_create(&mut ptr) })?;
        Ok(Self(ptr))
    }

    #[inline]
    pub fn query(&self) -> Result<(), CudaError> {
        CudaError::result_from_ffi(unsafe { cuda_event_query(self.0) })
    }

    #[inline]
    pub fn synchronize(&self) -> Result<(), CudaError> {
        CudaError::result_from_ffi(unsafe { cuda_event_synchronize(self.0) })
    }
}

impl Drop for CudaEvent {
    fn drop(&mut self) {
        unsafe { CudaError::result_from_ffi(cuda_event_destroy(self.0)).unwrap() }
    }
}
