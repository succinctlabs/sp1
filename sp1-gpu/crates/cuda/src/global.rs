// use std::{
//     alloc::Layout,
//     ffi::c_void,
//     ptr::{self, NonNull},
// };

// use sp1_gpu_sys::runtime::{
//     cuda_free, cuda_malloc, cuda_mem_copy_device_to_device, cuda_mem_copy_device_to_host,
//     cuda_mem_copy_host_to_device, cuda_mem_set,
// };
// use slop_alloc::{AllocError, Allocator};

// use slop_alloc::mem::{CopyDirection, CopyError, DeviceMemory};

// use super::CudaError;

// pub struct GlobalDeviceAllocator;

// unsafe impl Allocator for GlobalDeviceAllocator {
//     #[inline]
//     unsafe fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
//         let mut ptr: *mut c_void = ptr::null_mut();
//         unsafe {
//             CudaError::result_from_ffi(cuda_malloc(&mut ptr as *mut *mut c_void, layout.size()))
//                 .map_err(|_| AllocError)?;
//         };
//         let ptr = ptr as *mut u8;
//         Ok(NonNull::slice_from_raw_parts(NonNull::new_unchecked(ptr), layout.size()))
//     }

//     #[inline]
//     unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
//         unsafe { CudaError::result_from_ffi(cuda_free(ptr.as_ptr() as *mut c_void)).unwrap() }
//     }
// }

// impl DeviceMemory for GlobalDeviceAllocator {
//     #[inline]
//     unsafe fn copy_nonoverlapping(
//         &self,
//         src: *const u8,
//         dst: *mut u8,
//         size: usize,
//         direction: CopyDirection,
//     ) -> Result<(), CopyError> {
//         match direction {
//             CopyDirection::HostToDevice => CudaError::result_from_ffi(
//                 cuda_mem_copy_host_to_device(dst as *mut c_void, src as *const c_void, size),
//             ),
//             CopyDirection::DeviceToHost => CudaError::result_from_ffi(
//                 cuda_mem_copy_device_to_host(dst as *mut c_void, src as *const c_void, size),
//             ),
//             CopyDirection::DeviceToDevice => CudaError::result_from_ffi(
//                 cuda_mem_copy_device_to_device(dst as *mut c_void, src as *const c_void, size),
//             ),
//         }
//         .map_err(|_| CopyError)
//     }

//     #[inline]
//     unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
//         CudaError::result_from_ffi(cuda_mem_set(dst as *mut c_void, value, size))
//             .map_err(|_| CopyError)
//     }
// }
