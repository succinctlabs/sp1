use std::{
    borrow::{Borrow, BorrowMut},
    ffi::c_void,
    mem::MaybeUninit,
    ptr::{self, NonNull},
};

use slop_alloc::{AllocError, Allocator, RawBuffer};
use sp1_gpu_sys::runtime::{cuda_free_host, cuda_malloc_host};

use crate::CudaError;

pub const PINNED_ALLOCATOR: PinnedAllocator = PinnedAllocator;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PinnedAllocator;

unsafe impl Allocator for PinnedAllocator {
    unsafe fn allocate(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, slop_alloc::AllocError> {
        let mut ptr: *mut c_void = ptr::null_mut();
        unsafe {
            CudaError::result_from_ffi(cuda_malloc_host(
                &mut ptr as *mut *mut c_void,
                layout.size(),
            ))
            .map_err(|_| AllocError)?;
        };
        let ptr = ptr as *mut u8;
        Ok(NonNull::slice_from_raw_parts(NonNull::new_unchecked(ptr), layout.size()))
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, _layout: std::alloc::Layout) {
        CudaError::result_from_ffi(cuda_free_host(ptr.as_ptr() as *mut c_void)).unwrap()
    }
}

pub struct PinnedBuffer<T> {
    buf: RawBuffer<T, PinnedAllocator>,
}

impl<T> PinnedBuffer<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: RawBuffer::with_capacity_in(capacity, PINNED_ALLOCATOR) }
    }

    pub fn as_slice(&self) -> &[MaybeUninit<T>] {
        self.borrow()
    }

    pub fn as_mut_slice(&mut self) -> &mut [MaybeUninit<T>] {
        self.borrow_mut()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.buf.ptr() as *const T
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.buf.ptr()
    }
}

impl<T> Borrow<[MaybeUninit<T>]> for PinnedBuffer<T> {
    fn borrow(&self) -> &[MaybeUninit<T>] {
        unsafe {
            std::slice::from_raw_parts(self.buf.ptr() as *const MaybeUninit<T>, self.buf.capacity())
        }
    }
}

impl<T> BorrowMut<[MaybeUninit<T>]> for PinnedBuffer<T> {
    fn borrow_mut(&mut self) -> &mut [MaybeUninit<T>] {
        unsafe {
            std::slice::from_raw_parts_mut(
                self.buf.ptr() as *mut MaybeUninit<T>,
                self.buf.capacity(),
            )
        }
    }
}

unsafe impl<T> Send for PinnedBuffer<T> {}
unsafe impl<T> Sync for PinnedBuffer<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_buffer() {
        let mut buf = PinnedBuffer::<u32>::with_capacity(10);
        buf.as_mut_slice()[0].write(1);
        assert_eq!(buf.capacity(), 10);
        assert_eq!(unsafe { buf.as_slice()[0].assume_init() }, 1);
    }
}
