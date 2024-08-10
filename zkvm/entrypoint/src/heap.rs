use core::alloc::{GlobalAlloc, Layout};

use crate::syscalls::{sys_alloc_aligned, HEAP_POS};

/// A simple heap allocator.
///
/// Allocates memory from left to right, without any deallocation.
pub struct SimpleAlloc;

unsafe impl GlobalAlloc for SimpleAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        sys_alloc_aligned(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

impl SimpleAlloc {
    pub fn get_heap_pointer() -> *mut u8 {
        unsafe { HEAP_POS as *mut u8 }
    }

    pub fn set_heap_pointer(ptr: *mut u8) {
        unsafe { HEAP_POS = ptr as usize };
    }
}
