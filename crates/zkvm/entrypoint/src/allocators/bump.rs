use crate::syscalls::sys_alloc_aligned;
use core::alloc::{GlobalAlloc, Layout};

/// A simple heap allocator.
///
/// Allocates memory from left to right, without any deallocation.
struct SimpleAlloc;

unsafe impl GlobalAlloc for SimpleAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        sys_alloc_aligned(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static HEAP: SimpleAlloc = SimpleAlloc;
