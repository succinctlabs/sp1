use core::alloc::{GlobalAlloc, Layout};

use crate::syscalls::{sys_alloc_aligned, HEAP_POS};

use std::cell::UnsafeCell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

const ARENA_SIZE: usize = 128 * 1024;
const MAX_SUPPORTED_ALIGN: usize = 4096;
#[repr(C, align(4096))] // 4096 == MAX_SUPPORTED_ALIGN
struct SimpleAllocator {
    arena: UnsafeCell<[u8; ARENA_SIZE]>,
    remaining: AtomicUsize, // we allocate from the top, counting down
}

#[global_allocator]
static ALLOCATOR: SimpleAllocator = SimpleAllocator {
    arena: UnsafeCell::new([0x55; ARENA_SIZE]),
    remaining: AtomicUsize::new(ARENA_SIZE),
};

unsafe impl Sync for SimpleAllocator {}

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        // `Layout` contract forbids making a `Layout` with align=0, or align not power of 2.
        // So we can safely use a mask to ensure alignment without worrying about UB.
        let align_mask_to_round_down = !(align - 1);

        if align > MAX_SUPPORTED_ALIGN {
            return null_mut();
        }

        let arena = self.arena.get();
        let offset = self.remaining.load(Relaxed);

        if offset < size {
            return null_mut();
        }

        let aligned_offset = offset & align_mask_to_round_down;
        if aligned_offset < size {
            return null_mut();
        }

        let new_offset = aligned_offset - size;
        if self.remaining.compare_exchange(offset, new_offset, Relaxed, Relaxed).is_err() {
            return null_mut();
        }

        arena.add(new_offset) as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Memory is not deallocated in an arena allocator
    }
}

impl SimpleAllocator {
    pub fn get_heap_pointer(&self) -> *mut u8 {
        unsafe { HEAP_POS as *mut u8 }
    }

    pub fn set_heap_pointer(&mut self, ptr: *mut u8) {
        unsafe { HEAP_POS = ptr as usize };
    }
}
