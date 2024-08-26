use core::alloc::{GlobalAlloc, Layout};

use crate::syscalls::{sys_alloc_aligned, HEAP_POS};

use std::cell::UnsafeCell;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicUsize, Ordering, Ordering::Relaxed};
use std::mem::MaybeUninit;

pub const ARENA_SIZE: usize = 2 * 1024 * 1024 * 512;
/// An Arena allocator for better memory reuse.
pub struct ArenaAlloc {
    arena: UnsafeCell<MaybeUninit<[u8; ARENA_SIZE]>>,
    current: AtomicUsize,
}

impl ArenaAlloc {
    pub const fn new() -> Self {
        Self {
            arena: UnsafeCell::new(MaybeUninit::uninit()),
            current: AtomicUsize::new(0)
        }
    }

    pub fn reset(&self) {
        self.current.store(0, Ordering::Relaxed);
    }

    pub fn get_heap_pointer() -> *mut u8 {
        unsafe { HEAP_POS as *mut u8 }
    }

    pub fn set_heap_pointer(ptr: *mut u8) {
        unsafe { HEAP_POS = ptr as usize };
    }
}

unsafe impl Sync for ArenaAlloc {}

unsafe impl GlobalAlloc for ArenaAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let align = layout.align();

        let current = self.current.load(Ordering::Relaxed);
        let aligned_current = (current + align - 1) & !(align - 1);
        let new_current = aligned_current + size;

        if new_current > ARENA_SIZE {
            null_mut()
        } else {
            if self
                .current
                .compare_exchange(current, new_current, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                sys_alloc_aligned(size, align)
            } else {
                null_mut()
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Memory is not deallocated in an arena allocator
    }
}

// use critical_section::RawRestoreState;
// use embedded_alloc::Heap;

// struct MyCriticalSection;

// critical_section::set_impl!(MyCriticalSection);

// unsafe impl critical_section::Impl for MyCriticalSection {
//     unsafe fn acquire() -> RawRestoreState {}

//     unsafe fn release(_state: RawRestoreState) {}
// }

// pub static EMBEDDED_ALLOC_HEAP: Heap = Heap::empty();

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

pub fn get_heap_pointer() -> *mut u8 {
    unsafe { HEAP_POS as *mut u8 }
}

pub fn set_heap_pointer(ptr: *mut u8) {
    unsafe { HEAP_POS = ptr as usize };
}
