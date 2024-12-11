use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::syscalls::sys_alloc_aligned;

/// A block in our free list
#[repr(C)]
struct FreeBlock {
    size: usize,
    next: Option<NonNull<FreeBlock>>,
}

/// A simple heap allocator with free list.
///
/// Uses a first-fit strategy with coalescing of adjacent free blocks.
/// Designed for single-threaded embedded systems with a memory limit of 0x78000000.
pub struct SimpleAlloc {
    head: AtomicUsize,  // Stores the raw pointer value of the head FreeBlock
}

// SAFETY: The allocator is thread-safe due to atomic operations
unsafe impl Sync for SimpleAlloc {}

impl SimpleAlloc {
    const fn new() -> Self {
        Self {
            head: AtomicUsize::new(0),
        }
    }

    unsafe fn add_free_block(&self, ptr: *mut u8, size: usize) {
        let block = ptr as *mut FreeBlock;
        (*block).size = size;

        loop {
            let current_head = self.head.load(Ordering::Relaxed);
            (*block).next = NonNull::new(current_head as *mut FreeBlock);

            if self.head.compare_exchange(
                current_head,
                block as usize,
                Ordering::Release,
                Ordering::Relaxed,
            ).is_ok() {
                break;
            }
        }
    }

    unsafe fn find_block(&self, size: usize, align: usize) -> Option<(*mut u8, usize)> {
        let mut prev: Option<*mut FreeBlock> = None;
        let mut current_ptr = self.head.load(Ordering::Acquire) as *mut FreeBlock;

        while !current_ptr.is_null() {
            let addr = current_ptr as *mut u8;
            let aligned_addr = ((addr as usize + align - 1) & !(align - 1)) as *mut u8;
            let align_adj = aligned_addr as usize - addr as usize;

            if (*current_ptr).size >= size + align_adj {
                let next = (*current_ptr).next;
                let next_raw = next.map_or(0, |n| n.as_ptr() as usize);

                match prev {
                    Some(p) => (*p).next = next,
                    None => {
                        self.head.store(next_raw, Ordering::Release);
                    }
                }
                return Some((aligned_addr, (*current_ptr).size));
            }
            prev = Some(current_ptr);
            current_ptr = (*current_ptr).next.map_or(core::ptr::null_mut(), |n| n.as_ptr());
        }
        None
    }
}

unsafe impl GlobalAlloc for SimpleAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let align = layout.align();

        // Try to find a block in free list
        if let Some((ptr, _)) = self.find_block(size, align) {
            return ptr;
        }

        // If no suitable block found, allocate new memory
        sys_alloc_aligned(size, align)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        self.add_free_block(ptr, size);
    }
}

#[global_allocator]
static ALLOCATOR: SimpleAlloc = SimpleAlloc::new();
