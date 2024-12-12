use core::alloc::{GlobalAlloc, Layout};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::syscalls::sys_alloc_aligned;

/// A block in our free list
#[repr(C, align(8))]
struct FreeBlock {
    size: usize,
    next: Option<NonNull<FreeBlock>>,
}

// Global free list head stored as raw pointer value
static FREE_LIST_HEAD: AtomicUsize = AtomicUsize::new(0);

/// A simple heap allocator that supports freeing memory.
///
/// Uses a first-fit strategy for allocation and maintains a free list
/// for memory reuse. Designed for single-threaded embedded systems
/// with a memory limit of 0x78000000.
#[derive(Copy, Clone)]
pub struct SimpleAlloc;

// Implementation detail functions
impl SimpleAlloc {
    unsafe fn add_free_block(ptr: *mut u8, size: usize) {
        let block = ptr as *mut FreeBlock;
        (*block).size = size;

        loop {
            let current_head = FREE_LIST_HEAD.load(Ordering::Relaxed);
            (*block).next = NonNull::new(current_head as *mut FreeBlock);

            if FREE_LIST_HEAD
                .compare_exchange(
                    current_head,
                    block as usize,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    unsafe fn find_block(size: usize, align: usize) -> Option<(*mut u8, usize)> {
        let mut prev: Option<*mut FreeBlock> = None;
        let mut current_ptr = FREE_LIST_HEAD.load(Ordering::Acquire) as *mut FreeBlock;

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
                        FREE_LIST_HEAD.store(next_raw, Ordering::Release);
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
        if let Some((ptr, _)) = Self::find_block(size, align) {
            return ptr;
        }

        // If no suitable block found, allocate new memory
        sys_alloc_aligned(size, align)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        Self::add_free_block(ptr, size);
    }
}

#[used]
#[no_mangle]
pub static HEAP_ALLOCATOR: SimpleAlloc = SimpleAlloc;
