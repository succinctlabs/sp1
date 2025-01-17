use crate::{
    syscalls::MAX_MEMORY, EMBEDDED_RESERVED_INPUT_REGION_SIZE, EMBEDDED_RESERVED_INPUT_START,
};
use alloc::alloc::{GlobalAlloc, Layout};
use critical_section::RawRestoreState;
use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: EmbeddedAlloc = EmbeddedAlloc;

static INNER_HEAP: Heap = Heap::empty();

struct CriticalSection;
critical_section::set_impl!(CriticalSection);

unsafe impl critical_section::Impl for CriticalSection {
    unsafe fn acquire() -> RawRestoreState {}

    unsafe fn release(_token: RawRestoreState) {}
}

pub fn init() {
    extern "C" {
        // https://lld.llvm.org/ELF/linker_script.html#sections-command
        static _end: u8;
    }
    let heap_pos: usize = unsafe { (&_end) as *const u8 as usize };
    // The heap size that is available for the program is the total memory minus the reserved input
    // region and the heap position.
    let heap_size: usize = MAX_MEMORY - heap_pos - EMBEDDED_RESERVED_INPUT_REGION_SIZE;
    unsafe { INNER_HEAP.init(heap_pos, heap_size) };
}

pub fn used() -> usize {
    critical_section::with(|_cs| INNER_HEAP.used())
}

pub fn free() -> usize {
    critical_section::with(|_cs| INNER_HEAP.free())
}

struct EmbeddedAlloc;

unsafe impl GlobalAlloc for EmbeddedAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        INNER_HEAP.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Deallocating reserved input region memory is not allowed.
        if (ptr as usize) >= EMBEDDED_RESERVED_INPUT_START {
            return;
        }
        // Deallocating other memory is allowed.
        INNER_HEAP.dealloc(ptr, layout)
    }
}
