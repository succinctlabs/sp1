// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Memory addresses must be lower than BabyBear prime.
pub const MAX_MEMORY: usize = 0x78000000;

// Pointer to next heap address to use, or 0 if the heap has not yet been
// initialized.
#[cfg(feature = "bump")]
static mut HEAP_POS: usize = 0;

/// Allocate memory aligned to the given alignment.
///
/// Only available when the `bump` feature is enabled.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
#[cfg(feature = "bump")]
pub unsafe extern "C" fn sys_alloc_aligned(bytes: usize, align: usize) -> *mut u8 {
    extern "C" {
        // https://lld.llvm.org/ELF/linker_script.html#sections-command
        static _end: u8;
    }

    // SAFETY: Single threaded, so nothing else can touch this while we're working.
    let mut heap_pos = unsafe { HEAP_POS };

    if heap_pos == 0 {
        heap_pos = unsafe { (&_end) as *const u8 as usize };
    }

    let offset = heap_pos & (align - 1);
    if offset != 0 {
        heap_pos += align - offset;
    }

    let ptr = heap_pos as *mut u8;
    let (heap_pos, overflowed) = heap_pos.overflowing_add(bytes);

    if overflowed || MAX_MEMORY < heap_pos {
        panic!("Memory limit exceeded (0x78000000)");
    }

    unsafe { HEAP_POS = heap_pos };
    ptr
}

/// Used memory in bytes.
#[cfg(feature = "bump")]
pub fn used_memory() -> usize {
    unsafe { HEAP_POS }
}
