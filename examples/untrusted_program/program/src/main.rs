#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_primitives::consts::{PAGE_SIZE, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
use sp1_zkvm::lib::mprotect::mprotect;

const JIT_PROGRAM: &[u8] = include_bytes!("../../jit-program/untrusted-program-jit-program.bin");

pub fn main() {
    let execute_prot_should_fail = sp1_zkvm::io::read::<bool>();
    let test_prot_none_fail = sp1_zkvm::io::read::<bool>();

    // Allocate 10 pages of memory for a JIT program.
    let jit_memory = vec![0u8; 10 * PAGE_SIZE];

    // Get a pointer to the JIT memory rounded up to the nearest page.
    let jit_memory_ptr = jit_memory.as_ptr() as *const u8;
    let jit_memory_aligned_ptr = (jit_memory_ptr as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let jit_memory_aligned_ptr = jit_memory_aligned_ptr as *mut u8;

    println!("JIT memory aligned pointer: {:p}", jit_memory_aligned_ptr);

    // Write the JIT program to the page aligned memory.
    unsafe {
        std::ptr::copy(JIT_PROGRAM.as_ptr(), jit_memory_aligned_ptr, JIT_PROGRAM.len());
    }

    // Set the first page to be executable.
    let mut execute_page_flags = PROT_READ | PROT_EXEC;

    // Disable the execute flag if the test flag is set.
    if execute_prot_should_fail {
        execute_page_flags = PROT_READ;
    }

    mprotect(jit_memory_aligned_ptr, PAGE_SIZE, execute_page_flags);

    // Set the second page to be a guard page.
    mprotect((jit_memory_aligned_ptr as usize + PAGE_SIZE) as *mut u8, PAGE_SIZE, PROT_NONE);

    // The third page would be the jit program's stack.
    mprotect(
        (jit_memory_aligned_ptr as usize + 2 * PAGE_SIZE) as *mut u8,
        PAGE_SIZE,
        PROT_WRITE | PROT_READ,
    );

    // The fourth page is a guard page.
    mprotect((jit_memory_aligned_ptr as usize + 3 * PAGE_SIZE) as *mut u8, PAGE_SIZE, PROT_NONE);

    // Call the JIT program.
    // Cast addr to function pointer: _start() -> u32
    let func: extern "C" fn() -> u32 = unsafe { std::mem::transmute(jit_memory_aligned_ptr) };

    let result = func();

    // Print the result.
    println!("Finished");
    println!("JIT program result: {}", result);

    // Test writing into the stack page.
    let stack_ptr = (jit_memory_aligned_ptr as usize + 2 * PAGE_SIZE) as *mut u32;
    unsafe {
        *stack_ptr = 0x0;
    }

    // Test the failure case of trying to write into the guard page.
    if test_prot_none_fail {
        let guard_ptr = (jit_memory_aligned_ptr as usize + PAGE_SIZE) as *mut u32;
        unsafe {
            *guard_ptr = 0x0;
        }
    }
}
