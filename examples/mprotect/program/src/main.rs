#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_primitives::consts::{PAGE_SIZE, PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE};
use sp1_zkvm::lib::mprotect::mprotect;

pub fn main() {
    println!("Starting simple mprotect example");

    // Allocate 4 pages of memory
    let memory = vec![0u8; 4 * PAGE_SIZE];

    // Get a pointer to the memory rounded up to the nearest page boundary
    let memory_ptr = memory.as_ptr() as *const u8;
    let aligned_ptr = (memory_ptr as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aligned_ptr = aligned_ptr as *mut u8;

    println!("Memory aligned pointer: {:p}", aligned_ptr);

    // Test different protection settings on each page

    // Page 1: Read/Write permissions
    println!("Setting page 1 to READ|WRITE");
    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_WRITE);

    // Page 2: Read-only permissions
    println!("Setting page 2 to READ");
    mprotect((aligned_ptr as usize + PAGE_SIZE) as *mut u8, PAGE_SIZE, PROT_READ);

    // Page 3: No permissions (guard page)
    println!("Setting page 3 to NONE (guard page)");
    mprotect((aligned_ptr as usize + 2 * PAGE_SIZE) as *mut u8, PAGE_SIZE, PROT_NONE);

    // Test basic memory access on the read/write page
    println!("Testing memory access on page 1 (read/write)");
    let page1_ptr = aligned_ptr as *mut u32;
    unsafe {
        *page1_ptr = 0x12345678;
        let value = *page1_ptr;
        println!("Successfully wrote and read value: 0x{:x}", value);
    }

    // Test read access on the read-only page
    println!("Testing read access on page 2 (read-only)");
    let page2_ptr = (aligned_ptr as usize + PAGE_SIZE) as *mut u32;
    unsafe {
        // Initialize the page with some data first, before setting it to read-only
        // We'll do this by temporarily setting it back to read-write
        mprotect((aligned_ptr as usize + PAGE_SIZE) as *mut u8, PAGE_SIZE, PROT_READ | PROT_WRITE);
        *page2_ptr = 0x87654321;

        // Now set it back to read-only
        mprotect((aligned_ptr as usize + PAGE_SIZE) as *mut u8, PAGE_SIZE, PROT_READ);

        let value = *page2_ptr;
        println!("Successfully read value from read-only page: 0x{:x}", value);
    }

    println!("Simple mprotect example completed successfully!");
    println!("All mprotect syscalls were executed and processed by the chip");
}
