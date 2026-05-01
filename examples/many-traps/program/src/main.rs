#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::prelude::*;
use sp1_primitives::consts::{PAGE_SIZE, PROT_EXEC, PROT_FAILURE_WRITE, PROT_NONE, PROT_READ};
use sp1_zkvm::{lib::mprotect::mprotect, syscalls};

// When the design of trap is complete, we would move TrapContext,
// __SUCCINCT_TRAP_CONTEXT and install_trap_handler to sp1-zkvm crate.
#[repr(C)]
pub struct TrapContext {
    handler: u64,
    code: u64,
    pc: u64,
}

#[no_mangle]
#[used]
pub static mut __SUCCINCT_TRAP_CONTEXT: TrapContext = TrapContext { handler: 1, code: 0, pc: 1 };

pub fn install_trap_handler(h: extern "C" fn()) {
    unsafe {
        __SUCCINCT_TRAP_CONTEXT.handler = h as *mut u8 as u64;
    }
}

pub static mut TRAP_COUNTER: u64 = 0;

// This is the actual trap function. It will merely return(returning
// from the function that traps, not the trap handler) with the trap code.
#[unsafe(naked)]
pub extern "C" fn sp1_trap_trap_trap() {
    // Note this is actually a trap handler, not a normal function.
    // SP1 would *jump* to the start of this function instead of calling
    // this function. All the registers will be exactly the same value
    // as they are when the trap happens. This means if we do `ret`, we
    // will effectively be returning from the function causing the trap.
    core::arch::naked_asm!(
        "la a1, {counter}",
        "ld a0, 0(a1)",
        "addi a0, a0, 1",
        "sd a0, 0(a1)",
        "la a0, {context}",
        "ld a0, 8(a0)",
        "ret",
        context = sym __SUCCINCT_TRAP_CONTEXT,
        counter = sym TRAP_COUNTER,
    )
}

pub fn main() {
    println!("Starting many traps example");

    // If you comment this line out, trap will not take effect. SP1 will
    // simply terminate in case of permission violation.
    install_trap_handler(sp1_trap_trap_trap);

    // Heap allocated memory might not be page aligned, we are allocating
    // 2 pages(precompiles might need more), and find 1 aligned page inside.
    let mut memory = vec![0u8; 6 * PAGE_SIZE];
    rand::thread_rng().fill(&mut memory[..]);

    // Get a pointer to the memory rounded up to the nearest page boundary
    let memory_ptr = memory.as_ptr() as *const u8;
    let aligned_ptr = (memory_ptr as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aligned_ptr = aligned_ptr as *mut u8;

    println!("Memory aligned pointer: {:p}", aligned_ptr);

    let memory_traps: u32 = sp1_zkvm::io::read();
    println!("Start to trigger {memory_traps} memory traps");

    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_EXEC);
    for _ in 0..memory_traps {
        // Violate write permission
        assert_eq!(violating_write(aligned_ptr, rand::random()), PROT_FAILURE_WRITE);
    }

    let precompile_traps: u32 = sp1_zkvm::io::read();
    println!("Start to trigger {precompile_traps} precompile traps");

    mprotect(aligned_ptr, PAGE_SIZE, PROT_NONE);
    for _ in 0..precompile_traps {
        run_poseidon2(aligned_ptr);
    }

    assert_eq!(unsafe { TRAP_COUNTER }, (memory_traps + precompile_traps) as u64);
    println!("Terminating! We have handled {} traps!", unsafe { TRAP_COUNTER });
}

#[unsafe(naked)]
pub extern "C" fn violating_write(page_addr: *mut u8, target_value: u64) -> u64 {
    core::arch::naked_asm!("sd a1, 16(a0)", "mv a0, a1", "ret",)
}

#[inline(never)]
pub extern "C" fn run_poseidon2(first_page_addr: *mut u8) {
    syscalls::syscall_poseidon2(unsafe {
        std::mem::transmute::<*mut u8, &mut syscalls::Poseidon2State>(first_page_addr)
    });
}
