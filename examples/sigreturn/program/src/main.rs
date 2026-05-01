#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::prelude::*;
use sp1_primitives::consts::{PAGE_SIZE, PROT_NONE};
use sp1_zkvm::lib::mprotect::mprotect;

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

// This is a proof-of-concept trap function that saves registers to a
// local context, then use sigreturn syscall to restore the context, with
// the exception that PC is set so the instruction that traps is skipped.
// In a real production setup, it's very likely we will wrap most of the
// placeholder code shown in this function in helper functions, so you don't
// have to manually write the assembly code.
#[unsafe(naked)]
pub extern "C" fn sp1_trap_trap_trap() {
    core::arch::naked_asm!(
        // Save SP first
        "sd sp, -240(sp)",
        // 32 registers takes 256 bytes
        "addi sp, sp, -256",
        // Save all registers except PC and SP
        "sd ra, 8(sp)",
        "sd gp, 24(sp)",
        "sd tp, 32(sp)",
        "sd t0, 40(sp)",
        "sd t1, 48(sp)",
        "sd t2, 56(sp)",
        "sd s0, 64(sp)",
        "sd s1, 72(sp)",
        "sd a0, 80(sp)",
        "sd a1, 88(sp)",
        "sd a2, 96(sp)",
        "sd a3, 104(sp)",
        "sd a4, 112(sp)",
        "sd a5, 120(sp)",
        "sd a6, 128(sp)",
        "sd a7, 136(sp)",
        "sd s2, 144(sp)",
        "sd s3, 152(sp)",
        "sd s4, 160(sp)",
        "sd s5, 168(sp)",
        "sd s6, 176(sp)",
        "sd s7, 184(sp)",
        "sd s8, 192(sp)",
        "sd s9, 200(sp)",
        "sd s10, 208(sp)",
        "sd s11, 216(sp)",
        "sd t3, 224(sp)",
        "sd t4, 232(sp)",
        "sd t5, 240(sp)",
        "sd t6, 248(sp)",
        // Now we are setting PC to the next instruction after
        // the trapping one. SP1 does not support C extension,
        // so we can simply add 4 on current pc.
        "la a0, {context}",
        "ld a0, 16(a0)",
        "addi a0, a0, 4",
        "sd a0, 0(sp)",
        // Set a0(first argument of syscall) to point to the register array.
        "mv a0, sp",
        // Set a1 to zero.
        "li a1, 0",
        // Set syscall code to sigreturn.
        "li t0, 0x134",
        // Now execute the ecall, this should never return.
        "ecall",
        context = sym __SUCCINCT_TRAP_CONTEXT,
    )
}

pub fn main() {
    println!("Starting simple sigreturn example");

    // If you comment this line out, trap will not take effect. SP1 will
    // simply terminate in case of permission violation.
    install_trap_handler(sp1_trap_trap_trap);

    // Heap allocated memory might not be page aligned, we are allocating
    // 2 pages, and find 1 aligned page inside.
    let mut memory = vec![0u8; 2 * PAGE_SIZE];
    rand::thread_rng().fill(&mut memory[..]);

    // Get a pointer to the memory rounded up to the nearest page boundary
    let memory_ptr = memory.as_ptr() as *const u8;
    let aligned_ptr = (memory_ptr as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aligned_ptr = aligned_ptr as *mut u8;

    println!("Memory aligned pointer: {:p}", aligned_ptr);

    // Violate read permission
    mprotect(aligned_ptr, PAGE_SIZE, PROT_NONE);

    let default_value = rand::random();
    #[allow(unused_assignments)]
    let mut value: u64 = default_value;

    unsafe {
        core::arch::asm!(
            "ld {value}, 8({ptr})",
            ptr = in(reg) aligned_ptr,
            value = inout(reg) value,
        );
    }
    // If trap works, the code should proceed as if the above violating ld never
    // happens
    assert_eq!(value, default_value);

    println!("Terminating! We have tested sigreturn!");
}
