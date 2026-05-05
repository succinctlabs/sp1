// To generate the .bin file, run:
// 1) cargo +succinct build --target riscv64im-succinct-zkvm-elf --release
// 2) riscv64-unknown-elf-objcopy -O binary ../../target/riscv64im-succinct-zkvm-elf/release/untrusted-program-jit-program untrusted-program-jit-program.bin
// 3) Make a nit edit in the program/src/main.rs to ensure it rebuilds

// Includes dynamic instructions, including ALU ops with rd = x0.

#![no_std]
#![no_main]

use core::arch::asm;
use core::ptr::{read_volatile, write_volatile};

static mut MEM: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// Execute a variety of ALU instructions with rd = x0 (result discarded).
/// This exercises the AluX0 / AluX0User chip in the prover.
#[inline(never)]
fn alu_x0_exercise(a: u64, b: u64) {
    unsafe {
        asm!(
            // R-type ALU ops with rd = x0
            "add   x0, {a}, {b}",
            "sub   x0, {a}, {b}",
            "xor   x0, {a}, {b}",
            "or    x0, {a}, {b}",
            "and   x0, {a}, {b}",
            "sll   x0, {a}, {b}",
            "srl   x0, {a}, {b}",
            "sra   x0, {a}, {b}",
            "slt   x0, {a}, {b}",
            "sltu  x0, {a}, {b}",
            "mul   x0, {a}, {b}",
            "mulh  x0, {a}, {b}",
            "mulhsu x0, {a}, {b}",
            "mulhu x0, {a}, {b}",
            "div   x0, {a}, {b}",
            "divu  x0, {a}, {b}",
            "rem   x0, {a}, {b}",
            "remu  x0, {a}, {b}",
            // I-type ALU ops with rd = x0
            "addi  x0, {a}, 42",
            "xori  x0, {a}, 7",
            "ori   x0, {a}, 15",
            "andi  x0, {a}, 0xff",
            "slli  x0, {a}, 3",
            "srli  x0, {a}, 2",
            "srai  x0, {a}, 1",
            "slti  x0, {a}, 100",
            "sltiu x0, {a}, 100",
            // W-suffix R-type ops with rd = x0
            "addw  x0, {a}, {b}",
            "subw  x0, {a}, {b}",
            "sllw  x0, {a}, {b}",
            "srlw  x0, {a}, {b}",
            "sraw  x0, {a}, {b}",
            "mulw  x0, {a}, {b}",
            "divw  x0, {a}, {b}",
            "divuw x0, {a}, {b}",
            "remw  x0, {a}, {b}",
            "remuw x0, {a}, {b}",
            // W-suffix I-type ops with rd = x0
            "addiw x0, {a}, 42",
            "slliw x0, {a}, 3",
            "srliw x0, {a}, 2",
            "sraiw x0, {a}, 1",
            a = in(reg) a,
            b = in(reg) b,
            options(nomem, nostack),
        );
    }
}

#[no_mangle]
pub extern "C" fn _start() -> u64 {
    let mut acc: u64 = 0;
    let mut i: u64 = 0;

    unsafe {
        // Memory load loop
        while i < 8 {
            let val = read_volatile(&MEM[i as usize]);
            acc = acc.wrapping_add(val); // ADD
            acc ^= val << (i % 8); // XOR, SLL
            acc = acc.wrapping_sub(val >> 1); // SUB, SRL
            acc |= i; // OR
            acc &= !i; // AND
            if acc < 1000 {
                acc += 3; // SLT-like branching
            } else {
                acc -= 7;
            }

            write_volatile(&mut MEM[i as usize], acc); // SD
            i += 1;
        }
    }

    // Exercise ALU ops with rd = x0
    alu_x0_exercise(acc, 5);

    acc
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
