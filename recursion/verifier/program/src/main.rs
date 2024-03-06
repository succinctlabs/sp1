//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_recursion::stark::Proof;
use sp1_recursion::stark::VerifyingKey;
use sp1_recursion::utils::StarkUtils;

use sp1_static_machine::RISCV_STARK;

use core::arch::asm;

pub fn main() {
    type SC = sp1_recursion::utils::BabyBearBlake3;

    let config = SC::new();

    println!("cycle-tracker-start: program");

    let a = 1u32;
    let b = 4u32;
    let mut result: u32;

    unsafe {
        asm!(
            ".insn r 0x7f, 0, 0, {0}, {1}, {2}",
            out(reg) result,
            in(reg) a,
            in(reg) b,
            options(nostack)
        );
    }

    println!("cycle-tracker-end: program");

    println!("result: {}", result);

    // // Read the proof from the input
    // println!("cycle-tracker-start: read proof");
    // let proof = sp1_zkvm::io::read::<Proof<SC>>();
    // println!("cycle-tracker-end: read proof");

    println!("cycle-tracker-start: get a new challenger");
    // let mut challenger = config.challenger();
    println!("cycle-tracker-end: get a new challenger");

    // let vk = VerifyingKey::empty();

    // println!("cycle-tracker-start: verify proof");
    // RISCV_STARK
    //     .verify(&vk, &proof, &mut challenger)
    //     .expect("proof verification failed");
    // println!("cycle-tracker-end: verify proof");
}
