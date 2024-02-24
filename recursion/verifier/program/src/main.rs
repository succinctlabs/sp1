//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_recursion::stark::RiscvStark;

pub fn main() {
    // NOTE: values of n larger than 186 will overflow the u128 type,
    // resulting in output that doesn't match fibonacci sequence.
    // However, the resulting proof will still be valid!
    let n = sp1_zkvm::io::read::<u32>();

    type SC = sp1_recursion::utils::BabyBearBlake3;

    let machine = RiscvStark::new();
}
