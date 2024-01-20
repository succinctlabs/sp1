#![no_main]

extern crate succinct_zkvm;

#[cfg(target_os = "zkvm")]
use core::arch::asm;

use std::hint::black_box;

succinct_zkvm::entrypoint!(main);

fn fibonacci(n: u32) -> u32 {
    let mut nums = vec![1, 1];
    for _ in 0..n {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];

        c %= 7919;
        nums.push(c);
    }
    nums[nums.len() - 1]
}

pub fn main() {
    let result = black_box(fibonacci(black_box(5000)));

    println!("result: {}", result);

    // #[cfg(target_os = "zkvm")]
    // unsafe {
    //     asm!(
    //         "ecall",
    //         in("t0") result,
    //     );
    // }
}
