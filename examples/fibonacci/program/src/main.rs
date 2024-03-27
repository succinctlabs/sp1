#![no_main]
sp1_zkvm::entrypoint!(main);

use std::hint::black_box;

fn fibonacci(n: u32) -> u32 {
    let mut nums: Vec<u32> = vec![1, 1];

    let pi = [16u8; 32];

    sp1_zkvm::syscalls::syscall_write(5, pi.as_ptr(), pi.len());

    for _ in 0..n {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];
        c %= 7919;
        nums.push(c);
    }
    nums[nums.len() - 1]
}

pub fn main() {
    let result = black_box(fibonacci(black_box(16000)));
    println!("result: {}", result);
}
