#![no_main]
sp1_zkvm::entrypoint!(main);

use std::hint::black_box;

fn fibonacci(n: u32) -> u32 {
    let mut nums: Vec<u32> = vec![1, 1];

    sp1_zkvm::io::public_input(&mut n.to_le_bytes());

    for _ in 0..n {
        let mut c = nums[nums.len() - 1] + nums[nums.len() - 2];
        c %= 7919;
        nums.push(c);
    }
    let output = nums[nums.len() - 1];
    sp1_zkvm::io::public_input(&mut output.to_le_bytes());

    output
}

pub fn main() {
    let result = black_box(fibonacci(black_box(16000)));
    println!("result: {}", result);
}
