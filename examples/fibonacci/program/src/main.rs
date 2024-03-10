#![no_main]
sp1_zkvm::entrypoint!(main);

use std::hint::black_box;

fn fibonacci(n: u32) -> u32 {
    let mut a = 0;
    let mut b = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }
    b
}

pub fn main() {
    let result = black_box(fibonacci(black_box(500000000)));
    println!("result: {}", result);
}
