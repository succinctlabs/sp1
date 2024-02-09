//! A simple program to be proven inside the zkVM.

#![no_main]
extern crate succinct_zkvm;
succinct_zkvm::entrypoint!(main);

pub fn main() {
    let n = 10;
    let mut a = 0;
    let mut b = 1;
    let mut sum;
    for _ in 1..n {
        sum = a + b;
        a = b;
        b = sum;
    }
    println!("b: {}", b);
}
