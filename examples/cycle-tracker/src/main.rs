#![no_main]

extern crate succinct_zkvm;

use std::hint::black_box;

succinct_zkvm::entrypoint!(main);

#[succinct_derive::cycle_tracker]
pub fn f(x: usize) -> usize {
    x + 1
}

pub fn main() {
    black_box(f(black_box(1)));
}
