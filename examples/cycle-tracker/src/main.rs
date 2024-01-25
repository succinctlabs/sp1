#![no_main]

extern crate succinct_zkvm;

use serde::{Deserialize, Serialize};
use std::hint::black_box;

succinct_zkvm::entrypoint!(main);

#[succinct_derive::cycle_tracker]
pub fn f(x: usize) -> usize {
    x + 1
}

#[derive(Serialize, Deserialize)]
struct MyPoint {
    pub x: usize,
    pub y: usize,
}

pub fn main() {
    let my_point = MyPoint { x: 1, y: 2 };
    succinct_zkvm::env::write(&my_point);
    black_box(f(black_box(1)));
}
