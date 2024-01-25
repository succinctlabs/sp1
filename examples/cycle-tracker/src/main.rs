#![no_main]

extern crate succinct_zkvm;

use serde::{Deserialize, Serialize};
use std::hint::black_box;

succinct_zkvm::entrypoint!(main);

#[succinct_derive::cycle_tracker]
pub fn f(x: usize) -> usize {
    x + 1
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPoint {
    pub x: usize,
    pub y: usize,
}

pub fn main() {
    println!("cycle-tracker-start: read");
    let p1 = succinct_zkvm::env::read::<MyPoint>();
    println!("cycle-tracker-end: read");

    println!("cycle-tracker-start: read");
    let p2 = succinct_zkvm::env::read::<MyPoint>();
    println!("cycle-tracker-end: read");

    let p3: MyPoint = MyPoint {
        x: p1.x + p2.x,
        y: p1.y + p2.y,
    };

    println!("Addition of 2 points: {:?}", p3);

    println!("cycle-tracker-start: write");
    succinct_zkvm::env::write(&p3);
    println!("cycle-tracker-end: write");

    black_box(f(black_box(1)));
}
