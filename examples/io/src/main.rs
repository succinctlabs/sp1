#![no_main]

extern crate succinct_zkvm;

use serde::{Deserialize, Serialize};

succinct_zkvm::entrypoint!(main);

// Example program for io. For `io`, we use `MyPoint` and for `io_unaligned`, we use `MyPointUnaligned`.

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPoint {
    pub x: usize,
    pub y: usize,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

pub fn main() {
    let p1 = succinct_zkvm::read::<MyPointUnaligned>();
    println!("Read point: {:?}", p1);
    let p2 = succinct_zkvm::read::<MyPointUnaligned>();
    println!("Read point: {:?}", p2);

    let p3: MyPointUnaligned = MyPointUnaligned {
        x: p1.x + p2.x,
        y: p1.y + p2.y,
        b: p1.b && p2.b,
    };

    println!("Addition of 2 points: {:?}", p3);

    succinct_zkvm::write(&p3);
}
