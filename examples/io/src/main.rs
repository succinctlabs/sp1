#![no_main]

extern crate succinct_zkvm;

use serde::{Deserialize, Serialize};

succinct_zkvm::entrypoint!(main);

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPoint {
    pub x: usize,
    pub y: usize,
}

pub fn main() {
    let p1 = succinct_zkvm::io::read::<MyPoint>();
    let p2 = succinct_zkvm::io::read::<MyPoint>();

    let p3: MyPoint = MyPoint {
        x: p1.x + p2.x,
        y: p1.y + p2.y,
    };

    println!("Addition of 2 points: {:?}", p3);

    succinct_zkvm::io::write(&p3);
}
