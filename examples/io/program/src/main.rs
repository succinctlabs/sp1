#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct MyPointUnaligned {
    pub x: usize,
    pub y: usize,
    pub b: bool,
}

pub fn main() {
    let p1 = sp1_zkvm::io::read::<MyPointUnaligned>();
    println!("Read point: {:?}", p1);

    let p2 = sp1_zkvm::io::read::<MyPointUnaligned>();
    println!("Read point: {:?}", p2);

    let p3: MyPointUnaligned = MyPointUnaligned { x: p1.x + p2.x, y: p1.y + p2.y, b: p1.b && p2.b };
    println!("Addition of 2 points: {:?}", p3);
    sp1_zkvm::io::commit(&p3);
}
