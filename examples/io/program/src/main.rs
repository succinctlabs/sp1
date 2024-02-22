#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(C)]
struct MyPointUnaligned {
    pub x: u32,
    pub y: u32,
    pub b: bool,
    pub test: [u8; 1200],
}

pub fn main() {
    let p1 = sp1_zkvm::io::read_magic::<MyPointUnaligned>();

    let p2 = sp1_zkvm::io::read_magic::<MyPointUnaligned>();

    println!("test[-1] {}", p1.test[p1.test.len() - 1]);
    println!("test[-1] {}", p2.test[p2.test.len() - 1]);

    // let p3: MyPointUnaligned = MyPointUnaligned {
    //     x: p1.x + p2.x,
    //     y: p1.y + p2.y,
    //     b: p1.b && p2.b,
    // };
    // println!("Addition of 2 points: {:?}", p3);
    // sp1_zkvm::io::write(&p3);
}
