#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::precompiles::io;
use sp1_zkvm::precompiles::uint256_div::uint256_div;

#[sp1_derive::cycle_tracker]
pub fn main() {
    // 24
    let dividend: [u8; 32] = [
        24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    // 5
    let mut divisor: [u8; 32] = [
        5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    println!("cycle-tracker-start: uint256_div");
    let quotient = uint256_div(&dividend, &mut divisor);
    println!("cycle-tracker-end: uint256_div");
    io::write_slice(&quotient);

    let c: [u8; 32] = [
        4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    assert_eq!(quotient, c);
    println!("done");
}
