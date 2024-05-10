//! Program for uint256 arithmetic operations.

#![no_main]
sp1_zkvm::entrypoint!(main);

use crypto_bigint::NonZero;
use crypto_bigint::{Wrapping, U256};
use std::hint::black_box;

#[sp1_derive::cycle_tracker]
pub fn uint256_add(a: U256, b: U256) -> U256 {
    let result = Wrapping(a) + Wrapping(b);
    result.0
}

#[sp1_derive::cycle_tracker]
pub fn uint256_sub(a: U256, b: U256) -> U256 {
    let result = Wrapping(a) - Wrapping(b);
    result.0
}

#[sp1_derive::cycle_tracker]
pub fn uint256_mul(a: U256, b: U256) -> U256 {
    let result = Wrapping(a) * Wrapping(b);
    result.0
}

#[sp1_derive::cycle_tracker]
pub fn uint256_div(a: U256, b: U256) -> U256 {
    Wrapping(a)
        .0
        .wrapping_div_vartime(&Wrapping(NonZero::new(b).unwrap()).0)
}

pub fn main() {
    let a = U256::from(3u8);
    let b = U256::from(2u8);

    println!("cycle-tracker-start: uint256_add");
    let add = uint256_add(black_box(a), black_box(b));
    assert_eq!(add, U256::from(5u8));
    println!("cycle-tracker-end: uint256_add");
    println!("{:?}", add);

    println!("cycle-tracker-start: uint256_sub");
    let sub = uint256_sub(black_box(a), black_box(b));
    assert_eq!(sub, U256::from(1u8));
    println!("cycle-tracker-end: uint256_sub");
    println!("{:?}", sub);

    println!("cycle-tracker-start: uint256_div");
    let div = uint256_div(black_box(a), black_box(b));
    assert_eq!(div, U256::from(1u8));
    println!("cycle-tracker-end: uint256_div");
    println!("{:?}", div);

    println!("cycle-tracker-start: uint256_mul");
    let mul = uint256_mul(black_box(a), black_box(b));
    assert_eq!(mul, U256::from(6u8));
    println!("cycle-tracker-end: uint256_mul");
    println!("{:?}", mul);
}
