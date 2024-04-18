#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One, Zero};
use rand::Rng;
use std::convert::TryInto;

extern "C" {
    fn syscall_uint256_mul(x: *mut u32, y: *const u32);
}

fn uint256_mul(x: &mut [u8; 32], y: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_mul");
    unsafe {
        syscall_uint256_mul(x.as_mut_ptr() as *mut u32, y.as_ptr() as *const u32);
    }
    println!("cycle-tracker-end: uint256_mul");
    *x
}

#[sp1_derive::cycle_tracker]
fn main() {
    for _ in 0..100 {
        // Test with random numbers.
        let mut rng = rand::thread_rng();
        let mut x: [u8; 32] = rng.gen();
        let mut y: [u8; 32] = rng.gen();

        // Convert byte arrays to BigUint
        let x_big = BigUint::from_bytes_le(&x);
        let y_big = BigUint::from_bytes_le(&y);

        let result_bytes = uint256_mul(&mut x, &y);

        let mask = BigUint::one() << 256;
        let result = (x_big * y_big) % mask;

        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall);
    }

    // Test with random numbers.
    let mut rng = rand::thread_rng();
    let mut x: [u8; 32] = rng.gen();
    let y: [u8; 32] = rng.gen();

    // Hardcoded edge case: Multiplying by 1
    let mut one: [u8; 32] = [0; 32];
    one[0] = 1; // Least significant byte set to 1, represents the number 1
    let original_x = x; // Copy original x value before multiplication by 1
    let result_one = uint256_mul(&mut x, &one);
    assert_eq!(
        result_one, original_x,
        "Multiplying by 1 should yield the same number."
    );

    // Hardcoded edge case: Multiplying by 0
    let zero: [u8; 32] = [0; 32]; // Represents the number 0
    let result_zero = uint256_mul(&mut x, &zero);
    assert_eq!(result_zero, zero, "Multiplying by 0 should yield 0.");

    println!("All tests passed successfully!");
}
