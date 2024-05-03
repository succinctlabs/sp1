#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One, Zero};
use rand::Rng;
use sp1_zkvm::precompiles::uint256_div::sys_bigint;
use std::convert::TryInto;

fn uint256_mul(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_mul");
    let mut result = [0u32; 8];
    unsafe {
        sys_bigint(
            result.as_mut_ptr() as *mut [u32; 8],
            0,
            x.as_ptr() as *const [u32; 8],
            y.as_ptr() as *const [u32; 8],
            modulus.as_ptr() as *const [u32; 8],
        );
    }
    println!("cycle-tracker-end: uint256_mul");
    bytemuck::cast::<[u32; 8], [u8; 32]>(result)
}

#[sp1_derive::cycle_tracker]
fn main() {
    for _ in 0..100 {
        // Test with random numbers.
        let mut rng = rand::thread_rng();
        let mut x: [u8; 32] = rng.gen();
        let mut y: [u8; 32] = rng.gen();
        let modulus: [u8; 32] = rng.gen();

        // Convert byte arrays to BigUint
        let x_big = BigUint::from_bytes_le(&x);
        let y_big = BigUint::from_bytes_le(&y);
        let modulus_big = BigUint::from_bytes_le(&modulus);

        let result_bytes = uint256_mul(&x, &y, &modulus);

        let result = (x_big * y_big) % modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall);
    }

    // Test with random numbers.
    let mut rng = rand::thread_rng();
    let mut x: [u8; 32] = rng.gen();
    let y: [u8; 32] = rng.gen();

    // Hardcoded edge case: Multiplying by 1
    let mut modulus = [0u8; 32];
    modulus[31] = 1;

    let mut one: [u8; 32] = [0; 32];
    one[0] = 1; // Least significant byte set to 1, represents the number 1
    let original_x = x; // Copy original x value before multiplication by 1
    let result_one = uint256_mul(&x, &one, &modulus);
    assert_eq!(
        result_one, original_x,
        "Multiplying by 1 should yield the same number."
    );

    // Hardcoded edge case: Multiplying by 0
    let zero: [u8; 32] = [0; 32]; // Represents the number 0
    let result_zero = uint256_mul(&x, &zero, &modulus);
    assert_eq!(result_zero, zero, "Multiplying by 0 should yield 0.");

    println!("All tests passed successfully!");
}
