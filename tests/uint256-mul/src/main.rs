#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One};
use rand::Rng;
use sp1_zkvm::syscalls::sys_bigint;

fn uint256_mul(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_mul");
    let mut result = [0u32; 8];
    sys_bigint(
        result.as_mut_ptr() as *mut [u32; 8],
        0,
        x.as_ptr() as *const [u32; 8],
        y.as_ptr() as *const [u32; 8],
        modulus.as_ptr() as *const [u32; 8],
    );
    println!("cycle-tracker-end: uint256_mul");
    bytemuck::cast::<[u32; 8], [u8; 32]>(result)
}

fn uint256_add(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_add");
    let mut result = [0u32; 8];
    sys_bigint(
        result.as_mut_ptr() as *mut [u32; 8],
        1,
        x.as_ptr() as *const [u32; 8],
        y.as_ptr() as *const [u32; 8],
        modulus.as_ptr() as *const [u32; 8],
    );
    println!("cycle-tracker-end: uint256_add");
    bytemuck::cast::<[u32; 8], [u8; 32]>(result)
}

fn uint256_sub(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_sub");
    let mut result = [0u32; 8];
    sys_bigint(
        result.as_mut_ptr() as *mut [u32; 8],
        2,
        x.as_ptr() as *const [u32; 8],
        y.as_ptr() as *const [u32; 8],
        modulus.as_ptr() as *const [u32; 8],
    );
    println!("cycle-tracker-end: uint256_sub");
    bytemuck::cast::<[u32; 8], [u8; 32]>(result)
}

fn biguint_to_bytes_le(x: BigUint) -> [u8; 32] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}

#[sp1_derive::cycle_tracker]
fn main() {
    let mut rng = rand::thread_rng();

    // Test multiplication
    for _ in 0..50 {
        let mut x: [u8; 32] = rng.gen();
        let mut y: [u8; 32] = rng.gen();
        let modulus: [u8; 32] = rng.gen();

        let modulus_big = BigUint::from_bytes_le(&modulus);
        let x_big = BigUint::from_bytes_le(&x) % &modulus_big;
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y) % &modulus_big;
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = uint256_mul(&x, &y, &modulus);
        let result = (x_big * y_big) % &modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall, "Multiplication failed");
    }

    // Test addition
    for _ in 0..50 {
        let mut x: [u8; 32] = rng.gen();
        let mut y: [u8; 32] = rng.gen();
        let modulus: [u8; 32] = rng.gen();

        let modulus_big = BigUint::from_bytes_le(&modulus);
        let x_big = BigUint::from_bytes_le(&x) % &modulus_big;
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y) % &modulus_big;
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = uint256_add(&x, &y, &modulus);
        let result = (x_big + y_big) % &modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall, "Addition failed");
    }

    // Test subtraction
    for _ in 0..50 {
        let mut x: [u8; 32] = rng.gen();
        let mut y: [u8; 32] = rng.gen();
        let modulus: [u8; 32] = rng.gen();

        let modulus_big = BigUint::from_bytes_le(&modulus);
        let x_big = BigUint::from_bytes_le(&x) % &modulus_big;
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y) % &modulus_big;
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = uint256_sub(&x, &y, &modulus);
        let result = (modulus_big.clone() + x_big - y_big) % &modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall, "Subtraction failed");
    }

    // Modulus zero tests for multiplication (unchanged)
    let modulus = [0u8; 32];
    let modulus_big: BigUint = BigUint::one() << 256;
    for _ in 0..50 {
        let mut x: [u8; 32] = rng.gen();
        let mut y: [u8; 32] = rng.gen();

        let x_big = BigUint::from_bytes_le(&x) % &modulus_big;
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y) % &modulus_big;
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = uint256_mul(&x, &y, &modulus);
        let result = (x_big * y_big) % &modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(
            result, result_syscall,
            "Modulus zero multiplication failed: x: {:?}, y: {:?}",
            x, y
        );
    }

    // Special cases for addition and subtraction
    let zero: [u8; 32] = [0; 32];
    let mut one: [u8; 32] = [0; 32];
    one[0] = 1;
    let x: [u8; 32] = rng.gen();

    // Addition special cases
    let result_zero_add = uint256_add(&x, &zero, &modulus);
    assert_eq!(result_zero_add, x, "Adding zero failed");

    let result_modulus_add = uint256_add(&x, &modulus, &modulus);
    assert_eq!(result_modulus_add, x, "Adding modulus failed");

    // Subtraction special cases
    let result_zero_sub = uint256_sub(&x, &zero, &modulus);
    assert_eq!(result_zero_sub, x, "Subtracting zero failed");

    let result_same_sub = uint256_sub(&x, &x, &modulus);
    assert_eq!(result_same_sub, zero, "Subtracting the same number failed");

    println!("All tests passed successfully!");
}
