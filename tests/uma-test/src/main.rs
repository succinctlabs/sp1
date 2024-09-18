#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One};
use rand::Rng;
use sp1_zkvm::syscalls::sys_bigint_uma;

fn uint256_mul(x: &[u8; 32], y: &[u8; 32], modulus: &[u8; 32]) -> [u8; 32] {
    println!("cycle-tracker-start: uint256_mul");
    let mut result = [0u32; 8];
    sys_bigint_uma(
        result.as_mut_ptr() as *mut [u32; 8],
        0,
        x.as_ptr() as *const [u32; 8],
        y.as_ptr() as *const [u32; 8],
        modulus.as_ptr() as *const [u32; 8],
    );
    println!("cycle-tracker-end: uint256_mul");
    bytemuck::cast::<[u32; 8], [u8; 32]>(result)
}

fn biguint_to_bytes_le(x: BigUint) -> [u8; 32] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(32, 0);
    bytes.try_into().unwrap()
}
pub fn main() {
    let mut rng = rand::thread_rng();
    let mut x: [u8; 32] = rng.gen();
    let mut y: [u8; 32] = rng.gen();
    let modulus: [u8; 32] = rng.gen();

    // Convert byte arrays to BigUint
    let modulus_big = BigUint::from_bytes_le(&modulus);
    let x_big = BigUint::from_bytes_le(&x);
    x = biguint_to_bytes_le(&x_big % &modulus_big);
    let y_big = BigUint::from_bytes_le(&y);
    y = biguint_to_bytes_le(&y_big % &modulus_big);

    let result_bytes = uint256_mul(&x, &y, &modulus);

    let result = (x_big * y_big) % modulus_big;
    let result_syscall = BigUint::from_bytes_le(&result_bytes);

    assert_eq!(result, result_syscall);
}
