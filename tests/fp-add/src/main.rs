#![no_main]
sp1_zkvm::entrypoint!(main);

use num::{BigUint, One};
use rand::Rng;
use sp1_zkvm::syscalls::bls12381_sys_bigint;

fn fp_add(x: &[u8; 48], y: &[u8; 48]) -> [u8; 48] {
    let mut result = [0u32; 12];
    bls12381_sys_bigint(
        result.as_mut_ptr() as *mut [u32; 12],
        1,
        x.as_ptr() as *const [u32; 12],
        y.as_ptr() as *const [u32; 12],
    );
    bytemuck::cast::<[u32; 12], [u8; 48]>(result)
}

fn biguint_to_bytes_le(x: BigUint) -> [u8; 48] {
    let mut bytes = x.to_bytes_le();
    bytes.resize(48, 0);
    bytes.try_into().unwrap()
}

#[sp1_derive::cycle_tracker]
fn main() {
    // BLS12-381 modulus
    let modulus_big = BigUint::from_bytes_le(&[
        171, 170, 255, 255, 255, 255, 254, 185, 255, 255, 83, 177, 254, 255, 171, 30, 36, 246, 176,
        246, 160, 210, 48, 103, 191, 18, 133, 243, 132, 75, 119, 100, 215, 172, 75, 67, 182, 167,
        27, 75, 154, 230, 127, 57, 234, 17, 1, 26,
    ]);
    for _ in 0..1 {
        // Test with random numbers.
        let mut rng = rand::thread_rng();
        let mut x: [u8; 48] = [0; 48].map(|_| rng.gen());
        let mut y: [u8; 48] = [0; 48].map(|_| rng.gen());

        // Convert byte arrays to BigUint
        let x_big = BigUint::from_bytes_le(&x);
        x = biguint_to_bytes_le(&x_big % &modulus_big);
        let y_big = BigUint::from_bytes_le(&y);
        y = biguint_to_bytes_le(&y_big % &modulus_big);

        let result_bytes = fp_add(&x, &y);

        let result = (x_big + y_big) % &modulus_big;
        let result_syscall = BigUint::from_bytes_le(&result_bytes);

        assert_eq!(result, result_syscall);
    }

    // Test with random numbers.
    let mut rng = rand::thread_rng();
    let x: [u8; 48] =
        biguint_to_bytes_le(BigUint::from_bytes_le(&[0; 48].map(|_| rng.gen())) % &modulus_big);

    // Hardcoded edge case: adding 0
    let zero: [u8; 48] = [0; 48]; // Represents the number 0
    let result_zero = fp_add(&x, &original_x);
    assert_eq!(result_zero, zero, "adding 0 should yield x.");

    println!("All tests passed successfully!");
}
