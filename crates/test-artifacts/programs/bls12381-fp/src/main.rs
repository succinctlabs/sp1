#![no_main]

sp1_zkvm::entrypoint!(main);
use std::str::FromStr;

use sp1_zkvm::lib::{
    syscall_bls12381_fp_addmod, syscall_bls12381_fp_mulmod, syscall_bls12381_fp_submod,
};

use num_bigint::BigUint;
use rand::Rng;

fn add(lhs: &[u32; 12], rhs: &[u32; 12]) -> [u32; 12] {
    unsafe {
        let mut lhs_copy = *lhs;
        syscall_bls12381_fp_addmod(lhs_copy.as_mut_ptr(), rhs.as_ptr());
        lhs_copy
    }
}

fn sub(lhs: &[u32; 12], rhs: &[u32; 12]) -> [u32; 12] {
    unsafe {
        let mut lhs_copy = *lhs;
        syscall_bls12381_fp_submod(lhs_copy.as_mut_ptr(), rhs.as_ptr());
        lhs_copy
    }
}

fn mul(lhs: &[u32; 12], rhs: &[u32; 12]) -> [u32; 12] {
    unsafe {
        let mut lhs_copy = *lhs;
        syscall_bls12381_fp_mulmod(lhs_copy.as_mut_ptr(), rhs.as_ptr());
        lhs_copy
    }
}

fn random_u32_12() -> [u32; 12] {
    let mut rng = rand::thread_rng();
    let mut arr = [0u32; 12];
    for item in arr.iter_mut() {
        *item = rng.gen();
    }
    arr
}

fn u32_12_to_biguint(arr: &[u32; 12]) -> BigUint {
    let mut bytes = [0u8; 48];
    for i in 0..12 {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&arr[i].to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn reduce_modulo(arr: &[u32; 12], modulus: &BigUint) -> [u32; 12] {
    let bigint = u32_12_to_biguint(arr);
    let reduced = bigint % modulus;
    let bytes = reduced.to_bytes_le();
    let mut result = [0u32; 12];
    for i in 0..12 {
        if i * 4 < bytes.len() {
            let mut slice = [0u8; 4];
            slice.copy_from_slice(&bytes[i * 4..(i * 4 + 4).min(bytes.len())]);
            result[i] = u32::from_le_bytes(slice);
        }
    }
    result
}

pub fn main() {
    let modulus = BigUint::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787").unwrap();
    let zero: [u32; 12] = [0; 12];
    let zero_bigint = BigUint::ZERO;
    let one: [u32; 12] = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let one_bigint = BigUint::from(1u32);

    for _ in 0..10 {
        let a = random_u32_12();
        let b = random_u32_12();
        let a_reduced = reduce_modulo(&a, &modulus);
        let b_reduced = reduce_modulo(&b, &modulus);
        let a_bigint = u32_12_to_biguint(&a_reduced);
        let b_bigint = u32_12_to_biguint(&b_reduced);

        // Test addition
        assert_eq!(
            (a_bigint.clone() + b_bigint.clone()) % &modulus,
            u32_12_to_biguint(&add(&a_reduced, &b_reduced)) % &modulus
        );

        // Test addition with zero
        assert_eq!(
            (&a_bigint + &zero_bigint) % &modulus,
            u32_12_to_biguint(&add(&a_reduced, &zero)) % &modulus
        );

        // Test subtraction
        let expected_sub = if a_bigint < b_bigint {
            ((a_bigint.clone() + &modulus) - b_bigint.clone()) % &modulus
        } else {
            (a_bigint.clone() - b_bigint.clone()) % &modulus
        };
        assert_eq!(expected_sub, u32_12_to_biguint(&sub(&a_reduced, &b_reduced)) % &modulus);

        // Test subtraction with zero
        assert_eq!(
            (&a_bigint + &modulus - &zero_bigint) % &modulus,
            u32_12_to_biguint(&sub(&a_reduced, &zero)) % &modulus
        );

        // Test multiplication
        assert_eq!(
            (a_bigint.clone() * b_bigint.clone()) % &modulus,
            u32_12_to_biguint(&mul(&a_reduced, &b_reduced)) % &modulus
        );

        // Test multiplication with one
        assert_eq!(
            (&a_bigint * &one_bigint) % &modulus,
            u32_12_to_biguint(&mul(&a_reduced, &one)) % &modulus
        );

        // Test multiplication with zero
        assert_eq!(
            (&a_bigint * &zero_bigint) % &modulus,
            u32_12_to_biguint(&mul(&a_reduced, &zero)) % &modulus
        );
    }
    println!("All tests passed!");
}
