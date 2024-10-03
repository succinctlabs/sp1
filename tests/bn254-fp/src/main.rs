#![no_main]

sp1_zkvm::entrypoint!(main);
use std::str::FromStr;

use sp1_zkvm::lib::{syscall_bn254_fp_addmod, syscall_bn254_fp_mulmod, syscall_bn254_fp_submod};

use num_bigint::BigUint;
use rand::Rng;

const NUM_LIMBS: usize = 8;

fn add(lhs: &[u32; NUM_LIMBS], rhs: &[u32; NUM_LIMBS]) -> [u32; NUM_LIMBS] {
    unsafe {
        let mut lhs_copy = *lhs;
        syscall_bn254_fp_addmod(lhs_copy.as_mut_ptr(), rhs.as_ptr());
        lhs_copy
    }
}

fn sub(lhs: &[u32; NUM_LIMBS], rhs: &[u32; NUM_LIMBS]) -> [u32; NUM_LIMBS] {
    unsafe {
        let mut lhs_copy = *lhs;
        syscall_bn254_fp_submod(lhs_copy.as_mut_ptr(), rhs.as_ptr());
        lhs_copy
    }
}

fn mul(lhs: &[u32; NUM_LIMBS], rhs: &[u32; NUM_LIMBS]) -> [u32; NUM_LIMBS] {
    unsafe {
        let mut lhs_copy = *lhs;
        syscall_bn254_fp_mulmod(lhs_copy.as_mut_ptr(), rhs.as_ptr());
        lhs_copy
    }
}

fn random_u32_8() -> [u32; NUM_LIMBS] {
    let mut rng = rand::thread_rng();
    let mut arr = [0u32; NUM_LIMBS];
    for item in arr.iter_mut() {
        *item = rng.gen();
    }
    arr
}

fn u32_8_to_biguint(arr: &[u32; NUM_LIMBS]) -> BigUint {
    let mut bytes = [0u8; NUM_LIMBS * 4];
    for i in 0..NUM_LIMBS {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&arr[i].to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

fn reduce_modulo(arr: &[u32; NUM_LIMBS], modulus: &BigUint) -> [u32; NUM_LIMBS] {
    let bigint = u32_8_to_biguint(arr);
    let reduced = bigint % modulus;
    let bytes = reduced.to_bytes_le();
    let mut result = [0u32; NUM_LIMBS];
    for i in 0..NUM_LIMBS {
        let mut slice = [0u8; 4];
        if i * 4 < bytes.len() {
            let end = (i * 4 + 4).min(bytes.len());
            let len = end - i * 4;
            slice[..len].copy_from_slice(&bytes[i * 4..end]);
        }
        result[i] = u32::from_le_bytes(slice);
    }
    result
}

pub fn main() {
    let modulus = BigUint::from_str(
        "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    )
    .unwrap();
    let zero: [u32; NUM_LIMBS] = [0; NUM_LIMBS];
    let zero_bigint = BigUint::ZERO;
    let one: [u32; NUM_LIMBS] = [1, 0, 0, 0, 0, 0, 0, 0];
    let one_bigint = BigUint::from(1u32);

    for _ in 0..10 {
        let a = random_u32_8();
        let b = random_u32_8();
        let a_reduced = reduce_modulo(&a, &modulus);
        let b_reduced = reduce_modulo(&b, &modulus);
        let a_bigint = u32_8_to_biguint(&a_reduced);
        let b_bigint = u32_8_to_biguint(&b_reduced);

        // Test addition
        assert_eq!(
            (a_bigint.clone() + b_bigint.clone()) % &modulus,
            u32_8_to_biguint(&add(&a_reduced, &b_reduced)) % &modulus
        );

        // Test addition with zero
        assert_eq!(
            (&a_bigint + &zero_bigint) % &modulus,
            u32_8_to_biguint(&add(&a_reduced, &zero)) % &modulus
        );

        // Test subtraction
        let expected_sub = if a_bigint < b_bigint {
            ((a_bigint.clone() + &modulus) - b_bigint.clone()) % &modulus
        } else {
            (a_bigint.clone() - b_bigint.clone()) % &modulus
        };
        assert_eq!(expected_sub, u32_8_to_biguint(&sub(&a_reduced, &b_reduced)) % &modulus);

        // Test subtraction with zero
        assert_eq!(
            (&a_bigint + &modulus - &zero_bigint) % &modulus,
            u32_8_to_biguint(&sub(&a_reduced, &zero)) % &modulus
        );

        // Test multiplication
        assert_eq!(
            (a_bigint.clone() * b_bigint.clone()) % &modulus,
            u32_8_to_biguint(&mul(&a_reduced, &b_reduced)) % &modulus
        );

        // Test multiplication with one
        assert_eq!(
            (&a_bigint * &one_bigint) % &modulus,
            u32_8_to_biguint(&mul(&a_reduced, &one)) % &modulus
        );

        // Test multiplication with zero
        assert_eq!(
            (&a_bigint * &zero_bigint) % &modulus,
            u32_8_to_biguint(&mul(&a_reduced, &zero)) % &modulus
        );
    }
    println!("All tests passed!");
}
