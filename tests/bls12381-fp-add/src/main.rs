#![no_main]

sp1_zkvm::entrypoint!(main);
use std::{mem::transmute, str::FromStr};

use sp1_zkvm::lib::syscall_bls12381_fp_addmod;

use num_bigint::BigUint;
use rand::Rng;

fn add(lhs: &[u64; 6], rhs: &[u64; 6]) -> [u64; 6] {
    unsafe {
        let mut lhs_transmuted = transmute::<[u64; 6], [u32; 12]>(*lhs);
        let rhs_transmuted = transmute::<[u64; 6], [u32; 12]>(*rhs);
        syscall_bls12381_fp_addmod(lhs_transmuted.as_mut_ptr(), rhs_transmuted.as_ptr());
        transmute::<[u32; 12], [u64; 6]>(lhs_transmuted)
    }
}

fn random_u64_6() -> [u64; 6] {
    let mut rng = rand::thread_rng();
    let mut arr = [0u64; 6];
    for i in 0..6 {
        arr[i] = rng.gen();
    }
    arr
}

fn u64_6_to_biguint(arr: &[u64; 6]) -> BigUint {
    let mut bytes = [0u8; 48];
    for i in 0..6 {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&arr[i].to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

pub fn main() {
    let modulus = BigUint::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787").unwrap();
    let zero: [u64; 6] = [0; 6];
    let zero_bigint = BigUint::ZERO;
    let one: [u64; 6] = [1, 0, 0, 0, 0, 0];
    let one_bigint = BigUint::from(1u32);
    for _ in 0..10 {
        let a = random_u64_6();
        let b = random_u64_6();
        let a_bigint = u64_6_to_biguint(&a);
        let b_bigint = u64_6_to_biguint(&b);

        assert_eq!(
            (a_bigint + b_bigint) % &modulus,
            u64_6_to_biguint(&add(&a, &b)) % &modulus
        );

        // Test addition with zero
        let a = random_u64_6();
        let a_bigint = u64_6_to_biguint(&a);
        assert_eq!(
            (&a_bigint + &zero_bigint) % &modulus,
            u64_6_to_biguint(&add(&a, &zero)) % &modulus
        );
    }
    println!("All tests passed!");
}
