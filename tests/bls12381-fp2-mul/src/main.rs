#![no_main]

sp1_zkvm::entrypoint!(main);
use field::{
    common::{Bls12381Curve, Curve},
    fp::Fp,
    fp2::Fp2,
};
use sp1_zkvm::syscalls::syscall_bls12381_fp2_mulmod;
use std::{mem::transmute, str::FromStr};

use num_bigint::BigUint;
pub fn main() {
    let modulus = &BigUint::from_str("4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787").unwrap();

    for _ in 0..10 {
        let a = Fp2::<Bls12381Curve>::random(&mut rand::thread_rng());
        let b = Fp2::<Bls12381Curve>::random(&mut rand::thread_rng());

        let ac0 = &BigUint::from_bytes_le(&a.c0.to_bytes_unsafe());
        let ac1 = &BigUint::from_bytes_le(&a.c1.to_bytes_unsafe());
        let bc0 = &BigUint::from_bytes_le(&b.c0.to_bytes_unsafe());
        let bc1 = &BigUint::from_bytes_le(&b.c1.to_bytes_unsafe());

        // schoolbook multiplication
        //   c_0 = a_0 b_0 - a_1 b_1
        //   c_1 = a_0 b_1 + a_1 b_0
        let c0 = match (ac0 * bc0) % modulus < (ac1 * bc1) % modulus {
            true => ((modulus + (ac0 * bc0) % modulus) - (ac1 * bc1) % modulus) % modulus,
            false => ((ac0 * bc0) % modulus - (ac1 * bc1) % modulus) % modulus,
        };
        let c1 = ((ac0 * bc1) % modulus + (ac1 * bc0) % modulus) % modulus;
        let rhs = a * b;

        assert_eq!(c0, BigUint::from_bytes_le(&rhs.c0.to_bytes_unsafe()));
        assert_eq!(c1, BigUint::from_bytes_le(&rhs.c1.to_bytes_unsafe()));
    }
}
