#![no_main]
sp1_zkvm::entrypoint!(main);

use num_bigint::BigUint;
use rand::Rng;
use sp1_zkvm::syscalls::syscall_bls12381_fp2_mulmod;
use std::{mem::transmute, str::FromStr};

const MODULUS: &str = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787";

fn random_u64_6(modulus: &BigUint) -> [u64; 6] {
    let mut rng = rand::thread_rng();
    let mut arr = [0u64; 6];
    let modulus_bytes = modulus.to_bytes_le();
    let modulus_u64: [u64; 6] = [
        u64::from_le_bytes(modulus_bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(modulus_bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(modulus_bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(modulus_bytes[24..32].try_into().unwrap()),
        u64::from_le_bytes(modulus_bytes[32..40].try_into().unwrap()),
        u64::from_le_bytes(modulus_bytes[40..48].try_into().unwrap()),
    ];

    for i in 0..6 {
        arr[i] = rng.gen_range(0..modulus_u64[i]);
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

fn fp2_mul(
    lhs_c0: &[u64; 6],
    lhs_c1: &[u64; 6],
    rhs_c0: &[u64; 6],
    rhs_c1: &[u64; 6],
) -> ([u64; 6], [u64; 6]) {
    let lhs = [*lhs_c0, *lhs_c1].concat();
    let rhs = [*rhs_c0, *rhs_c1].concat();

    let mut lhs_transmuted: [u32; 24] =
        unsafe { transmute::<[u64; 12], [u32; 24]>(lhs.try_into().unwrap()) };
    let rhs_transmuted: [u32; 24] =
        unsafe { transmute::<[u64; 12], [u32; 24]>(rhs.try_into().unwrap()) };

    syscall_bls12381_fp2_mulmod(lhs_transmuted.as_mut_ptr(), rhs_transmuted.as_ptr());

    let result_c0: [u64; 6] =
        unsafe { transmute::<[u32; 12], [u64; 6]>(lhs_transmuted[0..12].try_into().unwrap()) };
    let result_c1: [u64; 6] =
        unsafe { transmute::<[u32; 12], [u64; 6]>(lhs_transmuted[12..24].try_into().unwrap()) };

    (result_c0, result_c1)
}

pub fn main() {
    let modulus = BigUint::from_str(MODULUS).unwrap();

    for _ in 0..10 {
        let a_c0 = random_u64_6(&modulus);
        let a_c1 = random_u64_6(&modulus);
        let b_c0 = random_u64_6(&modulus);
        let b_c1 = random_u64_6(&modulus);

        let a_c0_bigint = u64_6_to_biguint(&a_c0);
        let a_c1_bigint = u64_6_to_biguint(&a_c1);
        let b_c0_bigint = u64_6_to_biguint(&b_c0);
        let b_c1_bigint = u64_6_to_biguint(&b_c1);

        let ac0_bc0_mod = (&a_c0_bigint * &b_c0_bigint) % &modulus;
        let ac1_bc1_mod = (&a_c1_bigint * &b_c1_bigint) % &modulus;

        let c0 = if ac0_bc0_mod < ac1_bc1_mod {
            (&modulus + ac0_bc0_mod - ac1_bc1_mod) % &modulus
        } else {
            (ac0_bc0_mod - ac1_bc1_mod) % &modulus
        };

        let c1 = ((&a_c0_bigint * &b_c1_bigint) % &modulus
            + (&a_c1_bigint * &b_c0_bigint) % &modulus)
            % &modulus;

        let (res_c0, res_c1) = fp2_mul(&a_c0, &a_c1, &b_c0, &b_c1);

        assert_eq!(c0, u64_6_to_biguint(&res_c0) % &modulus);
        assert_eq!(c1, u64_6_to_biguint(&res_c1) % &modulus);
    }

    println!("All tests passed!");
}
