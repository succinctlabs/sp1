#![allow(unused_imports)]
use crate::utils::CurveOperations;
use crate::{syscall_bls12381_add, syscall_bls12381_decompress, syscall_bls12381_double};

use amcl::bls381::bls381::utils::deserialize_g1;
use anyhow::Result;

#[derive(Copy, Clone)]
pub struct Bls12381;

const NUM_WORDS: usize = 24;

impl CurveOperations<NUM_WORDS> for Bls12381 {
    // The generator has been taken from py_ecc python library by Ethereum Foundation.
    // https://github.com/ethereum/py_ecc/blob/7b9e1b3/py_ecc/bls12_381/bls12_381_curve.py#L38-L45
    const GENERATOR: [u32; NUM_WORDS] = [
        3_676_489_403,
        4_214_943_754,
        4_185_529_071,
        1_817_569_343,
        387_689_560,
        2_706_258_495,
        2_541_009_157,
        3_278_408_783,
        1_336_519_695,
        647_324_556,
        832_034_708,
        401_724_327,
        1_187_375_073,
        212_476_713,
        2_726_857_444,
        3_493_644_100,
        738_505_709,
        14_358_731,
        3_587_181_302,
        4_243_972_245,
        1_948_093_156,
        2_694_721_773,
        3_819_610_353,
        146_011_265,
    ];

    fn add_assign(limbs: &mut [u32; NUM_WORDS], other: &[u32; NUM_WORDS]) {
        unsafe {
            syscall_bls12381_add(limbs.as_mut_ptr(), other.as_ptr());
        }
    }

    fn double(limbs: &mut [u32; NUM_WORDS]) {
        unsafe {
            syscall_bls12381_double(limbs.as_mut_ptr());
        }
    }
}

/// Decompresses a compressed public key using `bls12381_decompress` precompile.
pub fn decompress_pubkey(compressed_key: &[u8; 48]) -> Result<[u8; 96]> {
    cfg_if::cfg_if! {
        if #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))] {
            let mut decompressed_key = [0u8; 96];
            decompressed_key[..48].copy_from_slice(compressed_key);
            let is_odd = (decompressed_key[0] & 0b_0010_0000) >> 5 == 0;
            decompressed_key[0] &= 0b_0001_1111;
            unsafe {
                syscall_bls12381_decompress(&mut decompressed_key, is_odd);
            }

            Ok(decompressed_key)
        } else {
            let point = deserialize_g1(compressed_key.as_slice()).unwrap();
            let x = point.getx().to_string();
            let y = point.gety().to_string();

            let decompressed_key = hex::decode(format!("{x}{y}")).unwrap();
            let mut result = [0u8; 96];
            result.copy_from_slice(&decompressed_key);

            Ok(result)
        }
    }
}
