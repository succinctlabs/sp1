#![allow(unused)]

use crate::syscall_bls12381_decompress;
use amcl::bls381::bls381::utils::deserialize_g1;
use anyhow::Result;

/// Decompresses a compressed public key using bls12381_decompress precompile.
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
            let point = deserialize_g1(&compressed_key.as_slice()).unwrap();
            let x = point.getx().to_string();
            let y = point.gety().to_string();

            let decompressed_key = hex::decode(format!("{x}{y}")).unwrap();
            let mut result = [0u8; 96];
            result.copy_from_slice(&decompressed_key);

            Ok(result)
        }
    }
}

