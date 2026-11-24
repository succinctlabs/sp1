use std::borrow::Borrow;

use serde::{Deserialize, Serialize};
pub use slop_algebra::PrimeField32;
use slop_algebra::{AbstractField, PrimeField};
use slop_bn254::Bn254Fr;
use slop_challenger::IopCtx;
use sp1_primitives::{poseidon2_hash, SP1Field, SP1GlobalContext};

use crate::{MachineVerifyingKey, DIGEST_SIZE};

/// The information necessary to verify a proof for a given RISC-V program.
#[derive(Clone, Serialize, Deserialize)]
pub struct SP1VerifyingKey {
    /// The underlying verifying key, where the underlying field is `SP1Field` and the digest type
    /// is an array of `DIGEST_SIZE` `SP1Field` elements.
    pub vk: MachineVerifyingKey<SP1GlobalContext>,
}

/// Convert 8 `SP1Field` words into a `Bn254Fr` field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
#[must_use]
pub fn koalabears_to_bn254(digest: &[SP1Field; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for word in digest.iter() {
        // Since SP1Field prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

/// Utility method for converting u32 words to bytes in big endian.
#[must_use]
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey {
    /// Hash the key into a digest of `SP1Field` elements.
    fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE];

    /// Hash the key into a digest of u32 elements.
    fn hash_u32(&self) -> [u32; DIGEST_SIZE];

    /// Hash the key into a `Bn254Fr` element.
    fn hash_bn254(&self) -> Bn254Fr {
        koalabears_to_bn254(&self.hash_koalabear())
    }

    /// Hash the key into a 32 byte hex string, prefixed with "0x".
    ///
    /// This is ideal for generating a vkey hash for onchain verification.
    fn bytes32(&self) -> String {
        let vkey_digest_bn254 = self.hash_bn254();
        format!("0x{:0>64}", vkey_digest_bn254.as_canonical_biguint().to_str_radix(16))
    }

    /// Hash the key into a 32 byte array.
    ///
    /// This has the same value as `bytes32`, but as a raw byte array.
    fn bytes32_raw(&self) -> [u8; 32] {
        let vkey_digest_bn254 = self.hash_bn254();
        let vkey_bytes = vkey_digest_bn254.as_canonical_biguint().to_bytes_be();
        assert!(vkey_bytes.len() <= 32, "Bn254Fr digest exceeded 32 bytes");
        let mut result = [0u8; 32];
        result[32 - vkey_bytes.len()..].copy_from_slice(&vkey_bytes);
        result
    }

    /// Hash the key into a digest of bytes elements.
    fn hash_bytes(&self) -> [u8; DIGEST_SIZE * 4] {
        words_to_bytes_be(&self.hash_u32())
    }

    /// Hash the key into a digest of u64 elements.
    fn hash_u64(&self) -> [u64; DIGEST_SIZE / 2] {
        self.hash_u32()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| chunk[0] as u64 | ((chunk[1] as u64) << 32))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

impl HashableKey for SP1VerifyingKey {
    fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE] {
        self.vk.hash_koalabear()
    }

    fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
        self.vk.hash_u32()
    }
}

impl<GC: IopCtx<F = SP1Field>> HashableKey for MachineVerifyingKey<GC>
where
    GC::Digest: Borrow<[SP1Field; DIGEST_SIZE]>,
{
    fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE] {
        #[cfg(not(feature = "mprotect"))]
        let num_inputs = DIGEST_SIZE + 3 + 14 + 1;
        #[cfg(feature = "mprotect")]
        let num_inputs = DIGEST_SIZE + 3 + 14 + 1 + 1 + 9 + 6;
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.preprocessed_commit.borrow());
        inputs.extend(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        inputs.push(self.untrusted_config.enable_untrusted_programs);
        #[cfg(feature = "mprotect")]
        inputs.push(self.untrusted_config.enable_trap_handler);
        #[cfg(feature = "mprotect")]
        inputs.extend(self.untrusted_config.trap_context.as_flattened());
        #[cfg(feature = "mprotect")]
        inputs.extend(self.untrusted_config.untrusted_memory.as_flattened());

        poseidon2_hash(inputs)
    }

    fn hash_u32(&self) -> [u32; 8] {
        self.hash_koalabear()
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestKey([SP1Field; DIGEST_SIZE]);

    impl HashableKey for TestKey {
        fn hash_koalabear(&self) -> [SP1Field; DIGEST_SIZE] {
            self.0
        }

        fn hash_u32(&self) -> [u32; DIGEST_SIZE] {
            self.0.map(|f| f.as_canonical_u32())
        }
    }

    fn decode_bytes32(hex_str: &str) -> [u8; 32] {
        let hex_digits = hex_str.strip_prefix("0x").expect("bytes32 should have 0x prefix");
        assert_eq!(hex_digits.len(), 64);
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_digits[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn test_bytes32_raw_leading_zero_bytes() {
        // digest[0] < 2^23 produces a <= 30-byte big-endian representation (< 2^240).
        let mut digest = [SP1Field::zero(); DIGEST_SIZE];
        digest[0] = SP1Field::from_canonical_u32((1 << 23) - 1);
        digest[1] = SP1Field::one();
        let key = TestKey(digest);
        assert_eq!(key.hash_bn254().as_canonical_biguint().to_bytes_be().len(), 30);
        assert_eq!(key.bytes32_raw(), decode_bytes32(&key.bytes32()));
    }

    #[test]
    fn test_bytes32_raw_zero_digest() {
        // Zero digest produces a 1-byte ([0]) big-endian representation.
        let key = TestKey([SP1Field::zero(); DIGEST_SIZE]);
        assert_eq!(key.hash_bn254().as_canonical_biguint().to_bytes_be(), vec![0]);
        assert_eq!(key.bytes32_raw(), [0u8; 32]);
        assert_eq!(key.bytes32_raw(), decode_bytes32(&key.bytes32()));
    }

    #[test]
    fn test_bytes32_raw_full_31_bytes() {
        // digest[0] >= 2^23 produces a 31-byte big-endian representation (>= 2^240).
        let mut digest = [SP1Field::zero(); DIGEST_SIZE];
        digest[0] = SP1Field::from_canonical_u32(1 << 23);
        let key = TestKey(digest);
        assert_eq!(key.hash_bn254().as_canonical_biguint().to_bytes_be().len(), 31);
        let raw = key.bytes32_raw();
        assert_eq!(raw[0], 0);
        assert_eq!(raw, decode_bytes32(&key.bytes32()));
    }
}
