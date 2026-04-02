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
        let mut result = [0u8; 32];
        result[1..].copy_from_slice(&vkey_bytes);
        result
    }

    /// Hash the key into a digest of bytes elements.
    fn hash_bytes(&self) -> [u8; DIGEST_SIZE * 4] {
        words_to_bytes_be(&self.hash_u32())
    }

    /// Hash the key into a digest of u64 elements.
    fn hash_u64(&self) -> [u64; DIGEST_SIZE / 2] {
        self.hash_u32()
            .chunks_exact(2)
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
        let num_inputs = DIGEST_SIZE + 3 + 14 + 1;
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.preprocessed_commit.borrow());
        inputs.extend(self.pc_start);
        inputs.extend(self.initial_global_cumulative_sum.0.x.0);
        inputs.extend(self.initial_global_cumulative_sum.0.y.0);
        inputs.push(self.enable_untrusted_programs);

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
