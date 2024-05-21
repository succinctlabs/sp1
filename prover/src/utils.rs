use std::{
    fs::{self, File},
    io::Read,
};

use futures::Future;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use sp1_core::{
    air::Word,
    io::SP1Stdin,
    runtime::{Program, Runtime},
};
use tokio::{runtime, task::block_in_place};

use crate::SP1CoreProofData;

pub const RECONSTRUCT_COMMITMENTS_ENV_VAR: &str = "RECONSTRUCT_COMMITMENTS";

impl SP1CoreProofData {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

/// Get the number of cycles for a given program.
pub fn get_cycles(elf: &[u8], stdin: &SP1Stdin) -> u64 {
    let program = Program::from(elf);
    let mut runtime = Runtime::new(program);
    runtime.write_vecs(&stdin.buffer);
    runtime.dry_run();
    runtime.state.global_clk
}

/// Load an ELF file from a given path.
pub fn load_elf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut elf_code = Vec::new();
    File::open(path)?.read_to_end(&mut elf_code)?;
    Ok(elf_code)
}

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    return words.iter().flat_map(|word| word.0).collect();
}

/// Convert 8 BabyBear words into a Bn254Fr field element by shifting by 31 bits each time. The last
/// word becomes the least significant bits.
pub fn babybears_to_bn254(digest: &[BabyBear; 8]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for word in digest.iter() {
        // Since BabyBear prime is less than 2^31, we can shift by 31 bits each time and still be
        // within the Bn254Fr field, so we don't have to truncate the top 3 bits.
        result *= Bn254Fr::from_canonical_u64(1 << 31);
        result += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
    }
    result
}

/// Convert 32 BabyBear bytes into a Bn254Fr field element. The first byte's most significant 3 bits
/// (which would become the 3 most significant bits) are truncated.
pub fn babybear_bytes_to_bn254(bytes: &[BabyBear; 32]) -> Bn254Fr {
    let mut result = Bn254Fr::zero();
    for (i, byte) in bytes.iter().enumerate() {
        debug_assert!(byte < &BabyBear::from_canonical_u32(256));
        if i == 0 {
            // 32 bytes is more than Bn254 prime, so we need to truncate the top 3 bits.
            result = Bn254Fr::from_canonical_u32(byte.as_canonical_u32() & 0x1f);
        } else {
            result *= Bn254Fr::from_canonical_u32(256);
            result += Bn254Fr::from_canonical_u32(byte.as_canonical_u32());
        }
    }
    result
}

/// Utility method for converting u32 words to bytes in big endian.
pub fn words_to_bytes_be(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_be_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    bytes
}

/// Utility method for blocking on an async function. If we're already in a tokio runtime, we'll
/// block in place. Otherwise, we'll create a new runtime.
pub fn block_on<T>(fut: impl Future<Output = T>) -> T {
    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}
