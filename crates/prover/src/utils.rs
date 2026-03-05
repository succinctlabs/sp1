use std::{
    fs::{self, File},
    io::Read,
    iter::{once, Skip, Take},
    sync::Arc,
};

use rand::{rngs::OsRng, RngCore};

use itertools::Itertools;
use slop_symmetric::CryptographicHasher;
use sp1_core_executor::Program;
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::{poseidon2_hasher, SP1Field};
use sp1_recursion_circuit::machine::RootPublicValues;
use sp1_recursion_executor::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH};

use crate::SP1CoreProofData;

/// Compute the digest of the public values.
pub fn recursion_public_values_digest(
    public_values: &RecursionPublicValues<SP1Field>,
) -> [SP1Field; 8] {
    let hasher = poseidon2_hasher();
    hasher.hash_slice(&public_values.as_array()[0..NUM_PV_ELMS_TO_HASH])
}

pub fn root_public_values_digest(public_values: &RootPublicValues<SP1Field>) -> [SP1Field; 8] {
    let hasher = poseidon2_hasher();
    let input = (*public_values.sp1_vk_digest())
        .into_iter()
        .chain(
            (*public_values.committed_value_digest()).into_iter().flat_map(|word| word.into_iter()),
        )
        .chain(once(*public_values.exit_code()))
        .chain(*public_values.vk_root())
        .chain(*public_values.proof_nonce())
        .collect::<Vec<_>>();
    hasher.hash_slice(&input)
}

pub fn is_root_public_values_valid(public_values: &RootPublicValues<SP1Field>) -> bool {
    let expected_digest = root_public_values_digest(public_values);
    for (value, expected) in public_values.digest().iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

/// Assert that the digest of the public values is correct.
pub fn is_recursion_public_values_valid(public_values: &RecursionPublicValues<SP1Field>) -> bool {
    let expected_digest = recursion_public_values_digest(public_values);
    for (value, expected) in public_values.digest.iter().copied().zip_eq(expected_digest) {
        if value != expected {
            return false;
        }
    }
    true
}

impl SP1CoreProofData {
    pub fn save(&self, path: &str) -> Result<(), std::io::Error> {
        let data = serde_json::to_string(self).unwrap();
        fs::write(path, data).unwrap();
        Ok(())
    }
}

/// Get the number of cycles for a given program.
pub fn get_cycles(elf: &[u8], stdin: &SP1Stdin) -> u64 {
    let program = Program::from(elf).unwrap();
    let mut executor = MinimalExecutorRunner::simple(Arc::new(program));
    for buf in &stdin.buffer {
        executor.with_input(buf);
    }
    while executor.execute_chunk().is_some() {}
    executor.global_clk()
}

/// Load an ELF file from a given path.
pub fn load_elf(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut elf_code = Vec::new();
    File::open(path)?.read_to_end(&mut elf_code)?;
    Ok(elf_code)
}

pub fn words_to_bytes<T: Copy>(words: &[[T; 4]; 8]) -> Vec<T> {
    words.iter().flat_map(|word| word.iter()).copied().collect()
}

/// Utility method for converting 32 big-endian bytes back into eight u32 words.
pub fn bytes_to_words_be(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for i in 0..8 {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4].try_into().unwrap();
        words[i] = u32::from_be_bytes(chunk);
    }
    words
}

pub trait MaybeTakeIterator<I: Iterator>: Iterator<Item = I::Item> {
    fn maybe_skip(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Skip(self.skip(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }

    fn maybe_take(self, bound: Option<usize>) -> RangedIterator<Self>
    where
        Self: Sized,
    {
        match bound {
            Some(bound) => RangedIterator::Take(self.take(bound)),
            None => RangedIterator::Unbounded(self),
        }
    }
}

impl<I: Iterator> MaybeTakeIterator<I> for I {}

pub enum RangedIterator<I> {
    Unbounded(I),
    Skip(Skip<I>),
    Take(Take<I>),
    Range(Take<Skip<I>>),
}

impl<I: Iterator> Iterator for RangedIterator<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            RangedIterator::Unbounded(unbounded) => unbounded.next(),
            RangedIterator::Skip(skip) => skip.next(),
            RangedIterator::Take(take) => take.next(),
            RangedIterator::Range(range) => range.next(),
        }
    }
}

/// Generate a 128-bit nonce using OsRng.
pub fn generate_nonce() -> [u32; 4] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);

    [
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    ]
}
