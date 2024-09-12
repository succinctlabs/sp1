use std::{
    borrow::Borrow,
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
};

use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::{AbstractField, PrimeField32};
use sp1_core_executor::{Executor, Program};
use sp1_core_machine::{io::SP1Stdin, reduce::SP1ReduceProof, riscv::CoreShapeConfig};
use sp1_recursion_core_v2::{
    air::RecursionPublicValues, shape::RecursionShapeConfig, stark::config::BabyBearPoseidon2Outer,
};
use sp1_stark::{SP1CoreOpts, Word};

use crate::{CompressAir, SP1CoreProofData};

/// Get the SP1 vkey BabyBear Poseidon2 digest this reduce proof is representing.
pub fn sp1_vkey_digest_babybear(proof: &SP1ReduceProof<BabyBearPoseidon2Outer>) -> [BabyBear; 8] {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<BabyBear> = proof.public_values.as_slice().borrow();
    pv.sp1_vk_digest
}

/// Get the SP1 vkey Bn Poseidon2 digest this reduce proof is representing.
pub fn sp1_vkey_digest_bn254(proof: &SP1ReduceProof<BabyBearPoseidon2Outer>) -> Bn254Fr {
    babybears_to_bn254(&sp1_vkey_digest_babybear(proof))
}

/// Get the committed values Bn Poseidon2 digest this reduce proof is representing.
pub fn sp1_commited_values_digest_bn254(proof: &SP1ReduceProof<BabyBearPoseidon2Outer>) -> Bn254Fr {
    let proof = &proof.proof;
    let pv: &RecursionPublicValues<BabyBear> = proof.public_values.as_slice().borrow();
    let committed_values_digest_bytes: [BabyBear; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    babybear_bytes_to_bn254(&committed_values_digest_bytes)
}

pub fn get_all_vk_digests(
    core_shape_config: &CoreShapeConfig<BabyBear>,
    recursion_shape_config: &RecursionShapeConfig<BabyBear, CompressAir<BabyBear>>,
    reduce_batch_size: usize,
) -> BTreeMap<[BabyBear; 8], usize> {
    let mut vk_map = core_shape_config
        .generate_all_allowed_shapes()
        .enumerate()
        .map(|(i, _)| ([BabyBear::from_canonical_usize(i); 8], i))
        .collect::<BTreeMap<_, _>>();

    let num_first_layer_vks = vk_map.len();

    vk_map.extend(
        recursion_shape_config.get_all_shape_combinations(reduce_batch_size).enumerate().map(
            |(i, _)| {
                let index = num_first_layer_vks + i;
                ([BabyBear::from_canonical_usize(index); 8], index)
            },
        ),
    );

    vk_map
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
    let mut runtime = Executor::new(program, SP1CoreOpts::default());
    runtime.write_vecs(&stdin.buffer);
    runtime.run_fast().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_all_vk_digests() {
        let core_shape_config = CoreShapeConfig::default();
        let recursion_shape_config = RecursionShapeConfig::default();
        let reduce_batch_size = 2;
        let vk_digests =
            get_all_vk_digests(&core_shape_config, &recursion_shape_config, reduce_batch_size);
        println!("Number of vk digests: {}", vk_digests.len());
        assert!(vk_digests.len() < 1 << 24);
    }
}
