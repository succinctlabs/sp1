use std::time::Instant;

use lazy_static::lazy_static;
use p3_baby_bear::BabyBear;
use sp1_core::{
    stark::{StarkProvingKey, StarkVerifyingKey},
    utils::BabyBearPoseidon2,
};
use sp1_recursion_core::{runtime::RecursionProgram, stark::config::BabyBearPoseidon2Outer};

pub static RECURSION_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/recursion_program.bin"));
pub static RECURSION_PK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rec_pk.bin"));
pub static RECURSION_VK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rec_vk.bin"));
pub static DEFERRED_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/deferred_program.bin"));
pub static DEFERRED_PK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/deferred_pk.bin"));
pub static DEFERRED_VK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/deferred_vk.bin"));
pub static COMPRESS_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/compress_program.bin"));
pub static COMPRESS_PK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/compress_pk.bin"));
pub static COMPRESS_VK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/compress_vk.bin"));
pub static SHRINK_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/shrink_program.bin"));
pub static SHRINK_PK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shrink_pk.bin"));
pub static SHRINK_VK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shrink_vk.bin"));
pub static WRAP_PROGRAM_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wrap_program.bin"));
pub static WRAP_PK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_pk.bin"));
pub static WRAP_VK_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_vk.bin"));

lazy_static! {
    pub static ref RECURSION_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&RECURSION_PROGRAM_BYTES).unwrap();
        println!(
            "Recursion program deserialized in {:?}",
            start_time.elapsed()
        );
        res
    };
    pub static ref RECURSION_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&RECURSION_PK_BYTES).unwrap();
        println!("Recursion pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref RECURSION_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&RECURSION_VK_BYTES).unwrap();
        println!("Recursion vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref DEFERRED_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&DEFERRED_PROGRAM_BYTES).unwrap();
        println!(
            "Deferred program deserialized in {:?}",
            start_time.elapsed()
        );
        res
    };
    pub static ref DEFERRED_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&DEFERRED_PK_BYTES).unwrap();
        println!("Deferred pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref DEFERRED_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&DEFERRED_VK_BYTES).unwrap();
        println!("Deferred vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref COMPRESS_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&COMPRESS_PROGRAM_BYTES).unwrap();
        println!(
            "Compress program deserialized in {:?}",
            start_time.elapsed()
        );
        res
    };
    pub static ref COMPRESS_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&COMPRESS_PK_BYTES).unwrap();
        println!("Compress pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref COMPRESS_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&COMPRESS_VK_BYTES).unwrap();
        println!("Compress vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref SHRINK_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&SHRINK_PROGRAM_BYTES).unwrap();
        println!("Shrink program deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref SHRINK_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&SHRINK_PK_BYTES).unwrap();
        println!("Shrink pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref SHRINK_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&SHRINK_VK_BYTES).unwrap();
        println!("Shrink vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&WRAP_PROGRAM_BYTES).unwrap();
        println!("Wrap program deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_PK: StarkProvingKey<BabyBearPoseidon2Outer> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&WRAP_PK_BYTES).unwrap();
        println!("Wrap pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_VK: StarkVerifyingKey<BabyBearPoseidon2Outer> = {
        let start_time = Instant::now();
        let res = bincode::deserialize(&WRAP_VK_BYTES).unwrap();
        println!("Wrap vk deserialized in {:?}", start_time.elapsed());
        res
    };
}
