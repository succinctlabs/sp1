use std::time::Instant;

use lazy_static::lazy_static;
use p3_baby_bear::BabyBear;
use sp1_core::{
    stark::{StarkProvingKey, StarkVerifyingKey},
    utils::BabyBearPoseidon2,
};
use sp1_recursion_core::{runtime::RecursionProgram, stark::config::BabyBearPoseidon2Outer};

lazy_static! {
    pub static ref RECURSION_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/recursion_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!(
            "Recursion program deserialized in {:?}",
            start_time.elapsed()
        );
        res
    };
    pub static ref RECURSION_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/rec_pk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Recursion pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref RECURSION_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/rec_vk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Recursion vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref DEFERRED_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/deferred_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!(
            "Deferred program deserialized in {:?}",
            start_time.elapsed()
        );
        res
    };
    pub static ref DEFERRED_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/deferred_pk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Deferred pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref DEFERRED_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/deferred_vk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Deferred vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref COMPRESS_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/compress_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!(
            "Compress program deserialized in {:?}",
            start_time.elapsed()
        );
        res
    };
    pub static ref COMPRESS_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/compress_pk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Compress pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref COMPRESS_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/compress_vk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Compress vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref SHRINK_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/shrink_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Shrink program deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref SHRINK_PK: StarkProvingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/shrink_pk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Shrink pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref SHRINK_VK: StarkVerifyingKey<BabyBearPoseidon2> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/shrink_vk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Shrink vk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Wrap program deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_PK: StarkProvingKey<BabyBearPoseidon2Outer> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_pk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Wrap pk deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_VK: StarkVerifyingKey<BabyBearPoseidon2Outer> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_vk.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Wrap vk deserialized in {:?}", start_time.elapsed());
        res
    };
}
