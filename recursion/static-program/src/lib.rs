use std::time::Instant;

use lazy_static::lazy_static;
use p3_baby_bear::BabyBear;
use sp1_recursion_core::runtime::RecursionProgram;

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
    pub static ref SHRINK_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/shrink_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Shrink program deserialized in {:?}", start_time.elapsed());
        res
    };
    pub static ref WRAP_PROGRAM: RecursionProgram<BabyBear> = {
        let start_time = Instant::now();
        let program = include_bytes!(concat!(env!("OUT_DIR"), "/wrap_program.bin"));
        let res = bincode::deserialize(program).unwrap();
        println!("Wrap program deserialized in {:?}", start_time.elapsed());
        res
    };
}
