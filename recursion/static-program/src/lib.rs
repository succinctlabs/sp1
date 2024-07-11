use std::time::Instant;

use lazy_static::lazy_static;
use p3_baby_bear::BabyBear;
use sp1_core::{
    stark::{StarkProvingKey, StarkVerifyingKey},
    utils::BabyBearPoseidon2,
};
use sp1_recursion_core::runtime::RecursionProgram;

macro_rules! include_and_deserialize {
    ($name:ident) => {
        paste::item! {
            pub static [<$name _PROGRAM_BYTES>]: &[u8] =
                include_bytes!(concat!(env!("OUT_DIR"), "/", stringify!($name), "_program.bin"));
            pub static [<$name _PK_BYTES>]: &[u8] =
                include_bytes!(concat!(env!("OUT_DIR"), "/", stringify!($name), "_pk.bin"));
            pub static [<$name _VK_BYTES>]: &[u8] =
                include_bytes!(concat!(env!("OUT_DIR"), "/", stringify!($name), "_vk.bin"));

            lazy_static! {
                pub static ref [<$name _PROGRAM>]: RecursionProgram<BabyBear> = {
                    let start_time = Instant::now();
                    let res = bincode::deserialize(&[<$name _PROGRAM_BYTES>]).unwrap();
                    println!(
                        "{} program deserialized in {:?}",
                        stringify!($name),
                        start_time.elapsed()
                    );
                    res
                };
                pub static ref [<$name _PK>]: StarkProvingKey<BabyBearPoseidon2> = {
                    let start_time = Instant::now();
                    let res = bincode::deserialize(&[<$name _PK_BYTES>]).unwrap();
                    println!("{} pk deserialized in {:?}", stringify!($name), start_time.elapsed());
                    res
                };
                pub static ref [<$name _VK>]: StarkVerifyingKey<BabyBearPoseidon2> = {
                    let start_time = Instant::now();
                    let res = bincode::deserialize(&[<$name _VK_BYTES>]).unwrap();
                    println!("{} vk deserialized in {:?}", stringify!($name), start_time.elapsed());
                    res
                };
            }
        }
    };
}

include_and_deserialize!(RECURSION);
include_and_deserialize!(COMPRESS);
include_and_deserialize!(SHRINK);
include_and_deserialize!(WRAP);
include_and_deserialize!(DEFERRED);
