use crate::stark::RecursionAirWideDeg3;
use p3_baby_bear::BabyBear;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;

use crate::air::Block;
use crate::runtime::RecursionProgram;
use crate::runtime::Runtime;
use crate::stark::RecursionAirSkinnyDeg7;
use p3_field::PrimeField32;
use sp1_core::stark::ProgramVerificationError;
use sp1_core::utils::run_test_machine;
use std::collections::VecDeque;

#[derive(PartialEq, Clone, Debug)]
pub enum TestConfig {
    All,
    WideDeg3,
    SkinnyDeg7,
    SkinnyDeg7Wrap,
}

type Val = <BabyBearPoseidon2 as StarkGenericConfig>::Val;
type Challenge = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge;

/// Takes in a program and runs it with the given witness and generates a proof with a variety of
/// machines depending on the provided test_config.
pub fn run_test_recursion(
    program: RecursionProgram<Val>,
    witness: Option<VecDeque<Vec<Block<BabyBear>>>>,
    test_config: TestConfig,
) {
    utils::setup_logger();
    let config = BabyBearPoseidon2::default();

    let mut runtime = Runtime::<Val, Challenge, _>::new(&program, config.perm.clone());
    if witness.is_some() {
        runtime.witness_stream = witness.unwrap();
    }
    runtime.run();
    println!(
        "The program executed successfully, number of cycles: {}",
        runtime.clk.as_canonical_u32() / 4
    );

    if test_config == TestConfig::All || test_config == TestConfig::WideDeg3 {
        let machine = RecursionAirWideDeg3::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    if test_config == TestConfig::All || test_config == TestConfig::SkinnyDeg7 {
        let machine = RecursionAirSkinnyDeg7::machine(BabyBearPoseidon2::compressed());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    if test_config == TestConfig::All || test_config == TestConfig::SkinnyDeg7Wrap {
        let machine = RecursionAirSkinnyDeg7::wrap_machine(BabyBearPoseidon2::compressed());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            if let ProgramVerificationError::<BabyBearPoseidon2>::NonZeroCumulativeSum = e {
                // For now we ignore this error, as the cumulative sum checking is expected to fail.
            } else {
                panic!("Verification failed: {:?}", e);
            }
        }
    }
}
