use p3_baby_bear::BabyBear;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;

use crate::air::Block;
use crate::runtime::RecursionProgram;
use crate::runtime::Runtime;
use crate::stark::RecursionAir;
use crate::stark::RecursionAirSkinnyDeg9;
use p3_field::PrimeField32;
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
        let machine = RecursionAir::<_, 3>::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    if test_config == TestConfig::All || test_config == TestConfig::SkinnyDeg7 {
        let machine = RecursionAirSkinnyDeg9::machine(BabyBearPoseidon2::compressed());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }

    if test_config == TestConfig::All || test_config == TestConfig::SkinnyDeg7Wrap {
        let machine = RecursionAirSkinnyDeg9::wrap_machine(BabyBearPoseidon2::compressed());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        if let Err(e) = result {
            panic!("Verification failed: {:?}", e);
        }
    }
}

/// Returns whether the `SP1_DEV` environment variable is enabled or disabled.
///
/// This variable controls whether a smaller version of the circuit will be used for generating the
/// PLONK proofs. This is useful for development and testing purposes.
///
/// By default, the variable is disabled.
pub fn sp1_dev_mode() -> bool {
    let value = std::env::var("SP1_DEV").unwrap_or_else(|_| "false".to_string());
    let enabled = value == "1" || value.to_lowercase() == "true";
    if enabled {
        tracing::warn!("SP1_DEV enviroment variable is enabled. do not enable this in production");
    }
    enabled
}
