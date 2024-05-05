use crate::stark::RecursionAirWideDeg3;
use p3_baby_bear::BabyBear;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;
use std::env;

use crate::air::Block;
use crate::runtime::RecursionProgram;
use crate::runtime::Runtime;
use crate::stark::RecursionAirSkinnyDeg7;
use p3_field::PrimeField32;
use sp1_core::utils::run_test_machine;
use std::collections::VecDeque;

#[derive(PartialEq, Clone, Debug)]
pub enum TestConfig {
    All,
    WideDeg3,
    SkinnyDeg7,
}

type Val = <BabyBearPoseidon2 as StarkGenericConfig>::Val;
type Challenge = <BabyBearPoseidon2 as StarkGenericConfig>::Challenge;

/// Should only be used in tests to debug the constraints after running a runtime instance.
pub fn run_test_recursion(
    program: RecursionProgram<Val>,
    witness: Option<VecDeque<Vec<Block<BabyBear>>>>,
    test_config: TestConfig,
) {
    utils::setup_logger();
    env::set_var("RUST_LOG", "debug");

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
        result.unwrap();
    }

    if test_config == TestConfig::All || test_config == TestConfig::SkinnyDeg7 {
        let machine = RecursionAirSkinnyDeg7::machine(BabyBearPoseidon2::default());
        let (pk, vk) = machine.setup(&program);
        let record = runtime.record.clone();
        let result = run_test_machine(record, machine, pk, vk);
        result.unwrap();
    }
}
