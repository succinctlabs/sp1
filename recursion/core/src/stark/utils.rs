use p3_baby_bear::BabyBear;
use sp1_core::stark::StarkGenericConfig;
use sp1_core::utils;
use sp1_core::utils::BabyBearPoseidon2;
use std::env;

use crate::runtime::ExecutionRecord;
use crate::runtime::RecursionProgram;

use super::RecursionAir;

/// Should only be used in tests to debug the constraints after running a runtime instance.
pub fn debug_constraints(program: RecursionProgram<BabyBear>, record: ExecutionRecord<BabyBear>) {
    env::set_var("RUST_LOG", "debug");
    utils::setup_logger();
    let machine = RecursionAir::<_, 3>::machine(BabyBearPoseidon2::default());
    let (pk, _) = machine.setup(&program);
    let mut challenger = machine.config().challenger();
    machine.debug_constraints(&pk, record, &mut challenger);
}
