use std::time::Instant;

use sp1_core::{
    stark::{RiscvAir, StarkGenericConfig},
    utils::{setup_logger, BabyBearPoseidon2},
};
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_core::runtime::Runtime;
use sp1_recursion_program::compress::build_compress;

fn main() {
    println!("Hello, world!");

    prove_compress();
}

fn prove_sp1() {}

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;
type A = RiscvAir<F>;

fn prove_compress() {
    setup_logger();

    let program = build_compress();

    let config = SC::default();
    let machine = A::machine(config);
    let mut runtime = Runtime::<F, EF, _>::new(&program, machine.config().perm.clone());

    let time = Instant::now();
    runtime.run();
    let elapsed = time.elapsed();
    runtime.print_stats();
    println!("Execution took: {:?}", elapsed);
}

fn prove_reduce() {}

fn prove_snark() {}
