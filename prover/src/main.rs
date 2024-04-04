#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use std::time::Instant;

use sp1_core::{
    runtime::Program,
    stark::{Proof, RiscvAir, StarkGenericConfig, VerifyingKey},
    utils::{run_and_prove, setup_logger, BabyBearPoseidon2},
};
use sp1_recursion_compiler::asm::AsmConfig;
use sp1_recursion_core::runtime::Runtime;
use sp1_recursion_program::compress::build_compress;

fn main() {
    let (sp1_proof, vk) = prove_sp1();
    prove_compress(sp1_proof, vk);
}

type SC = BabyBearPoseidon2;
type F = <SC as StarkGenericConfig>::Val;
type EF = <SC as StarkGenericConfig>::Challenge;
type C = AsmConfig<F, EF>;
type A = RiscvAir<F>;

fn prove_sp1() -> (Proof<SC>, VerifyingKey<SC>) {
    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    let config = SC::default();
    let machine = RiscvAir::machine(config.clone());
    let program = Program::from(elf);
    let (_, vk) = machine.setup(&program);
    #[allow(deprecated)]
    let stdin = sp1_core::SP1Stdin {
        buffer: vec![],
        ptr: 0,
    };
    let (proof, _) = run_and_prove(program, stdin, config);
    let mut challenger_ver = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger_ver).unwrap();
    println!("Proof generated successfully");

    (proof, vk)
}

fn prove_compress(sp1_proof: Proof<SC>, vk: VerifyingKey<SC>) {
    setup_logger();

    let program = build_compress(sp1_proof, vk);

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
