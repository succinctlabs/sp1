#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use clap::Parser;
use sp1_core::io::SP1Stdin;
use sp1_prover::SP1Prover;
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_groth16_ffi::Groth16Prover;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    build_dir: String,
}

pub fn main() {
    sp1_core::utils::setup_logger();
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    let args = Args::parse();

    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SP1Prover::new();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let stdin = SP1Stdin::new();
    let core_proof = prover.prove_core(&pk, &stdin);
    let core_challenger = prover.setup_core_challenger(&vk, &core_proof);

    tracing::info!("reduce");
    let reduced_proof = prover.reduce(&vk, core_proof);

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(&vk, core_challenger, reduced_proof);

    tracing::info!("building verifier constraints");
    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(&prover.reduce_vk_outer, wrapped_proof.clone()));

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    wrapped_proof.write(&mut witness);

    tracing::info!("sanity check gnark test");
    Groth16Prover::test(constraints.clone(), witness.clone());

    tracing::info!("sanity check gnark build");
    Groth16Prover::build(
        constraints.clone(),
        witness.clone(),
        args.build_dir.clone().into(),
    );

    tracing::info!("sanity check gnark prove");
    let proof = Groth16Prover::prove(witness.clone(), args.build_dir.clone().into());

    println!("{:?}", proof);
}
