#![feature(generic_const_exprs)]
#![allow(incomplete_features)]

use sp1_prover::SP1Prover;
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_sdk::{utils::setup_logger, SP1Stdin};

pub fn main() {
    setup_logger();

    let elf = include_bytes!("../../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SP1Prover::new();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let stdin = SP1Stdin::new();
    let core_proof = prover.prove_core(&pk, &stdin);

    // TODO: Get rid of this method by reading it from public values.
    let core_challenger = prover.setup_core_challenger(&vk, &core_proof);

    tracing::info!("reduce");
    let reduced_proof = prover.reduce(&vk, core_proof);

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(&vk, core_challenger, reduced_proof);

    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(&prover.reduce_vk_outer, wrapped_proof));

    // Write constraints to file
    let serialized = serde_json::to_string(&constraints).unwrap();
    let mut file = std::fs::File::create("constraints.json").unwrap();
    std::io::Write::write_all(&mut file, serialized.as_bytes()).unwrap();
}
