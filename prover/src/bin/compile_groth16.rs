#![feature(generic_const_exprs)]

use sp1_core::{
    runtime::Program,
    stark::{Proof, RiscvAir},
    utils::BabyBearPoseidon2,
};
use sp1_prover::SP1ProverImpl;
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_sdk::utils::setup_logger;

pub fn main() {
    setup_logger();

    let prover = SP1ProverImpl::new();
    let elf =
        include_bytes!("../../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");
    let program = Program::from(elf);
    let sp1_config = BabyBearPoseidon2::new();
    let sp1_machine = RiscvAir::machine(sp1_config);
    let (_, sp1_vk) = sp1_machine.setup(&program);
    let core_proof: Proof<BabyBearPoseidon2> = tracing::info_span!("sp1 proof")
        .in_scope(|| SP1ProverImpl::prove(elf, &[bincode::serialize::<u32>(&4).unwrap()]));
    let sp1_challenger = prover.initialize_challenger(&sp1_vk, &core_proof.shard_proofs);

    let inner_reduce_proof = tracing::info_span!("inner reduce proof")
        .in_scope(|| prover.reduce_tree::<2>(&sp1_vk, core_proof));

    let outer_reduce_proof = tracing::info_span!("outer reduce proof")
        .in_scope(|| prover.wrap_into_outer(&sp1_vk, sp1_challenger, inner_reduce_proof));

    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(&prover.reduce_vk_outer, outer_reduce_proof));

    // Write constraints to file
    let serialized = serde_json::to_string(&constraints).unwrap();
    let mut file = std::fs::File::create("constraints.json").unwrap();
    std::io::Write::write_all(&mut file, serialized.as_bytes()).unwrap();
}
