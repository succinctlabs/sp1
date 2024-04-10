#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]

use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    runtime::Program,
    stark::{LocalProver, Proof, RiscvAir, ShardProof, StarkGenericConfig},
    utils::{run_and_prove, BabyBearPoseidon2},
};
use sp1_recursion_core::{runtime::Runtime, stark::RecursionAir};
use sp1_recursion_program::{hints::Hintable, reduce::build_reduce, stark::EMPTY};

type InnerSC = BabyBearPoseidon2;
type InnerF = <InnerSC as StarkGenericConfig>::Val;
type InnerEF = <InnerSC as StarkGenericConfig>::Challenge;
type InnerA = RiscvAir<InnerF>;

pub struct SP1ProverImpl;

impl SP1ProverImpl {
    pub fn prove(elf: &[u8], stdin: &[Vec<u8>]) -> Proof<InnerSC> {
        let config = InnerSC::default();
        let machine = RiscvAir::machine(config.clone());
        let program = Program::from(elf);
        let (_, vk) = machine.setup(&program);
        let start = Instant::now();
        let (proof, _) = run_and_prove(program, stdin, config);
        let duration = start.elapsed().as_secs_f64();
        println!("leaf proving time = {:?}", duration);
        let mut challenger_ver = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger_ver).unwrap();
        proof
    }

    pub fn reduce(elf: &[u8], proof: Proof<InnerSC>) -> Vec<ShardProof<InnerSC>> {
        let config = InnerSC::default();
        let machine = RiscvAir::machine(config.clone());
        let program = Program::from(elf);
        let (_, vk) = machine.setup(&program);
        let reduce_program = build_reduce();
        println!("nb_shards {}", proof.shard_proofs.len());
        let config = InnerSC::default();

        let is_recursive_flags: Vec<usize> = proof.shard_proofs.iter().map(|_| 0).collect();
        let sorted_indices: Vec<Vec<usize>> = proof
            .shard_proofs
            .iter()
            .map(|p| {
                machine
                    .chips_sorted_indices(p)
                    .into_iter()
                    .map(|x| match x {
                        Some(x) => x,
                        None => EMPTY,
                    })
                    .collect()
            })
            .collect();

        let mut challenger = machine.config().challenger();
        challenger.observe(vk.commit);
        let reconstruct_challenger = challenger.clone();
        for proof in proof.shard_proofs.iter() {
            challenger.observe(proof.commitment.main_commit);
            let public_values = PublicValues::<Word<BabyBear>, BabyBear>::new(proof.public_values);
            challenger.observe_slice(&public_values.to_vec());
        }

        let chips = machine.chips();
        let ordering = vk.chip_ordering.clone();
        let (prep_sorted_indices, prep_domains): (
            Vec<usize>,
            Vec<TwoAdicMultiplicativeCoset<BabyBear>>,
        ) = machine
            .preprocessed_chip_ids()
            .into_iter()
            .map(|chip_idx| {
                let name = chips[chip_idx].name().clone();
                let prep_sorted_idx = ordering[&name];
                (prep_sorted_idx, vk.chip_information[prep_sorted_idx].1)
            })
            .unzip();

        // Generate inputs.
        let mut witness_stream = Vec::new();
        witness_stream.extend(proof.shard_proofs.write());
        witness_stream.extend(is_recursive_flags.write());
        witness_stream.extend(sorted_indices.write());
        witness_stream.extend(challenger.write());
        witness_stream.extend(reconstruct_challenger.write());
        witness_stream.extend(prep_sorted_indices.write());
        witness_stream.extend(prep_domains.write());
        witness_stream.extend(vk.write());
        witness_stream.extend(vk.write());

        // Execute runtime.
        let machine = InnerA::machine(config);
        let mut runtime =
            Runtime::<InnerF, InnerEF, _>::new(&reduce_program, machine.config().perm.clone());
        runtime.witness_stream = witness_stream;
        runtime.run();
        runtime.print_stats();

        // Generate proof.
        let config = BabyBearPoseidon2::new();
        let machine = RecursionAir::machine(config);
        let (pk, _) = machine.setup(&reduce_program);
        // let mut challenger = machine.config().challenger();
        // let record_clone = runtime.record.clone();
        // machine.debug_constraints(&pk, record_clone, &mut challenger);
        let start = Instant::now();
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
        let duration = start.elapsed().as_secs();
        println!("recursion duration = {}", duration);

        // let mut challenger = machine.config().challenger();
        // machine.verify(&vk, &proof, &mut challenger).unwrap();

        proof.shard_proofs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core::utils::setup_logger;
    #[test]
    fn test_prove_sp1() {
        setup_logger();
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let stdin = [bincode::serialize::<u32>(&6).unwrap()];
        let proof = SP1ProverImpl::prove(elf, &stdin);
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");
        SP1ProverImpl::reduce(elf, proof);
    }
}
