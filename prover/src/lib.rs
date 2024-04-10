#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]

use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    runtime::Program,
    stark::{
        Dom, LocalProver, MachineStark, Proof, RiscvAir, ShardProof, StarkGenericConfig, Val,
        VerifyingKey,
    },
    utils::{run_and_prove, BabyBearPoseidon2},
};
use sp1_recursion_core::{
    runtime::{Program as RecursionProgram, Runtime},
    stark::RecursionAir,
};
use sp1_recursion_program::{hints::Hintable, reduce::build_reduce, stark::EMPTY};
use std::time::Instant;

type InnerSC = BabyBearPoseidon2;
type InnerF = <InnerSC as StarkGenericConfig>::Val;
type InnerEF = <InnerSC as StarkGenericConfig>::Challenge;
type InnerA = RiscvAir<InnerF>;

pub struct SP1ProverImpl {
    reduce_program: RecursionProgram<BabyBear>,
    reduce_vk: VerifyingKey<BabyBearPoseidon2>,
}

pub struct ReduceProof {
    proof: ShardProof<InnerSC>,
    is_recursive: bool,
}

impl Default for SP1ProverImpl {
    fn default() -> Self {
        Self::new()
    }
}

fn get_sorted_indices<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &MachineStark<SC, A>,
    proof: &ShardProof<SC>,
) -> Vec<usize> {
    machine
        .chips_sorted_indices(proof)
        .into_iter()
        .map(|x| match x {
            Some(x) => x,
            None => EMPTY,
        })
        .collect()
}

fn get_preprocessed_data<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &MachineStark<SC, A>,
    vk: &VerifyingKey<SC>,
) -> (Vec<usize>, Vec<Dom<SC>>) {
    let chips = machine.chips();
    let (prep_sorted_indices, prep_domains) = machine
        .preprocessed_chip_ids()
        .into_iter()
        .map(|chip_idx| {
            let name = chips[chip_idx].name().clone();
            let prep_sorted_idx = vk.chip_ordering[&name];
            (prep_sorted_idx, vk.chip_information[prep_sorted_idx].1)
        })
        .unzip();
    (prep_sorted_indices, prep_domains)
}

impl SP1ProverImpl {
    pub fn new() -> Self {
        // TODO: load from serde
        let reduce_program = build_reduce();
        let (_, reduce_vk) =
            RecursionAir::machine(BabyBearPoseidon2::default()).setup(&reduce_program);
        Self {
            reduce_program,
            reduce_vk,
        }
    }

    pub fn prove(elf: &[u8], stdin: &[Vec<u8>]) -> Proof<InnerSC> {
        let config = InnerSC::default();
        let machine = RiscvAir::machine(config.clone());
        let program = Program::from(elf);
        let (_, vk) = machine.setup(&program);
        let (proof, _) = run_and_prove(program, stdin, config);
        let mut challenger_ver = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger_ver).unwrap();
        proof
    }

    pub fn reduce(
        &self,
        sp1_vk: &VerifyingKey<BabyBearPoseidon2>,
        reduce_proofs: Vec<ReduceProof>,
    ) -> ShardProof<InnerSC> {
        let config = InnerSC::default();
        let sp1_machine = RiscvAir::machine(config.clone());
        let recursion_machine = RecursionAir::machine(config.clone());

        println!("nb_proofs {}", reduce_proofs.len());
        let config = InnerSC::default();

        let is_recursive_flags: Vec<usize> = reduce_proofs
            .iter()
            .map(|p| p.is_recursive as usize)
            .collect();
        let sorted_indices: Vec<Vec<usize>> = reduce_proofs
            .iter()
            .map(|p| {
                if p.is_recursive {
                    get_sorted_indices(&recursion_machine, &p.proof)
                } else {
                    get_sorted_indices(&sp1_machine, &p.proof)
                }
            })
            .collect();

        let mut sp1_challenger = sp1_machine.config().challenger();
        sp1_challenger.observe(sp1_vk.commit);
        let reconstruct_challenger = sp1_challenger.clone();
        for reduce_proof in reduce_proofs.iter() {
            let proof = &reduce_proof.proof;
            sp1_challenger.observe(proof.commitment.main_commit);
            let public_values = PublicValues::<Word<BabyBear>, BabyBear>::new(proof.public_values);
            sp1_challenger.observe_slice(&public_values.to_vec());
        }

        let mut recursion_challenger = recursion_machine.config().challenger();
        recursion_challenger.observe(self.reduce_vk.commit);

        let (prep_sorted_indices, prep_domains): (
            Vec<usize>,
            Vec<TwoAdicMultiplicativeCoset<BabyBear>>,
        ) = get_preprocessed_data(&sp1_machine, sp1_vk);

        let (recursion_prep_sorted_indices, recursion_prep_domains): (
            Vec<usize>,
            Vec<TwoAdicMultiplicativeCoset<BabyBear>>,
        ) = get_preprocessed_data(&recursion_machine, sp1_vk);

        let proofs: Vec<ShardProof<BabyBearPoseidon2>> =
            reduce_proofs.into_iter().map(|p| p.proof).collect();

        // Generate inputs.
        let mut witness_stream = Vec::new();
        witness_stream.extend(proofs.write());
        witness_stream.extend(is_recursive_flags.write());
        witness_stream.extend(sorted_indices.write());
        witness_stream.extend(sp1_challenger.write());
        witness_stream.extend(reconstruct_challenger.write());
        witness_stream.extend(recursion_challenger.write());
        witness_stream.extend(prep_sorted_indices.write());
        witness_stream.extend(prep_domains.write());
        witness_stream.extend(recursion_prep_sorted_indices.write());
        witness_stream.extend(recursion_prep_domains.write());
        witness_stream.extend(sp1_vk.write());
        witness_stream.extend(self.reduce_vk.write());
        println!("witness_stream.len() = {}", witness_stream.len());

        // Execute runtime.
        let machine = InnerA::machine(config);
        let mut runtime =
            Runtime::<InnerF, InnerEF, _>::new(&self.reduce_program, machine.config().perm.clone());
        runtime.witness_stream = witness_stream;
        runtime.run();
        runtime.print_stats();

        // Generate proof.
        let config = BabyBearPoseidon2::new();
        let machine = RecursionAir::machine(config);
        let (pk, _) = machine.setup(&self.reduce_program);
        // let mut challenger = machine.config().challenger();
        // let record_clone = runtime.record.clone();
        // machine.debug_constraints(&pk, record_clone, &mut challenger);
        let start = Instant::now();
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
        let duration = start.elapsed().as_secs();
        println!("proving duration = {}", duration);

        // let mut challenger = machine.config().challenger();
        // machine.verify(&vk, &proof, &mut challenger).unwrap();

        proof.shard_proofs.into_iter().next().unwrap()
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
            include_bytes!("../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");
        let stdin = [bincode::serialize::<u32>(&6).unwrap()];
        let proof = SP1ProverImpl::prove(elf, &stdin);

        let sp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
        let (_, vk) = sp1_machine.setup(&Program::from(elf));
        let reduce_proofs = proof
            .shard_proofs
            .into_iter()
            .map(|p| ReduceProof {
                proof: p,
                is_recursive: false,
            })
            .collect::<Vec<_>>();
        let prover = SP1ProverImpl::new();
        prover.reduce(&vk, reduce_proofs);
    }
}
