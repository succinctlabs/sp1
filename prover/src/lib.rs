#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]

use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use serde::{Deserialize, Serialize};
use sp1_core::{
    air::MachineAir,
    runtime::Program,
    stark::{
        Challenger, Dom, LocalProver, MachineStark, Proof, RiscvAir, ShardProof,
        StarkGenericConfig, Val, VerifyingKey,
    },
    utils::{run_and_prove, BabyBearPoseidon2},
};
use sp1_recursion_core::{
    runtime::{RecursionProgram, Runtime},
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

#[derive(Serialize, Deserialize)]
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
        let start = Instant::now();
        let (proof, _) = run_and_prove(program, stdin, config);
        let duration = start.elapsed().as_secs_f64();
        println!("leaf proving time = {:?}", duration);
        let mut challenger_ver = machine.config().challenger();
        machine.verify(&vk, &proof, &mut challenger_ver).unwrap();
        proof
    }

    pub fn reduce(
        &self,
        sp1_vk: &VerifyingKey<BabyBearPoseidon2>,
        sp1_challenger: Challenger<BabyBearPoseidon2>,
        reduce_proofs: &[ReduceProof],
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
        println!("is_recursive_flags = {:?}", is_recursive_flags);
        let sorted_indices: Vec<Vec<usize>> = reduce_proofs
            .iter()
            .map(|p| {
                if p.is_recursive {
                    let indices = get_sorted_indices(&recursion_machine, &p.proof);
                    println!("indices = {:?}", indices);
                    indices
                } else {
                    get_sorted_indices(&sp1_machine, &p.proof)
                }
            })
            .collect();

        let mut reconstruct_challenger = sp1_machine.config().challenger();
        reconstruct_challenger.observe(sp1_vk.commit);

        let (prep_sorted_indices, prep_domains): (
            Vec<usize>,
            Vec<TwoAdicMultiplicativeCoset<BabyBear>>,
        ) = get_preprocessed_data(&sp1_machine, sp1_vk);

        let (recursion_prep_sorted_indices, recursion_prep_domains): (
            Vec<usize>,
            Vec<TwoAdicMultiplicativeCoset<BabyBear>>,
        ) = get_preprocessed_data(&recursion_machine, &self.reduce_vk);

        let proofs: Vec<&ShardProof<BabyBearPoseidon2>> =
            reduce_proofs.iter().map(|p| &p.proof).collect();

        // Generate inputs.
        let mut witness_stream = Vec::new();
        witness_stream.extend(proofs.write());
        witness_stream.extend(is_recursive_flags.write());
        witness_stream.extend(sorted_indices.write());
        witness_stream.extend(sp1_challenger.write());
        witness_stream.extend(reconstruct_challenger.write());
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
        println!("recursion duration = {}", duration);

        // let mut challenger = machine.config().challenger();
        // machine.verify(&vk, &proof, &mut challenger).unwrap();

        proof.shard_proofs.into_iter().next().unwrap()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use sp1_core::utils::setup_logger;

    #[ignore]
    #[test]
    fn test_prove_sp1() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");
        let prover = SP1ProverImpl::new();

        // let proofs: Vec<ReduceProof> =
        //     bincode::deserialize(&std::fs::read("1.bin").expect("Failed to read file")).unwrap();
        // println!("nb_proofs {}", proofs.len());
        // let recursion_machine = RecursionAir::machine(BabyBearPoseidon2::default());
        // let mut challenger = recursion_machine.config().challenger();
        // let proof = Proof::<BabyBearPoseidon2> {
        //     shard_proofs: vec![proofs.into_iter().next().unwrap().proof],
        // };
        // recursion_machine
        //     .verify(&prover.reduce_vk, &proof, &mut challenger)
        //     .unwrap();

        // exit(0);

        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let stdin = [bincode::serialize::<u32>(&6).unwrap()];
        let proof = SP1ProverImpl::prove(elf, &stdin);

        let sp1_machine = RiscvAir::machine(BabyBearPoseidon2::default());
        let (_, vk) = sp1_machine.setup(&Program::from(elf));

        let mut sp1_challenger = sp1_machine.config().challenger();
        sp1_challenger.observe(vk.commit);
        for shard_proof in proof.shard_proofs.iter() {
            sp1_challenger.observe(shard_proof.commitment.main_commit);
            sp1_challenger.observe_slice(&shard_proof.public_values.to_vec());
        }

        let mut reduce_proofs = proof
            .shard_proofs
            .into_iter()
            .map(|p| ReduceProof {
                proof: p,
                is_recursive: false,
            })
            .collect::<Vec<_>>();
        let n = 2;
        let mut layer = 0;

        // let sp1_challenger = sp1_machine.config().challenger();
        // let mut reduce_proofs: Vec<ReduceProof> =
        //     bincode::deserialize(&std::fs::read("1.bin").expect("Failed to read file")).unwrap();
        // layer = 1;

        let start = Instant::now();
        while reduce_proofs.len() > 1 {
            // Write layer to {i}.bin with bincode
            let serialized = bincode::serialize(&reduce_proofs).unwrap();
            std::fs::write(format!("{}.bin", layer), serialized).unwrap();
            let mut next_proofs = Vec::new();
            for i in (0..reduce_proofs.len()).step_by(n) {
                let end = std::cmp::min(i + n, reduce_proofs.len());
                if i == end - 1 {
                    next_proofs.push(reduce_proofs.pop().unwrap());
                    continue;
                }
                let proofs = &reduce_proofs[i..end];
                let proof = prover.reduce(&vk, sp1_challenger.clone(), proofs);
                let recursion_machine = RecursionAir::machine(BabyBearPoseidon2::default());
                let mut challenger = recursion_machine.config().challenger();
                let full_proof = Proof::<BabyBearPoseidon2> {
                    shard_proofs: vec![proof],
                };
                let res = recursion_machine.verify(&prover.reduce_vk, &full_proof, &mut challenger);
                if res.is_err() {
                    println!("Failed to verify proof");
                    println!("err = {:?}", res.err());
                }
                next_proofs.push(ReduceProof {
                    proof: full_proof.shard_proofs.into_iter().next().unwrap(),
                    is_recursive: true,
                });
            }
            reduce_proofs = next_proofs;
            layer += 1;
        }
        let duration = start.elapsed().as_secs();
        println!("duration = {}", duration);
    }
}
