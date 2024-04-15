#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]

use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core::{
    air::MachineAir,
    runtime::Program,
    stark::{
        Challenger, Com, Dom, LocalProver, MachineStark, OpeningProof, PcsProverData, Proof,
        Prover, RiscvAir, ShardMainData, ShardProof, StarkGenericConfig, Val, VerifyingKey,
    },
    utils::{run_and_prove, BabyBearPoseidon2},
};
use sp1_recursion_circuit::{stark::build_wrap_circuit, witness::Witnessable};
use sp1_recursion_compiler::{constraints::groth16_ffi, ir::Witness};
use sp1_recursion_core::{
    cpu::Instruction,
    runtime::{RecursionProgram, Runtime},
    stark::{
        config::{BabyBearPoseidon2Inner, BabyBearPoseidon2Outer},
        RecursionAir,
    },
};
use sp1_recursion_program::{hints::Hintable, reduce::build_reduce_program, stark::EMPTY};
use std::time::Instant;

type SP1SC = BabyBearPoseidon2;
type InnerSC = BabyBearPoseidon2Inner;
type InnerF = <InnerSC as StarkGenericConfig>::Val;
type InnerEF = <InnerSC as StarkGenericConfig>::Challenge;
type OuterSC = BabyBearPoseidon2Outer;

pub struct SP1ProverImpl {
    pub reduce_program: RecursionProgram<BabyBear>,
    pub reduce_setup_program: RecursionProgram<BabyBear>,
    pub reduce_vk_inner: VerifyingKey<InnerSC>,
    pub reduce_vk_outer: VerifyingKey<OuterSC>,
}

#[derive(Serialize, Deserialize)]
pub enum ReduceProof {
    SP1(ShardProof<SP1SC>),
    Recursive(ShardProof<InnerSC>),
    FinalRecursive(ShardProof<OuterSC>),
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
        let reduce_setup_program = build_reduce_program(true);
        let mut reduce_program = build_reduce_program(false);
        reduce_program.instructions[0] = Instruction::new(
            sp1_recursion_core::runtime::Opcode::ADD,
            BabyBear::zero(),
            [BabyBear::zero(); 4],
            [BabyBear::zero(); 4],
            BabyBear::zero(),
            BabyBear::zero(),
            false,
            false,
        );
        let (_, reduce_vk_inner) = RecursionAir::machine(InnerSC::default()).setup(&reduce_program);
        let (_, reduce_vk_outer) = RecursionAir::machine(OuterSC::default()).setup(&reduce_program);
        Self {
            reduce_setup_program,
            reduce_program,
            reduce_vk_inner,
            reduce_vk_outer,
        }
    }

    /// Generate an SP1 core proof of a program and its inputs.
    pub fn prove<SC: StarkGenericConfig<Val = BabyBear> + Default>(
        elf: &[u8],
        stdin: &[Vec<u8>],
    ) -> Proof<SC>
    where
        <SC as StarkGenericConfig>::Challenger: Clone,
        OpeningProof<SC>: Send + Sync,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        <SC as StarkGenericConfig>::Val: PrimeField32,
    {
        let config = SC::default();
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

    /// Generate a reduce proof that reduces a Vec of proofs into 1 proof.
    pub fn reduce<SC: StarkGenericConfig<Val = BabyBear> + Default>(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>,
        sp1_challenger: Challenger<SP1SC>,
        reduce_proofs: &[ReduceProof],
    ) -> ShardProof<SC>
    where
        SC::Challenger: Clone,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        LocalProver<SC, RecursionAir<BabyBear>>: Prover<SC, RecursionAir<BabyBear>>,
    {
        let sp1_config = SP1SC::default();
        let sp1_machine = RiscvAir::machine(sp1_config);
        let recursion_config = InnerSC::default();
        let recursion_machine = RecursionAir::machine(recursion_config.clone());

        println!("nb_proofs {}", reduce_proofs.len());

        let is_recursive_flags: Vec<usize> = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProof::SP1(_) => 0,
                ReduceProof::Recursive(_) => 1,
                _ => panic!("can't reduce final proof"),
            })
            .collect();
        println!("is_recursive_flags = {:?}", is_recursive_flags);
        let sorted_indices: Vec<Vec<usize>> = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProof::SP1(proof) => {
                    let indices = get_sorted_indices(&sp1_machine, proof);
                    println!("indices = {:?}", indices);
                    indices
                }
                ReduceProof::Recursive(proof) => {
                    let indices = get_sorted_indices(&recursion_machine, proof);
                    println!("indices = {:?}", indices);
                    indices
                }
                _ => unreachable!(),
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
        ) = get_preprocessed_data(&recursion_machine, &self.reduce_vk_inner);

        // Generate inputs.
        let mut witness_stream = Vec::new();
        witness_stream.extend(is_recursive_flags.write());
        witness_stream.extend(sorted_indices.write());
        witness_stream.extend(sp1_challenger.write());
        witness_stream.extend(reconstruct_challenger.write());
        witness_stream.extend(prep_sorted_indices.write());
        witness_stream.extend(prep_domains.write());
        witness_stream.extend(recursion_prep_sorted_indices.write());
        witness_stream.extend(recursion_prep_domains.write());
        witness_stream.extend(sp1_vk.write());
        witness_stream.extend(self.reduce_vk_inner.write());
        for proof in reduce_proofs.iter() {
            match proof {
                ReduceProof::SP1(proof) => {
                    witness_stream.extend(proof.write());
                }
                ReduceProof::Recursive(proof) => {
                    witness_stream.extend(proof.write());
                }
                _ => unreachable!(),
            }
        }
        println!("witness_stream.len() = {}", witness_stream.len());

        // Execute runtime to get the memory setup.
        println!("setting up memory for recursion");
        let machine = RecursionAir::machine(recursion_config.clone());
        let mut runtime = Runtime::<InnerF, InnerEF, _>::new(
            &self.reduce_setup_program,
            machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream;
        runtime.run();
        let mut checkpoint = runtime.memory.clone();
        runtime.print_stats();

        // Execute runtime.
        println!("executing recursion");
        let machine = RecursionAir::machine(recursion_config);
        let mut runtime =
            Runtime::<InnerF, InnerEF, _>::new(&self.reduce_program, machine.config().perm.clone());
        checkpoint.iter_mut().for_each(|e| {
            e.timestamp = BabyBear::zero();
        });
        runtime.memory = checkpoint;
        runtime.run();
        runtime.print_stats();

        // Generate proof.
        let config = SC::default();
        let machine = RecursionAir::machine(config);
        let (pk, _) = machine.setup(&self.reduce_program);

        let start = Instant::now();
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);
        let duration = start.elapsed().as_secs();
        println!("recursion duration = {}", duration);

        proof.shard_proofs.into_iter().next().unwrap()
    }

    /// Recursively reduce proofs into a single proof using an N-ary tree.
    pub fn reduce_tree<const N: usize>(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>,
        sp1_challenger: Challenger<SP1SC>,
        proof: Proof<SP1SC>,
    ) -> ShardProof<OuterSC> {
        let mut reduce_proofs = proof
            .shard_proofs
            .into_iter()
            .map(ReduceProof::SP1)
            .collect::<Vec<_>>();
        let mut layer = 0;
        while reduce_proofs.len() > 1 {
            println!("layer = {}, num_proofs = {}", layer, reduce_proofs.len());
            let start = Instant::now();
            reduce_proofs = self.reduce_layer::<N>(sp1_vk, sp1_challenger.clone(), reduce_proofs);
            let duration = start.elapsed().as_secs();
            println!("layer {}, reduce duration = {}", layer, duration);
            layer += 1;
        }
        let last_proof = reduce_proofs.into_iter().next().unwrap();
        match last_proof {
            ReduceProof::FinalRecursive(proof) => proof,
            _ => unreachable!(),
        }
    }

    /// Reduce a list of proofs in groups of N into a smaller list of proofs.
    pub fn reduce_layer<const N: usize>(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>,
        sp1_challenger: Challenger<SP1SC>,
        mut proofs: Vec<ReduceProof>,
    ) -> Vec<ReduceProof> {
        if proofs.len() <= N {
            // With the last proof, we need to use outer config since the proof will be
            // verified in groth16 circuit.
            let start = Instant::now();
            let proof: ShardProof<OuterSC> = self.reduce(sp1_vk, sp1_challenger.clone(), &proofs);
            let duration = start.elapsed().as_secs();
            println!("final reduce duration = {}", duration);
            return vec![ReduceProof::FinalRecursive(proof)];
        }

        // If there's one proof at the end, just push it to the next layer.
        let last_proof = if proofs.len() % N == 1 {
            Some(proofs.pop().unwrap())
        } else {
            None
        };

        let chunks: Vec<_> = proofs.chunks(N).collect();

        // Process at most 4 proofs at once in parallel, due to memory limits.
        let partition_size = std::cmp::max(1, chunks.len() / 4);
        let mut new_proofs: Vec<ReduceProof> = chunks
            .into_par_iter()
            .chunks(partition_size)
            .flat_map(|partition| {
                partition
                    .iter()
                    .map(|chunk| {
                        let start = Instant::now();
                        let proof = self.reduce(sp1_vk, sp1_challenger.clone(), chunk);
                        let duration = start.elapsed().as_secs();
                        println!("reduce duration = {}", duration);
                        ReduceProof::Recursive(proof)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        if let Some(proof) = last_proof {
            new_proofs.push(proof);
        }
        new_proofs
    }

    /// Wrap an outer recursive proof into a groth16 proof.
    pub fn wrap(&self, proof: ShardProof<OuterSC>) {
        let mut witness = Witness::default();
        proof.write(&mut witness);
        let constraints = build_wrap_circuit(&self.reduce_vk_outer, proof);
        let start = Instant::now();
        groth16_ffi::prove(constraints, witness);
        let duration = start.elapsed().as_secs();
        println!("wrap duration = {}", duration);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use sp1_core::utils::setup_logger;
    use sp1_recursion_circuit::{stark::build_wrap_circuit, witness::Witnessable};
    use sp1_recursion_compiler::{constraints::groth16_ffi, ir::Witness};
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;

    #[test]
    fn test_prove_sp1() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");
        let prover = SP1ProverImpl::new();

        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");
        let proof = match std::fs::read("sp1_proof.bin") {
            Ok(proof) => bincode::deserialize::<Proof<SP1SC>>(&proof).unwrap(),
            Err(_) => {
                let stdin = [bincode::serialize::<u32>(&6).unwrap()];
                let proof = SP1ProverImpl::prove(elf, &stdin);

                // save proof
                let serialized = bincode::serialize(&proof).unwrap();
                std::fs::write("sp1_proof.bin", serialized).unwrap();

                proof
            }
        };

        let sp1_machine = RiscvAir::machine(SP1SC::default());
        let (_, vk) = sp1_machine.setup(&Program::from(elf));

        // Observe all commitments and public values. This challenger will be witnessed into
        // reduce program and used to verify sp1 proofs. It will also be reconstructed over all the
        // reduce steps to prove that the witnessed challenger was correct.
        let mut sp1_challenger = sp1_machine.config().challenger();
        sp1_challenger.observe(vk.commit);
        for shard_proof in proof.shard_proofs.iter() {
            sp1_challenger.observe(shard_proof.commitment.main_commit);
            sp1_challenger.observe_slice(&shard_proof.public_values.to_vec());
        }

        let start = Instant::now();
        let final_proof = prover.reduce_tree::<2>(&vk, sp1_challenger, proof);
        let duration = start.elapsed().as_secs();
        println!("full reduce duration = {}", duration);

        // Save final proof to file
        let serialized = bincode::serialize(&final_proof).unwrap();
        std::fs::write("final.bin", serialized).unwrap();

        // Wrap the final proof into a groth16 proof
        prover.wrap(final_proof);
    }

    #[ignore]
    #[test]
    fn test_gnark_final() {
        let reduce_proof = bincode::deserialize::<ShardProof<BabyBearPoseidon2Outer>>(
            &std::fs::read("final.bin").expect("Failed to read file"),
        )
        .unwrap();
        let prover = SP1ProverImpl::new();
        let constraints = build_wrap_circuit(&prover.reduce_vk_outer, reduce_proof);

        let reduce_proof = bincode::deserialize::<ShardProof<BabyBearPoseidon2Outer>>(
            &std::fs::read("final.bin").expect("Failed to read file"),
        )
        .unwrap();

        let mut witness = Witness::default();
        reduce_proof.write(&mut witness);

        groth16_ffi::prove(constraints, witness);
    }
}
