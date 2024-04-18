#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    runtime::Program,
    stark::{
        Challenger, Com, Dom, LocalProver, MachineStark, OpeningProof, PcsProverData, Proof,
        Prover, RiscvAir, ShardMainData, ShardProof, StarkGenericConfig, Val, VerifyingKey,
    },
    utils::{run_and_prove, BabyBearPoseidon2, BabyBearPoseidon2Inner},
};
use sp1_recursion_circuit::{stark::build_wrap_circuit, witness::Witnessable};
use sp1_recursion_compiler::{constraints::groth16_ffi, ir::Witness};
use sp1_recursion_core::{
    runtime::{RecursionProgram, Runtime},
    stark::{config::BabyBearPoseidon2Outer, RecursionAir},
};
use sp1_recursion_program::{hints::Hintable, reduce::build_reduce_program, stark::EMPTY};
use std::time::Instant;

type SP1SC = BabyBearPoseidon2;
type SP1F = <SP1SC as StarkGenericConfig>::Val;
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
pub enum ReduceProofType {
    SP1(ReduceProof<SP1SC>),
    Recursive(ReduceProof<InnerSC>),
    FinalRecursive(ReduceProof<OuterSC>),
}

impl From<ShardProof<SP1SC>> for ReduceProofType {
    fn from(proof: ShardProof<SP1SC>) -> Self {
        ReduceProofType::SP1(proof.into())
    }
}

// TODO: We should not need this, once reduce program public inputs are committed directly, we can
// read these values from the proof public values.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>"))]
pub struct ReduceProof<SC: StarkGenericConfig> {
    pub proof: ShardProof<SC>,
    pub start_pc: SC::Val,
    pub next_pc: SC::Val,
    pub start_shard: SC::Val,
    pub next_shard: SC::Val,
}

impl From<ShardProof<SP1SC>> for ReduceProof<SP1SC> {
    fn from(proof: ShardProof<SP1SC>) -> Self {
        let pv = PublicValues::<Word<BabyBear>, BabyBear>::from_vec(proof.public_values.clone());

        ReduceProof {
            proof,
            start_pc: pv.start_pc,
            next_pc: pv.next_pc,
            start_shard: pv.shard,
            next_shard: if pv.next_pc == BabyBear::zero() {
                BabyBear::zero()
            } else {
                pv.shard + BabyBear::one()
            },
        }
    }
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
        let (reduce_setup_program, reduce_program) = build_reduce_program();
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
        reduce_proofs: &[ReduceProofType],
        deferred_proofs: &[(ShardProof<InnerSC>, &VerifyingKey<SP1SC>)],
    ) -> ReduceProof<SC>
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
                ReduceProofType::SP1(_) => 0,
                ReduceProofType::Recursive(_) => 1,
                _ => panic!("can't reduce final proof"),
            })
            .collect();
        println!("is_recursive_flags = {:?}", is_recursive_flags);
        let sorted_indices: Vec<Vec<usize>> = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProofType::SP1(reduce_proof) => {
                    let indices = get_sorted_indices(&sp1_machine, &reduce_proof.proof);
                    println!("indices = {:?}", indices);
                    indices
                }
                ReduceProofType::Recursive(reduce_proof) => {
                    let indices = get_sorted_indices(&recursion_machine, &reduce_proof.proof);
                    println!("indices = {:?}", indices);
                    indices
                }
                _ => unreachable!(),
            })
            .collect();

        let start_pcs = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProofType::SP1(ref proof) => proof.start_pc,
                ReduceProofType::Recursive(ref proof) => proof.start_pc,
                _ => unreachable!(),
            })
            .collect_vec();

        let next_pcs = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProofType::SP1(ref proof) => proof.next_pc,
                ReduceProofType::Recursive(ref proof) => proof.next_pc,
                _ => unreachable!(),
            })
            .collect_vec();

        let start_shards = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProofType::SP1(ref proof) => proof.start_shard,
                ReduceProofType::Recursive(ref proof) => proof.start_shard,
                _ => unreachable!(),
            })
            .collect_vec();

        let next_shards = reduce_proofs
            .iter()
            .map(|p| match p {
                ReduceProofType::SP1(ref proof) => proof.next_shard,
                ReduceProofType::Recursive(ref proof) => proof.next_shard,
                _ => unreachable!(),
            })
            .collect_vec();

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

        let deferred_sorted_indices: Vec<Vec<usize>> = deferred_proofs
            .iter()
            .map(|(proof, _)| {
                let indices = get_sorted_indices(&recursion_machine, proof);
                println!("indices = {:?}", indices);
                indices
            })
            .collect();

        let deferred_proof_vec: Vec<_> = deferred_proofs.iter().map(|(proof, _)| proof).collect();

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
        witness_stream.extend(Hintable::write(&start_pcs));
        witness_stream.extend(Hintable::write(&next_pcs));
        witness_stream.extend(Hintable::write(&start_shards));
        witness_stream.extend(Hintable::write(&next_shards));
        for proof in reduce_proofs.iter() {
            match proof {
                ReduceProofType::SP1(reduce_proof) => {
                    witness_stream.extend(reduce_proof.proof.write());
                }
                ReduceProofType::Recursive(reduce_proof) => {
                    witness_stream.extend(reduce_proof.proof.write());
                }
                _ => unreachable!(),
            }
        }
        let empty_hash = [BabyBear::zero(); 8].to_vec();
        witness_stream.extend(Hintable::write(&empty_hash));
        witness_stream.extend(deferred_sorted_indices.write());
        witness_stream.extend(deferred_proof_vec.write());
        for (_, vk) in deferred_proofs.iter() {
            witness_stream.extend(vk.write());
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

        assert!(proof.shard_proofs.len() == 1);

        let proof = proof.shard_proofs.into_iter().next().unwrap();

        ReduceProof {
            proof,
            start_pc: start_pcs[0],
            next_pc: next_pcs[next_pcs.len() - 1],
            start_shard: start_shards[0],
            next_shard: next_shards[next_shards.len() - 1],
        }
    }

    /// Initialize a challenger given a verifying key and a list of shard proofs.
    pub fn initialize_challenger(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>,
        shard_proofs: &[ShardProof<SP1SC>],
    ) -> Challenger<SP1SC> {
        let sp1_config = SP1SC::default();
        let sp1_machine = RiscvAir::machine(sp1_config);
        let mut sp1_challenger = sp1_machine.config().challenger();
        sp1_vk.observe_into(&mut sp1_challenger);
        for shard_proof in shard_proofs.iter() {
            sp1_challenger.observe(shard_proof.commitment.main_commit);
            sp1_challenger
                .observe_slice(&shard_proof.public_values.to_vec()[0..sp1_machine.num_pv_elts()]);
        }
        sp1_challenger
    }

    /// Recursively reduce proofs into a single proof using an N-ary tree.
    pub fn reduce_tree<const N: usize>(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>,
        proof: Proof<SP1SC>,
        // deferred_proofs: &[(ReduceProof, &VerifyingKey<SP1SC>)],
    ) -> ReduceProof<InnerSC> {
        // Observe all commitments and public values. This challenger will be witnessed into
        // reduce program and used to verify sp1 proofs. It will also be reconstructed over all the
        // reduce steps to prove that the witnessed challenger was correct.
        let sp1_challenger = self.initialize_challenger(sp1_vk, &proof.shard_proofs);

        let mut reduce_proofs = proof
            .shard_proofs
            .into_iter()
            .map(|proof| {
                let pv = PublicValues::<Word<SP1F>, SP1F>::from_vec(proof.public_values.clone());

                ReduceProofType::SP1(ReduceProof {
                    proof,
                    start_pc: pv.start_pc,
                    next_pc: pv.next_pc,
                    start_shard: pv.shard,
                    next_shard: if pv.next_pc == SP1F::zero() {
                        SP1F::zero()
                    } else {
                        pv.shard + SP1F::one()
                    },
                })
            })
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
            ReduceProofType::Recursive(proof) => proof,
            ReduceProofType::SP1(_) => {
                // If there's only one shard, we still want to wrap it into an inner proof.
                self.reduce(sp1_vk, sp1_challenger, &[last_proof], &[])
            }
            _ => unreachable!(),
        }
    }

    /// Reduce a list of proofs in groups of N into a smaller list of proofs.
    pub fn reduce_layer<const N: usize>(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>,
        sp1_challenger: Challenger<SP1SC>,
        mut proofs: Vec<ReduceProofType>,
    ) -> Vec<ReduceProofType> {
        // If there's one proof at the end, just push it to the next layer.
        let last_proof = if proofs.len() % N == 1 {
            Some(proofs.pop().unwrap())
        } else {
            None
        };

        let chunks: Vec<_> = proofs.chunks(N).collect();

        // Process at most 4 proofs at once in parallel, due to memory limits.
        let partition_size = std::cmp::max(1, chunks.len() / 4);
        let mut new_proofs: Vec<ReduceProofType> = chunks
            .into_par_iter()
            .chunks(partition_size)
            .flat_map(|partition| {
                partition
                    .iter()
                    .map(|chunk| {
                        let start = Instant::now();
                        let proof = self.reduce(sp1_vk, sp1_challenger.clone(), chunk, &[]);
                        let duration = start.elapsed().as_secs();
                        println!("reduce duration = {}", duration);
                        ReduceProofType::Recursive(proof)
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        if let Some(proof) = last_proof {
            new_proofs.push(proof);
        }
        new_proofs
    }

    /// Wrap a recursive proof into an outer recursive proof that can be verified in groth16.
    pub fn wrap_into_outer(
        &self,
        sp1_vk: &VerifyingKey<SP1SC>, // TODO: we could read these from proof public values
        sp1_challenger: Challenger<SP1SC>,
        reduce_proof: ReduceProof<InnerSC>,
    ) -> ShardProof<OuterSC> {
        self.reduce(
            sp1_vk,
            sp1_challenger,
            &[ReduceProofType::Recursive(reduce_proof)],
            &[],
        )
        .proof
    }

    /// Wrap an outer recursive proof into a groth16 proof.
    pub fn wrap_into_groth16(&self, proof: ShardProof<OuterSC>) {
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
    use sp1_core::{
        runtime::Runtime,
        utils::{prove_core, setup_logger},
    };
    use sp1_recursion_circuit::{stark::build_wrap_circuit, witness::Witnessable};
    use sp1_recursion_compiler::{constraints::groth16_ffi, ir::Witness};
    use sp1_recursion_core::stark::config::BabyBearPoseidon2Outer;
    use sp1_sdk::{ProverClient, SP1Stdin};

    #[test]
    #[ignore]
    fn test_prove_sp1() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

        // Generate SP1 proof
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

        type SC = BabyBearPoseidon2;
        type F = <SC as StarkGenericConfig>::Val;
        type A = RiscvAir<F>;

        let machine = A::machine(SC::default());
        let (_, vk) = machine.setup(&Program::from(elf));
        let mut challenger = machine.config().challenger();
        let client = ProverClient::new();
        let proof = client
            .prove_local(elf, SP1Stdin::new(), machine.config().clone())
            .unwrap()
            .proof;
        machine.verify(&vk, &proof, &mut challenger).unwrap();
        let prover = SP1ProverImpl::new();
        let sp1_challenger = prover.initialize_challenger(&vk, &proof.shard_proofs);

        let sp1_machine = RiscvAir::machine(SP1SC::default());
        let (_, vk) = sp1_machine.setup(&Program::from(elf));

        let start = Instant::now();
        let final_proof = prover.reduce_tree::<2>(&vk, proof);
        let duration = start.elapsed().as_secs();
        println!("full reduce duration = {}", duration);

        // Save final proof to file
        let serialized = bincode::serialize(&final_proof).unwrap();
        std::fs::write("final.bin", serialized).unwrap();

        // Wrap into outer proof
        let outer_proof = prover.wrap_into_outer(&vk, sp1_challenger, final_proof);

        // Wrap the final proof into a groth16 proof
        prover.wrap_into_groth16(outer_proof);
    }

    #[ignore]
    #[test]
    fn test_gnark_final() {
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");
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

    #[ignore]
    #[test]
    fn test_verify_proof_program() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

        let sp1_machine = RiscvAir::machine(SP1SC::default());
        let fibonacci_io_elf =
            include_bytes!("../../examples/fibonacci-io/program/elf/riscv32im-succinct-zkvm-elf");
        let fibonacci_program = Program::from(fibonacci_io_elf);
        let config = BabyBearPoseidon2::new();
        let (_, fibonacci_vk) = sp1_machine.setup(&fibonacci_program);

        let prover = SP1ProverImpl::new();
        let proof_to_verify = match std::fs::read("inner_proof.bin") {
            Ok(proof) => bincode::deserialize::<Proof<InnerSC>>(&proof).unwrap(),
            Err(_) => {
                let (fibonacci_proof, _) = run_and_prove(
                    fibonacci_program.clone(),
                    &[bincode::serialize::<u32>(&4).unwrap()],
                    config,
                );
                println!("shards: {:?}", fibonacci_proof.shard_proofs.len());

                let mut challenger = sp1_machine.config().challenger();
                sp1_machine
                    .verify(&fibonacci_vk, &fibonacci_proof, &mut challenger)
                    .unwrap();
                println!("verified fibonacci");

                let final_proof = prover.reduce_tree::<2>(&fibonacci_vk, fibonacci_proof);

                let proof = Proof {
                    shard_proofs: vec![final_proof.proof],
                };
                let serialized = bincode::serialize(&proof).unwrap();
                std::fs::write("inner_proof.bin", serialized).unwrap();
                proof
            }
        };

        let verify_proof_elf =
            include_bytes!("../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");
        let verify_program = Program::from(verify_proof_elf);
        let mut runtime = Runtime::new(verify_program.clone());
        let (_, verify_vk) = sp1_machine.setup(&verify_program);

        let mut pv_digest_raw: [u32; 8] = [0; 8];
        for (i, val) in proof_to_verify.shard_proofs[0].public_values[..8]
            .iter()
            .enumerate()
        {
            pv_digest_raw[i] = val.as_canonical_u32();
        }
        let mut vk_raw: [u32; 8] = [0; 8];
        for (i, val) in prover.reduce_vk_inner.commit.as_ref().iter().enumerate() {
            vk_raw[i] = val.as_canonical_u32();
        }
        runtime.write_proof(proof_to_verify.clone(), prover.reduce_vk_inner.clone());
        runtime.write_stdin(&vk_raw);
        runtime.write_stdin(&pv_digest_raw);
        // runtime.write_stdin(input)
        runtime.run();
        println!("public values: {:?}", runtime.record.public_values);

        let config = BabyBearPoseidon2::new();
        let proof = prove_core(config, runtime);
        println!("shards {:?}", proof.shard_proofs.len());

        let mut challenger = sp1_machine.config().challenger();
        sp1_machine
            .verify(&verify_vk, &proof, &mut challenger)
            .unwrap();
        println!("verified");

        let mut challenger = sp1_machine.config().challenger();
        verify_vk.observe_into(&mut challenger);
        for shard_proof in proof.shard_proofs.iter() {
            challenger.observe(shard_proof.commitment.main_commit);
            challenger.observe_slice(&shard_proof.public_values.to_vec());
        }
        let reduce_proofs = vec![proof.shard_proofs[0].clone().into()];
        let reduce_proof_to_verify = proof_to_verify.shard_proofs[0].clone();

        prover.reduce::<InnerSC>(
            &verify_vk,
            challenger,
            &reduce_proofs,
            &[(reduce_proof_to_verify, &fibonacci_vk)],
        );
    }
}
