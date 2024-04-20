//! An end-to-end-prover implementation for SP1.
//!
//! Seperates the proof generation process into multiple stages:
//!
//! 1. Generate shard proofs which split up and prove the valid execution of a RISC-V program.
//! 2. Reduce shard proofs into a single shard proof.
//! 3. Wrap the shard proof into a SNARK-friendly field.
//! 4. Wrap the last shard proof, proven over the SNARK-friendly field, into a Groth16/PLONK proof.

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![allow(deprecated)]
#![allow(clippy::new_without_default)]

mod verify;

use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sp1_core::stark::{Challenge, Com, Domain, PcsProverData, Prover, ShardMainData};
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    runtime::Program,
    stark::{
        Challenger, Dom, LocalProver, RiscvAir, ShardProof, StarkGenericConfig, StarkMachine,
        StarkProvingKey, StarkVerifyingKey, Val,
    },
    utils::{run_and_prove, BabyBearPoseidon2},
    SP1PublicValues,
};
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::constraints::groth16_ffi;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_core::runtime::RecursionProgram;
use sp1_recursion_core::{
    runtime::Runtime,
    stark::{config::BabyBearPoseidon2Outer, RecursionAir},
};
use sp1_recursion_program::reduce::ReduceProgram;
use sp1_recursion_program::{hints::Hintable, stark::EMPTY};
use sp1_sdk::SP1Stdin;

/// The configuration for the core prover.
type CoreSC = BabyBearPoseidon2;

/// The configuration for the recursive prover.
type InnerSC = BabyBearPoseidon2;

/// The configuration for the outer prover.
type OuterSC = BabyBearPoseidon2Outer;

/// A end-to-end prover implementation for SP1.
pub struct SP1Prover {
    pub reduce_program: RecursionProgram<BabyBear>,
    pub reduce_setup_program: RecursionProgram<BabyBear>,
    pub reduce_vk_inner: StarkVerifyingKey<InnerSC>,
    pub reduce_vk_outer: StarkVerifyingKey<OuterSC>,
}

/// The information necessary to generate a proof for a given RISC-V program.
pub struct SP1ProvingKey {
    pub pk: StarkProvingKey<CoreSC>,
    pub program: Program,
}

/// The information necessary to verify a proof for a given RISC-V program.
pub struct SP1VerifyingKey {
    pub vk: StarkVerifyingKey<CoreSC>,
}

/// A proof of a RISC-V execution with given inputs and outputs composed of multiple shard proofs.
#[derive(Serialize, Deserialize)]
pub struct SP1CoreProof {
    pub shard_proofs: Vec<ShardProof<CoreSC>>,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
}

/// An intermediate proof which proves the execution over a range of shards.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "ShardProof<SC>: Serialize"))]
#[serde(bound(deserialize = "ShardProof<SC>: Deserialize<'de>"))]
pub struct SP1ReduceProof<SC: StarkGenericConfig> {
    pub proof: ShardProof<SC>,
    pub start_pc: SC::Val,
    pub next_pc: SC::Val,
    pub start_shard: SC::Val,
    pub next_shard: SC::Val,
}

/// A wrapper to abstract proofs representing a range of shards with multiple proving configs.
#[derive(Serialize, Deserialize)]
pub enum SP1ReduceProofWrapper {
    Core(SP1ReduceProof<CoreSC>),
    Recursive(SP1ReduceProof<InnerSC>),
}

impl SP1Prover {
    /// Initializes a new [SP1Prover].
    pub fn new() -> Self {
        let reduce_setup_program = ReduceProgram::setup();
        let reduce_program = ReduceProgram::build();
        let (_, reduce_vk_inner) = RecursionAir::machine(InnerSC::default()).setup(&reduce_program);
        let (_, reduce_vk_outer) = RecursionAir::machine(OuterSC::default()).setup(&reduce_program);
        Self {
            reduce_setup_program,
            reduce_program,
            reduce_vk_inner,
            reduce_vk_outer,
        }
    }

    /// Creates a proving key and a verifying key for a given RISC-V ELF.
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let program = Program::from(elf);
        let config = CoreSC::default();
        let machine = RiscvAir::machine(config);
        let (pk, vk) = machine.setup(&program);
        let pk = SP1ProvingKey { pk, program };
        let vk = SP1VerifyingKey { vk };
        (pk, vk)
    }

    /// Generate shard proofs which split up and prove the valid execution of a RISC-V program with
    /// the core prover.
    pub fn prove_core(&self, pk: &SP1ProvingKey, stdin: &SP1Stdin) -> SP1CoreProof {
        let config = CoreSC::default();
        let (proof, public_values_stream) =
            run_and_prove(pk.program.clone(), &stdin.buffer, config);
        let public_values = SP1PublicValues::from(&public_values_stream);
        SP1CoreProof {
            shard_proofs: proof.shard_proofs,
            stdin: stdin.clone(),
            public_values,
        }
    }

    /// Reduce shards proofs to a single shard proof using the recursion prover.
    pub fn reduce(&self, vk: &SP1VerifyingKey, proof: SP1CoreProof) -> SP1ReduceProof<InnerSC> {
        // Observe all commitments and public values.
        //
        // This challenger will be witnessed into reduce program and used to verify sp1 proofs. It
        // will also be reconstructed over all the reduce steps to prove that the witnessed
        // challenger was correct.
        let core_machine = RiscvAir::machine(CoreSC::default());
        let mut core_challenger = core_machine.config().challenger();
        vk.vk.observe_into(&mut core_challenger);
        for shard_proof in proof.shard_proofs.iter() {
            core_challenger.observe(shard_proof.commitment.main_commit);
            core_challenger
                .observe_slice(&shard_proof.public_values.to_vec()[0..core_machine.num_pv_elts()]);
        }

        // Map the existing shards to a self-reducing type of proof (i.e. Reduce: T[] -> T).
        let mut reduce_proofs = proof
            .shard_proofs
            .into_iter()
            .map(|proof| {
                let public_values = PublicValues::<Word<Val<CoreSC>>, Val<CoreSC>>::from_vec(
                    proof.public_values.clone(),
                );
                SP1ReduceProofWrapper::Core(SP1ReduceProof {
                    proof,
                    start_pc: public_values.start_pc,
                    next_pc: public_values.next_pc,
                    start_shard: public_values.shard,
                    next_shard: if public_values.next_pc == Val::<CoreSC>::zero() {
                        Val::<CoreSC>::zero()
                    } else {
                        public_values.shard + Val::<CoreSC>::one()
                    },
                })
            })
            .collect::<Vec<_>>();

        // Keep reducing until we have only one shard. If we have only one shard, we still want to
        // wrap it into a reduce shard.
        while reduce_proofs.len() > 1 {
            reduce_proofs = self.reduce_layer(vk, core_challenger.clone(), reduce_proofs, 2);
        }

        // Return the remaining single reduce proof.
        assert_eq!(reduce_proofs.len(), 1);
        let last_proof = reduce_proofs.into_iter().next().unwrap();
        match last_proof {
            SP1ReduceProofWrapper::Recursive(proof) => proof,
            SP1ReduceProofWrapper::Core(_) => {
                self.reduce_batch(vk, core_challenger, &[last_proof], &[])
            }
        }
    }

    /// Reduce a set of shard proofs in groups of `batch_size` into a smaller set of shard proofs
    /// using the recursion prover.
    fn reduce_layer(
        &self,
        vk: &SP1VerifyingKey,
        sp1_challenger: Challenger<CoreSC>,
        mut proofs: Vec<SP1ReduceProofWrapper>,
        batch_size: usize,
    ) -> Vec<SP1ReduceProofWrapper> {
        // If there's one proof at the end, push it to the next layer.
        let last_proof = if proofs.len() % batch_size == 1 {
            Some(proofs.pop().unwrap())
        } else {
            None
        };

        // Process at most 4 proofs at once in parallel, due to memory limits.
        let chunks: Vec<_> = proofs.chunks(batch_size).collect();
        let mut new_proofs: Vec<SP1ReduceProofWrapper> = chunks
            .into_par_iter()
            .map(|chunk| {
                let proof = self.reduce_batch(vk, sp1_challenger.clone(), chunk, &[]);
                SP1ReduceProofWrapper::Recursive(proof)
            })
            .collect();

        if let Some(proof) = last_proof {
            new_proofs.push(proof);
        }
        new_proofs
    }

    /// Reduces a batch of shard proofs into a single shard proof using the recursion prover.
    fn reduce_batch<SC>(
        &self,
        vk: &SP1VerifyingKey,
        core_challenger: Challenger<CoreSC>,
        reduce_proofs: &[SP1ReduceProofWrapper],
        deferred_proofs: &[(ShardProof<InnerSC>, &StarkVerifyingKey<CoreSC>)],
    ) -> SP1ReduceProof<SC>
    where
        SC: StarkGenericConfig<Val = BabyBear> + Default,
        SC::Challenger: Clone,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        LocalProver<SC, RecursionAir<BabyBear>>: Prover<SC, RecursionAir<BabyBear>>,
    {
        // Setup the machines.
        let core_machine = RiscvAir::machine(CoreSC::default());
        let recursion_machine = RecursionAir::machine(InnerSC::default());

        // Compute inputs.
        let is_recursive_flags: Vec<usize> = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(_) => 0,
                SP1ReduceProofWrapper::Recursive(_) => 1,
            })
            .collect();
        let sorted_indices: Vec<Vec<usize>> = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(reduce_proof) => {
                    get_sorted_indices(&core_machine, &reduce_proof.proof)
                }
                SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                    get_sorted_indices(&recursion_machine, &reduce_proof.proof)
                }
            })
            .collect();
        let start_pcs = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(ref proof) => proof.start_pc,
                SP1ReduceProofWrapper::Recursive(ref proof) => proof.start_pc,
            })
            .collect_vec();
        let next_pcs = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(ref proof) => proof.next_pc,
                SP1ReduceProofWrapper::Recursive(ref proof) => proof.next_pc,
            })
            .collect_vec();
        let start_shards = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(ref proof) => proof.start_shard,
                SP1ReduceProofWrapper::Recursive(ref proof) => proof.start_shard,
            })
            .collect_vec();
        let next_shards = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(ref proof) => proof.next_shard,
                SP1ReduceProofWrapper::Recursive(ref proof) => proof.next_shard,
            })
            .collect_vec();
        let (prep_sorted_indices, prep_domains): (Vec<usize>, Vec<Domain<CoreSC>>) =
            get_preprocessed_data(&core_machine, &vk.vk);
        let (recursion_prep_sorted_indices, recursion_prep_domains): (
            Vec<usize>,
            Vec<Domain<InnerSC>>,
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
        let mut reconstruct_challenger = core_machine.config().challenger();
        reconstruct_challenger.observe(vk.vk.commit);

        // Convert the inputs into a witness stream.
        let mut witness_stream = Vec::new();
        witness_stream.extend(is_recursive_flags.write());
        witness_stream.extend(sorted_indices.write());
        witness_stream.extend(core_challenger.write());
        witness_stream.extend(reconstruct_challenger.write());
        witness_stream.extend(prep_sorted_indices.write());
        witness_stream.extend(prep_domains.write());
        witness_stream.extend(recursion_prep_sorted_indices.write());
        witness_stream.extend(recursion_prep_domains.write());
        witness_stream.extend(vk.vk.write());
        witness_stream.extend(self.reduce_vk_inner.write());
        witness_stream.extend(Hintable::write(&start_pcs));
        witness_stream.extend(Hintable::write(&next_pcs));
        witness_stream.extend(Hintable::write(&start_shards));
        witness_stream.extend(Hintable::write(&next_shards));
        for proof in reduce_proofs.iter() {
            match proof {
                SP1ReduceProofWrapper::Core(reduce_proof) => {
                    witness_stream.extend(reduce_proof.proof.write());
                }
                SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                    witness_stream.extend(reduce_proof.proof.write());
                }
            }
        }
        let empty_hash = [BabyBear::zero(); 8].to_vec();
        witness_stream.extend(Hintable::write(&empty_hash));
        witness_stream.extend(deferred_sorted_indices.write());
        witness_stream.extend(deferred_proof_vec.write());
        for (_, vk) in deferred_proofs.iter() {
            witness_stream.extend(vk.write());
        }

        // Execute runtime to get the memory setup.
        let machine = RecursionAir::machine(InnerSC::default());
        let mut runtime = Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.reduce_setup_program,
            machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run();
        let mut checkpoint = runtime.memory.clone();
        runtime.print_stats();

        // Execute runtime.
        let machine = RecursionAir::machine(InnerSC::default());
        let mut runtime = Runtime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.reduce_program,
            machine.config().perm.clone(),
        );
        checkpoint.iter_mut().for_each(|e| {
            e.1.timestamp = BabyBear::zero();
        });
        runtime.memory = checkpoint;
        runtime.run();

        // Generate proof.
        let machine = RecursionAir::machine(SC::default());
        let (pk, _) = machine.setup(&self.reduce_program);
        let mut challenger = machine.config().challenger();
        let proof = machine.prove::<LocalProver<_, _>>(&pk, runtime.record, &mut challenger);

        // Return the reduced proof.
        assert!(proof.shard_proofs.len() == 1);
        let proof = proof.shard_proofs.into_iter().next().unwrap();
        SP1ReduceProof {
            proof,
            start_pc: start_pcs[0],
            next_pc: next_pcs[next_pcs.len() - 1],
            start_shard: start_shards[0],
            next_shard: next_shards[next_shards.len() - 1],
        }
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    pub fn wrap_bn254(
        &self,
        vk: &SP1VerifyingKey,
        core_challenger: Challenger<CoreSC>,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> ShardProof<OuterSC> {
        self.reduce_batch::<OuterSC>(
            vk,
            core_challenger,
            &[SP1ReduceProofWrapper::Recursive(reduced_proof)],
            &[],
        )
        .proof
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a Groth16 proof.
    pub fn wrap_groth16(&self, proof: ShardProof<OuterSC>) {
        let mut witness = Witness::default();
        proof.write(&mut witness);
        let constraints = build_wrap_circuit(&self.reduce_vk_outer, proof);
        groth16_ffi::prove(constraints, witness);
    }

    // TODO: Get rid of this method by reading it from public values.
    pub fn setup_core_challenger(
        &self,
        vk: &SP1VerifyingKey,
        proof: &SP1CoreProof,
    ) -> Challenger<CoreSC> {
        let core_machine = RiscvAir::machine(CoreSC::default());
        let mut core_challenger = core_machine.config().challenger();
        vk.vk.observe_into(&mut core_challenger);
        for shard_proof in proof.shard_proofs.iter() {
            core_challenger.observe(shard_proof.commitment.main_commit);
            core_challenger
                .observe_slice(&shard_proof.public_values.to_vec()[0..core_machine.num_pv_elts()]);
        }
        core_challenger
    }
}

fn get_sorted_indices<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    machine: &StarkMachine<SC, A>,
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
    machine: &StarkMachine<SC, A>,
    vk: &StarkVerifyingKey<SC>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core::utils::setup_logger;
    use sp1_sdk::SP1Stdin;

    #[test]
    #[ignore]
    fn test_prove_sp1() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

        // Generate SP1 proof
        let elf =
            include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

        tracing::info!("initializing prover");
        let prover = SP1Prover::new();

        tracing::info!("setup elf");
        let (pk, vk) = prover.setup(elf);

        tracing::info!("prove core");
        let stdin = SP1Stdin::new();
        let core_proof = prover.prove_core(&pk, &stdin);

        tracing::info!("verify core");
        core_proof.verify(&vk).unwrap();

        // TODO: Get rid of this method by reading it from public values.
        let core_challenger = prover.setup_core_challenger(&vk, &core_proof);

        tracing::info!("reduce");
        let reduced_proof = prover.reduce(&vk, core_proof);

        tracing::info!("wrap");
        let wrapped_bn254_proof = prover.wrap_bn254(&vk, core_challenger, reduced_proof);

        tracing::info!("groth16");
        prover.wrap_groth16(wrapped_bn254_proof);
    }
}
