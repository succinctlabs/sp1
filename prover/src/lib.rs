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

mod utils;
mod verify;

use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_field::TwoAdicField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sp1_core::air::POSEIDON_NUM_WORDS;
use sp1_core::air::PV_DIGEST_NUM_WORDS;
use sp1_core::air::WORD_SIZE;
pub use sp1_core::io::{SP1PublicValues, SP1Stdin};
use sp1_core::runtime::Runtime;
use sp1_core::stark::{Challenge, Com, Domain, PcsProverData, Prover, ShardMainData};
use sp1_core::{
    air::{MachineAir, PublicValues, Word},
    runtime::Program,
    stark::{
        Challenger, Dom, LocalProver, RiscvAir, ShardProof, StarkGenericConfig, StarkMachine,
        StarkProvingKey, StarkVerifyingKey, Val,
    },
    utils::{run_and_prove, BabyBearPoseidon2},
};
use sp1_primitives::poseidon2_hash;
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_circuit::DIGEST_SIZE;
use sp1_recursion_compiler::constraints::groth16_ffi;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_core::runtime::RecursionProgram;
use sp1_recursion_core::{
    air::PublicValues as RecursionPublicValues,
    runtime::Runtime as RecursionRuntime,
    stark::{config::BabyBearPoseidon2Outer, RecursionAir},
};
use sp1_recursion_program::reduce::ReduceProgram;
use sp1_recursion_program::{hints::Hintable, stark::EMPTY};

/// The configuration for the core prover.
pub type CoreSC = BabyBearPoseidon2;

/// The configuration for the recursive prover.
pub type InnerSC = BabyBearPoseidon2;

/// The configuration for the outer prover.
pub type OuterSC = BabyBearPoseidon2Outer;

/// A end-to-end prover implementation for SP1.
pub struct SP1Prover {
    pub reduce_program: RecursionProgram<BabyBear>,
    pub reduce_setup_program: RecursionProgram<BabyBear>,
    pub reduce_vk_inner: StarkVerifyingKey<InnerSC>,
    pub reduce_vk_outer: StarkVerifyingKey<OuterSC>,
    pub core_machine: StarkMachine<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>,
    pub inner_recursion_machine:
        StarkMachine<InnerSC, RecursionAir<<InnerSC as StarkGenericConfig>::Val>>,
    pub outer_recursion_machine:
        StarkMachine<OuterSC, RecursionAir<<OuterSC as StarkGenericConfig>::Val>>,
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
#[derive(Serialize, Deserialize, Clone)]
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
}

/// A wrapper to abstract proofs representing a range of shards with multiple proving configs.
#[derive(Serialize, Deserialize)]
pub enum SP1ReduceProofWrapper {
    Core(SP1ReduceProof<CoreSC>),
    Recursive(SP1ReduceProof<InnerSC>),
}

/// Reprents the state of reducing proofs together. This is used to track the current values since
/// some reduce batches may have only deferred proofs.
#[derive(Clone)]
pub struct ReduceState {
    pub committed_values_digest: [Word<Val<CoreSC>>; PV_DIGEST_NUM_WORDS],
    pub deferred_proofs_digest: [Val<CoreSC>; POSEIDON_NUM_WORDS],
    pub start_pc: Val<CoreSC>,
    pub exit_code: Val<CoreSC>,
    pub start_shard: Val<CoreSC>,
    pub reconstruct_deferred_digest: [Val<CoreSC>; POSEIDON_NUM_WORDS],
}

impl ReduceState {
    pub fn from_reduce_end_state<SC: StarkGenericConfig<Val = BabyBear>>(
        state: &SP1ReduceProof<SC>,
    ) -> Self {
        let pv = RecursionPublicValues::from_vec(state.proof.public_values.clone());
        Self {
            committed_values_digest: pv.committed_value_digest,
            deferred_proofs_digest: pv.deferred_proofs_digest,
            start_pc: pv.next_pc,
            exit_code: pv.exit_code,
            start_shard: pv.next_shard,
            reconstruct_deferred_digest: pv.end_reconstruct_deferred_digest,
        }
    }

    pub fn from_reduce_start_state<SC: StarkGenericConfig<Val = BabyBear>>(
        state: &SP1ReduceProof<SC>,
    ) -> Self {
        let pv = RecursionPublicValues::from_vec(state.proof.public_values.clone());
        Self {
            committed_values_digest: pv.committed_value_digest,
            deferred_proofs_digest: pv.deferred_proofs_digest,
            start_pc: pv.start_pc,
            exit_code: pv.exit_code,
            start_shard: pv.start_shard,
            reconstruct_deferred_digest: pv.start_reconstruct_deferred_digest,
        }
    }

    pub fn from_core_start_state(state: &ShardProof<CoreSC>) -> Self {
        let pv =
            PublicValues::<Word<Val<CoreSC>>, Val<CoreSC>>::from_vec(state.public_values.clone());
        Self {
            committed_values_digest: pv.committed_value_digest,
            deferred_proofs_digest: pv.deferred_proofs_digest,
            start_pc: pv.start_pc,
            exit_code: pv.exit_code,
            start_shard: pv.shard,
            // TODO: we assume that core proofs aren't in a later batch than one with a deferred proof
            reconstruct_deferred_digest: [BabyBear::zero(); 8],
        }
    }
}

impl SP1Prover {
    /// Initializes a new [SP1Prover].
    pub fn new() -> Self {
        let reduce_setup_program = ReduceProgram::setup();
        // Load program from reduce.bin if it exists
        let file = std::fs::File::open("reduce.bin");
        let reduce_program = match file {
            Ok(file) => bincode::deserialize_from(file).unwrap(),
            Err(_) => {
                println!("reduce.bin not found, building reduce program");
                let program = ReduceProgram::build();
                let file = std::fs::File::create("reduce.bin").unwrap();
                bincode::serialize_into(file, &program).unwrap();
                program
            }
        };
        println!("program size: {}", reduce_program.instructions.len());
        let (_, reduce_vk_inner) = RecursionAir::machine(InnerSC::default()).setup(&reduce_program);
        let (_, reduce_vk_outer) = RecursionAir::machine(OuterSC::default()).setup(&reduce_program);
        let core_machine = RiscvAir::machine(CoreSC::default());
        let inner_recursion_machine = RecursionAir::machine(InnerSC::default());
        let outer_recursion_machine = RecursionAir::machine(OuterSC::default());
        Self {
            reduce_setup_program,
            reduce_program,
            reduce_vk_inner,
            reduce_vk_outer,
            core_machine,
            inner_recursion_machine,
            outer_recursion_machine,
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

    /// Generate a proof of an SP1 program with the specified inputs.
    pub fn execute(elf: &[u8], stdin: &SP1Stdin) -> SP1PublicValues {
        let program = Program::from(elf);
        let mut runtime = Runtime::new(program);
        runtime.write_vecs(&stdin.buffer);
        runtime.run();
        SP1PublicValues::from(&runtime.state.public_values_stream)
    }

    /// Generate shard proofs which split up and prove the valid execution of a RISC-V program with
    /// the core prover.
    pub fn prove_core(&self, pk: &SP1ProvingKey, stdin: &SP1Stdin) -> SP1CoreProof {
        let config = CoreSC::default();
        let (proof, public_values_stream) = run_and_prove(pk.program.clone(), &stdin, config);
        let public_values = SP1PublicValues::from(&public_values_stream);
        SP1CoreProof {
            shard_proofs: proof.shard_proofs,
            stdin: stdin.clone(),
            public_values,
        }
    }

    /// Reduce shards proofs to a single shard proof using the recursion prover.
    pub fn reduce(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        mut deferred_proofs: Vec<ShardProof<InnerSC>>,
    ) -> SP1ReduceProof<InnerSC> {
        // Observe all commitments and public values.
        //
        // This challenger will be witnessed into reduce program and used to verify sp1 proofs. It
        // will also be reconstructed over all the reduce steps to prove that the witnessed
        // challenger was correct.
        let mut core_challenger = self.core_machine.config().challenger();
        vk.vk.observe_into(&mut core_challenger);
        for shard_proof in proof.shard_proofs.iter() {
            core_challenger.observe(shard_proof.commitment.main_commit);
            core_challenger.observe_slice(
                &shard_proof.public_values.to_vec()[0..self.core_machine.num_pv_elts()],
            );
        }

        // Map the existing shards to a self-reducing type of proof (i.e. Reduce: T[] -> T).
        let mut reduce_proofs = proof
            .shard_proofs
            .into_iter()
            .map(|proof| SP1ReduceProofWrapper::Core(SP1ReduceProof { proof }))
            .collect::<Vec<_>>();

        // Keep reducing until we have only one shard.
        while reduce_proofs.len() > 1 {
            println!("new layer {}", reduce_proofs.len());
            let layer_deferred_proofs = std::mem::take(&mut deferred_proofs);
            reduce_proofs = self.reduce_layer(
                vk,
                core_challenger.clone(),
                reduce_proofs,
                layer_deferred_proofs,
                2,
            );
        }

        // Return the remaining single reduce proof. If we have only one shard, we still want to
        // wrap it into a reduce shard.
        assert_eq!(reduce_proofs.len(), 1);
        let last_proof = reduce_proofs.into_iter().next().unwrap();
        match last_proof {
            SP1ReduceProofWrapper::Recursive(proof) => proof,
            SP1ReduceProofWrapper::Core(ref proof) => {
                let state = ReduceState::from_core_start_state(&proof.proof);
                let reconstruct_challenger = self.setup_initial_core_challenger(vk);
                self.reduce_batch(
                    vk,
                    core_challenger,
                    reconstruct_challenger,
                    state,
                    &[last_proof],
                    &deferred_proofs,
                    true,
                )
            }
        }
    }

    /// Reduce a set of shard proofs in groups of `batch_size` into a smaller set of shard proofs
    /// using the recursion prover.
    fn reduce_layer(
        &self,
        vk: &SP1VerifyingKey,
        sp1_challenger: Challenger<CoreSC>,
        proofs: Vec<SP1ReduceProofWrapper>,
        deferred_proofs: Vec<ShardProof<InnerSC>>,
        batch_size: usize,
    ) -> Vec<SP1ReduceProofWrapper> {
        let last_proof = None;

        // If there are deferred proofs, we want to add them to the end.
        // OPT: If there's only one proof in the last batch, we could push it to the next layer.
        // OPT: We could pack deferred proofs into the last chunk if it has less than batch_size proofs.
        let chunks: Vec<_> = proofs.chunks(batch_size).collect();

        let mut reconstruct_challenger = self.setup_initial_core_challenger(vk);
        let reconstruct_challengers = chunks
            .iter()
            .map(|proofs| {
                let start_challenger = reconstruct_challenger.clone();
                for proof in proofs.iter() {
                    match proof {
                        SP1ReduceProofWrapper::Core(reduce_proof) => {
                            reconstruct_challenger
                                .observe(reduce_proof.proof.commitment.main_commit);
                            reconstruct_challenger.observe_slice(
                                &reduce_proof.proof.public_values.to_vec()
                                    [0..self.core_machine.num_pv_elts()],
                            );
                            let pv = PublicValues::<Word<Val<CoreSC>>, Val<CoreSC>>::from_vec(
                                reduce_proof.proof.public_values.clone(),
                            );
                            println!("next_pc = {:?}", pv.next_pc);
                            println!("shard = {:?}", pv.shard);
                            println!("pv_digest = {:?}", pv.committed_value_digest);
                        }
                        SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                            let pv = RecursionPublicValues::from_vec(
                                reduce_proof.proof.public_values.clone(),
                            );
                            reconstruct_challenger.sponge_state =
                                pv.end_reconstruct_challenger.sponge_state;
                            reconstruct_challenger.input_buffer =
                                pv.end_reconstruct_challenger.input_buffer[..pv
                                    .end_reconstruct_challenger
                                    .num_inputs
                                    .as_canonical_u32()
                                    as usize]
                                    .to_vec();
                            reconstruct_challenger.output_buffer =
                                pv.end_reconstruct_challenger.output_buffer[..pv
                                    .end_reconstruct_challenger
                                    .num_outputs
                                    .as_canonical_u32()
                                    as usize]
                                    .to_vec();
                            println!("2next_pc = {:?}", pv.next_pc);
                            println!("start_shard = {:?}", pv.start_shard);
                            println!("next_shard = {:?}", pv.next_shard);
                            println!("pv_digest = {:?}", pv.committed_value_digest);
                        }
                    }
                }
                start_challenger
            })
            .collect::<Vec<_>>();
        let start_states = chunks
            .iter()
            .map(|chunk| match chunk[0] {
                SP1ReduceProofWrapper::Core(ref proof) => {
                    ReduceState::from_core_start_state(&proof.proof)
                }
                SP1ReduceProofWrapper::Recursive(ref proof) => {
                    ReduceState::from_reduce_start_state(proof)
                }
            })
            .collect::<Vec<_>>();
        for start_state in start_states.iter() {
            println!(
                "1deferred_digest = {:?}",
                start_state.deferred_proofs_digest
            );
            println!(
                "1deferred_digest = {:?}",
                start_state.reconstruct_deferred_digest
            );
        }
        // This is the last layer only if the outcome is a single proof. If there are deferred proofs
        // or there is a single proof being pushed to the next layer, it's not the last layer.
        let is_complete = chunks.len() == 1 && last_proof.is_none() && deferred_proofs.is_empty();
        println!(
            "num main chunks = {}, num deferred chunks = {}",
            chunks.len(),
            deferred_proofs.len()
        );
        let mut new_proofs: Vec<SP1ReduceProofWrapper> = chunks
            .into_iter()
            .zip(reconstruct_challengers.into_iter())
            .zip(start_states.into_iter())
            .map(|((chunk, reconstruct_challenger), start_state)| {
                let proof = self.reduce_batch(
                    vk,
                    sp1_challenger.clone(),
                    reconstruct_challenger,
                    start_state,
                    chunk,
                    &[],
                    is_complete,
                );
                SP1ReduceProofWrapper::Recursive(proof)
            })
            .collect();

        if let Some(proof) = last_proof {
            new_proofs.push(proof);
        }

        // For all the proofs with only deferred proofs, the start and end state will be the end
        // state of the last proof from above.
        let last_new_proof = &new_proofs[new_proofs.len() - 1];
        let mut reduce_state: ReduceState = match last_new_proof {
            SP1ReduceProofWrapper::Recursive(ref proof) => {
                ReduceState::from_reduce_end_state(proof)
            }
            _ => unreachable!(),
        };
        let deferred_chunks: Vec<_> = deferred_proofs.chunks(batch_size).collect();
        let start_states = deferred_chunks
            .iter()
            .map(|chunk| {
                let start_state = reduce_state.clone();
                // Accumulate deferred proofs into the digest
                // poseidon2( current_digest[..8] || pv.sp1_vk_digest[..8] || pv.committed_value_digest[..32] )
                for proof in chunk.iter() {
                    println!(
                        "before deferred_digest = {:?}",
                        reduce_state.reconstruct_deferred_digest
                    );
                    let pv = RecursionPublicValues::from_vec(proof.public_values.clone());
                    let mut inputs = [BabyBear::zero(); 48];
                    inputs[0..8].copy_from_slice(&reduce_state.reconstruct_deferred_digest);
                    let vk_digest = pv.sp1_vk_digest;
                    inputs[8..16].copy_from_slice(&vk_digest);
                    for i in 0..PV_DIGEST_NUM_WORDS {
                        for j in 0..WORD_SIZE {
                            inputs[16 + i * WORD_SIZE + j] = pv.committed_value_digest[i][j];
                        }
                    }
                    println!("inputs: {:?}", inputs);
                    reduce_state.reconstruct_deferred_digest = poseidon2_hash(inputs.to_vec());
                    println!(
                        "after deferred_digest = {:?}",
                        reduce_state.reconstruct_deferred_digest
                    );
                }
                start_state
            })
            .collect::<Vec<_>>();
        for start_state in start_states.iter() {
            println!("deferred_digest = {:?}", start_state.deferred_proofs_digest);
            println!(
                "reconstruct_deferred_digest = {:?}",
                start_state.reconstruct_deferred_digest
            );
        }

        println!("num deferred chunks = {}", deferred_chunks.len());
        let new_deferred_proofs = deferred_chunks
            .into_par_iter()
            .zip(start_states.into_par_iter())
            .map(|(proofs, state)| {
                self.reduce_batch::<InnerSC>(
                    vk,
                    sp1_challenger.clone(),
                    reconstruct_challenger.clone(),
                    state,
                    &[],
                    proofs,
                    false,
                )
            })
            .collect::<Vec<_>>();

        new_proofs.extend(
            new_deferred_proofs
                .into_iter()
                .map(SP1ReduceProofWrapper::Recursive),
        );
        new_proofs
    }

    /// Reduces a batch of shard proofs into a single shard proof using the recursion prover.
    #[allow(clippy::too_many_arguments)]
    fn reduce_batch<SC>(
        &self,
        vk: &SP1VerifyingKey,
        core_challenger: Challenger<CoreSC>,
        reconstruct_challenger: Challenger<CoreSC>,
        state: ReduceState,
        reduce_proofs: &[SP1ReduceProofWrapper],
        deferred_proofs: &[ShardProof<InnerSC>],
        is_complete: bool,
    ) -> SP1ReduceProof<SC>
    where
        SC: StarkGenericConfig<Val = BabyBear> + Default,
        SC::Challenger: Clone,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        LocalProver<SC, RecursionAir<BabyBear>>: Prover<SC, RecursionAir<BabyBear>>,
    {
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
                    get_sorted_indices(&self.core_machine, &reduce_proof.proof)
                }
                SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                    get_sorted_indices(&self.inner_recursion_machine, &reduce_proof.proof)
                }
            })
            .collect();
        let (prep_sorted_indices, prep_domains): (Vec<usize>, Vec<Domain<CoreSC>>) =
            get_preprocessed_data(&self.core_machine, &vk.vk);
        let (recursion_prep_sorted_indices, recursion_prep_domains): (
            Vec<usize>,
            Vec<Domain<InnerSC>>,
        ) = get_preprocessed_data(&self.inner_recursion_machine, &self.reduce_vk_inner);
        let deferred_sorted_indices: Vec<Vec<usize>> = deferred_proofs
            .iter()
            .map(|proof| {
                let indices = get_sorted_indices(&self.inner_recursion_machine, proof);
                println!("indices = {:?}", indices);
                indices
            })
            .collect();

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
        witness_stream.extend(state.committed_values_digest.write());
        witness_stream.extend(state.deferred_proofs_digest.write());
        witness_stream.extend(Hintable::write(&state.start_pc));
        witness_stream.extend(Hintable::write(&state.exit_code));
        witness_stream.extend(Hintable::write(&state.start_shard));
        witness_stream.extend(Hintable::write(&state.reconstruct_deferred_digest));
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
        witness_stream.extend(deferred_sorted_indices.write());
        witness_stream.extend(deferred_proofs.to_vec().write());
        let is_complete = if is_complete { 1usize } else { 0 };
        witness_stream.extend(is_complete.write());

        // Execute runtime to get the memory setup.
        let machine = RecursionAir::machine(InnerSC::default());
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.reduce_setup_program,
            machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run();
        let mut checkpoint = runtime.memory.clone();
        runtime.print_stats();

        // Execute runtime.
        let machine = RecursionAir::machine(InnerSC::default());
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
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
        SP1ReduceProof { proof }
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    pub fn wrap_bn254(
        &self,
        vk: &SP1VerifyingKey,
        core_challenger: Challenger<CoreSC>,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> ShardProof<OuterSC> {
        // Since the proof passed in should be complete already, the start reconstruct_challenger
        // should be in initial state with only vk observed.
        let reconstruct_challenger = self.setup_initial_core_challenger(vk);
        let state = ReduceState::from_reduce_start_state(&reduced_proof);
        self.reduce_batch::<OuterSC>(
            vk,
            core_challenger,
            reconstruct_challenger,
            state,
            &[SP1ReduceProofWrapper::Recursive(reduced_proof)],
            &[],
            true,
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

    pub fn setup_initial_core_challenger(&self, vk: &SP1VerifyingKey) -> Challenger<CoreSC> {
        let mut core_challenger = self.core_machine.config().challenger();
        vk.vk.observe_into(&mut core_challenger);
        core_challenger
    }

    pub fn setup_core_challenger(
        &self,
        vk: &SP1VerifyingKey,
        proof: &SP1CoreProof,
    ) -> Challenger<CoreSC> {
        let mut core_challenger = self.setup_initial_core_challenger(vk);
        for shard_proof in proof.shard_proofs.iter() {
            core_challenger.observe(shard_proof.commitment.main_commit);
            core_challenger.observe_slice(
                &shard_proof.public_values.to_vec()[0..self.core_machine.num_pv_elts()],
            );
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

/// Hash the verifying key + prep domains into a single digest.
/// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
fn hash_vkey<A: MachineAir<BabyBear>>(
    machine: &StarkMachine<CoreSC, A>,
    vkey: &SP1VerifyingKey,
) -> [BabyBear; 8] {
    // TODO: cleanup
    let (_, prep_domains) = get_preprocessed_data(machine, &vkey.vk);
    let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
    let mut inputs = Vec::with_capacity(num_inputs);
    inputs.extend(vkey.vk.commit.as_ref());
    inputs.push(vkey.vk.pc_start);
    for domain in prep_domains.iter() {
        inputs.push(BabyBear::from_canonical_usize(domain.log_n));
        let size = 1 << domain.log_n;
        inputs.push(BabyBear::from_canonical_usize(size));
        let g = BabyBear::two_adic_generator(domain.log_n);
        inputs.push(domain.shift);
        inputs.push(g);
    }

    println!("vkey hash inputs: {:?}", inputs);
    poseidon2_hash(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_core::io::SP1Stdin;
    use sp1_core::utils::setup_logger;

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
        let reduced_proof = prover.reduce(&vk, core_proof, vec![]);

        tracing::info!("wrap");
        let wrapped_bn254_proof = prover.wrap_bn254(&vk, core_challenger, reduced_proof);

        tracing::info!("groth16");
        prover.wrap_groth16(wrapped_bn254_proof);
    }

    #[test]
    #[ignore]
    fn test_deferred_verify() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

        // Generate SP1 proof
        let keccak_elf = include_bytes!("../../tests/keccak256/elf/riscv32im-succinct-zkvm-elf");

        let verify_elf = include_bytes!("../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");

        tracing::info!("initializing prover");
        let prover = SP1Prover::new();

        tracing::info!("setup elf");
        let (keccak_pk, keccak_vk) = prover.setup(keccak_elf);
        let (verify_pk, verify_vk) = prover.setup(verify_elf);

        tracing::info!("prove subproof 1");
        let mut stdin = SP1Stdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        // Read proof from p1.bin if exists
        let p1_file = std::fs::File::open("p1.bin");
        let deferred_proof_1 = match p1_file {
            Ok(file) => bincode::deserialize_from(file).unwrap(),
            Err(_) => {
                let deferred_proof_1 = prover.prove_core(&keccak_pk, &stdin);
                let file = std::fs::File::create("p1.bin").unwrap();
                bincode::serialize_into(file, &deferred_proof_1).unwrap();
                deferred_proof_1
            }
        };
        let pv_1 = deferred_proof_1.public_values.buffer.data.clone();
        println!("proof 1 pv: {:?}", hex::encode(pv_1.clone()));
        let pv_digest_1 = deferred_proof_1.shard_proofs[0].public_values[..32]
            .iter()
            .map(|x| x.as_canonical_u32() as u8)
            .collect::<Vec<_>>();
        println!("proof 1 pv_digest: {:?}", hex::encode(pv_digest_1.clone()));

        tracing::info!("prove subproof 2");
        let mut stdin = SP1Stdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        // Read proof from p2.bin if exists
        let p2_file = std::fs::File::open("p2.bin");
        let deferred_proof_2 = match p2_file {
            Ok(file) => bincode::deserialize_from(file).unwrap(),
            Err(_) => {
                let deferred_proof_2 = prover.prove_core(&keccak_pk, &stdin);
                let file = std::fs::File::create("p2.bin").unwrap();
                bincode::serialize_into(file, &deferred_proof_2).unwrap();
                deferred_proof_2
            }
        };
        let pv_2 = deferred_proof_2.public_values.buffer.data.clone();
        println!("proof 2 pv: {:?}", hex::encode(pv_2.clone()));
        let pv_digest_2 = deferred_proof_2.shard_proofs[0].public_values[..32]
            .iter()
            .map(|x| x.as_canonical_u32() as u8)
            .collect::<Vec<_>>();
        println!("proof 2 pv_digest: {:?}", hex::encode(pv_digest_2.clone()));

        println!("reduce subproof 1");
        let deferred_reduce_1 = prover.reduce(&keccak_vk, deferred_proof_1, vec![]);

        println!("reduce subproof 2");
        let deferred_reduce_2 = prover.reduce(&keccak_vk, deferred_proof_2, vec![]);

        let mut stdin = SP1Stdin::new();
        let vkey_digest = hash_vkey(&prover.core_machine, &keccak_vk);
        let vkey_digest: [u32; 8] = vkey_digest
            .into_iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        stdin.write(&vkey_digest);
        stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        stdin.write_proof(deferred_reduce_1.proof.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.proof.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.proof.clone(), keccak_vk.vk.clone());

        println!("proving verify program (core)");
        let verify_proof = prover.prove_core(&verify_pk, &stdin);
        let pv = PublicValues::<Word<BabyBear>, BabyBear>::from_vec(
            verify_proof.shard_proofs[0].public_values.clone(),
        );

        println!("deferred_hash: {:?}", pv.deferred_proofs_digest);

        println!("proving verify program (recursion)");
        let verify_reduce = prover.reduce(
            &verify_vk,
            verify_proof.clone(),
            vec![
                deferred_reduce_1.proof,
                deferred_reduce_2.proof.clone(),
                deferred_reduce_2.proof,
            ],
        );
        let reduce_pv = RecursionPublicValues::from_vec(verify_reduce.proof.public_values.clone());
        println!("deferred_hash: {:?}", reduce_pv.deferred_proofs_digest);
        println!("complete: {:?}", reduce_pv.is_complete);

        println!("wrap");
        let challenger = prover.setup_core_challenger(&verify_vk, &verify_proof);
        let wrapped = prover.wrap_bn254(&verify_vk, challenger, verify_reduce);

        tracing::info!("groth16");
        prover.wrap_groth16(wrapped);
    }
}
