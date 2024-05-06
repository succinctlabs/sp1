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
#![allow(clippy::too_many_arguments)]
#![allow(clippy::new_without_default)]

pub mod build;
pub mod install;
mod types;
pub mod utils;
mod verify;

use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;
pub use sp1_core::io::{SP1PublicValues, SP1Stdin};
use sp1_core::runtime::Runtime;
use sp1_core::stark::{
    Challenge, Com, Domain, PcsProverData, Prover, ShardMainData, StarkProvingKey,
};
use sp1_core::{
    runtime::Program,
    stark::{
        Challenger, LocalProver, RiscvAir, ShardProof, StarkGenericConfig, StarkMachine,
        StarkVerifyingKey, Val,
    },
    utils::{run_and_prove, BabyBearPoseidon2},
};
use sp1_primitives::hash_deferred_proof;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_core::runtime::RecursionProgram;
use sp1_recursion_core::stark::RecursionAirSkinnyDeg7;
use sp1_recursion_core::{
    air::RecursionPublicValues,
    runtime::Runtime as RecursionRuntime,
    stark::{config::BabyBearPoseidon2Outer, RecursionAirWideDeg3},
};
pub use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Proof;
use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Prover;
pub use sp1_recursion_gnark_ffi::Groth16Proof;
use sp1_recursion_gnark_ffi::Groth16Prover;
use sp1_recursion_program::hints::Hintable;
use sp1_recursion_program::reduce::ReduceProgram;
use sp1_recursion_program::types::QuotientDataValues;
use std::env;
use std::path::PathBuf;
use std::time::Instant;
use tracing::instrument;
pub use types::*;
use utils::babybear_bytes_to_bn254;
use utils::babybears_to_bn254;
use utils::words_to_bytes;

use crate::types::ReduceState;
use crate::utils::get_chip_quotient_data;
use crate::utils::get_preprocessed_data;
use crate::utils::get_sorted_indices;
use crate::utils::RECONSTRUCT_COMMITMENTS_ENV_VAR;

/// The configuration for the core prover.
pub type CoreSC = BabyBearPoseidon2;

/// The configuration for the inner prover.
pub type InnerSC = BabyBearPoseidon2;

/// The configuration for the outer prover.
pub type OuterSC = BabyBearPoseidon2Outer;

/// A end-to-end prover implementation for SP1.
pub struct SP1Prover {
    /// The program that can recursively verify a set of proofs into a single proof.
    pub recursion_program: RecursionProgram<BabyBear>,

    /// The program that sets up memory for the recursion program.
    pub recursion_setup_program: RecursionProgram<BabyBear>,

    /// The proving key for the reduce step.
    pub compress_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the reduce step.
    pub compress_vk: StarkVerifyingKey<InnerSC>,

    /// The proving key for the shrink step.
    pub shrink_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the shrink step.
    pub shrink_vk: StarkVerifyingKey<InnerSC>,

    /// The proving key for the wrap step.
    pub wrap_pk: StarkProvingKey<OuterSC>,

    /// The verification key for the wrapping step.
    pub wrap_vk: StarkVerifyingKey<OuterSC>,

    /// The machine used for proving the core step.
    pub core_machine: StarkMachine<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>,

    /// The machine used for proving the reduce step.
    pub compress_machine:
        StarkMachine<InnerSC, RecursionAirWideDeg3<<InnerSC as StarkGenericConfig>::Val>>,

    /// The machine used for proving the compress step.
    pub shrink_machine:
        StarkMachine<InnerSC, RecursionAirSkinnyDeg7<<InnerSC as StarkGenericConfig>::Val>>,

    /// The machine used for proving the wrapping step.
    pub wrap_machine:
        StarkMachine<OuterSC, RecursionAirSkinnyDeg7<<OuterSC as StarkGenericConfig>::Val>>,
}

impl SP1Prover {
    /// Initializes a new [SP1Prover].
    #[instrument(name = "initialize prover", level = "info", skip_all)]
    pub fn new() -> Self {
        let recursion_setup_program = ReduceProgram::setup();
        let recursion_program = ReduceProgram::build();
        let (compress_pk, compress_vk) =
            RecursionAirWideDeg3::machine(InnerSC::default()).setup(&recursion_program);
        let (shrink_pk, shrink_vk) =
            RecursionAirSkinnyDeg7::machine(InnerSC::compressed()).setup(&recursion_program);
        let (wrap_pk, wrap_vk) =
            RecursionAirSkinnyDeg7::machine(OuterSC::default()).setup(&recursion_program);
        let core_machine = RiscvAir::machine(CoreSC::default());
        let compress_machine = RecursionAirWideDeg3::machine(InnerSC::default());
        let shrink_machine = RecursionAirSkinnyDeg7::machine(InnerSC::compressed());
        let wrap_machine = RecursionAirSkinnyDeg7::machine(OuterSC::default());
        Self {
            recursion_setup_program,
            recursion_program,
            compress_pk,
            compress_vk,
            shrink_pk,
            shrink_vk,
            wrap_pk,
            wrap_vk,
            core_machine,
            compress_machine,
            shrink_machine,
            wrap_machine,
        }
    }

    /// Creates a proving key and a verifying key for a given RISC-V ELF.
    #[instrument(name = "setup", level = "info", skip_all)]
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        let program = Program::from(elf);
        let (pk, vk) = self.core_machine.setup(&program);
        let vk = SP1VerifyingKey { vk };
        let pk = SP1ProvingKey {
            pk,
            elf: elf.to_vec(),
            vk: vk.clone(),
        };
        (pk, vk)
    }

    /// Accumulate deferred proofs into a single digest.
    pub fn hash_deferred_proofs(
        prev_digest: [Val<CoreSC>; 8],
        deferred_proofs: &[ShardProof<InnerSC>],
    ) -> [Val<CoreSC>; 8] {
        let mut digest = prev_digest;
        for proof in deferred_proofs.iter() {
            let pv = RecursionPublicValues::from_vec(proof.public_values.clone());
            let committed_values_digest = words_to_bytes(&pv.committed_value_digest);
            digest = hash_deferred_proof(
                &digest,
                &pv.sp1_vk_digest,
                &committed_values_digest.try_into().unwrap(),
            );
        }
        digest
    }

    /// Generate a proof of an SP1 program with the specified inputs.
    #[instrument(name = "execute", level = "info", skip_all)]
    pub fn execute(elf: &[u8], stdin: &SP1Stdin) -> SP1PublicValues {
        let program = Program::from(elf);
        let mut runtime = Runtime::new(program);
        runtime.write_vecs(&stdin.buffer);
        for (proof, vkey) in stdin.proofs.iter() {
            runtime.write_proof(proof.clone(), vkey.clone());
        }
        runtime.run();
        SP1PublicValues::from(&runtime.state.public_values_stream)
    }

    /// Generate shard proofs which split up and prove the valid execution of a RISC-V program with
    /// the core prover.
    #[instrument(name = "prove_core", level = "info", skip_all)]
    pub fn prove_core(
        &self,
        pk: &SP1ProvingKey,
        stdin: &SP1Stdin,
    ) -> SP1ProofWithMetadata<SP1CoreProofData> {
        let config = CoreSC::default();
        let program = Program::from(&pk.elf);
        let (proof, public_values_stream) = run_and_prove(program, stdin, config);
        let public_values = SP1PublicValues::from(&public_values_stream);
        SP1ProofWithMetadata {
            proof: SP1CoreProofData(proof.shard_proofs),
            stdin: stdin.clone(),
            public_values,
        }
    }

    /// Compress shards proofs to a single shard proof using the recursion prover.
    #[instrument(name = "compress", level = "info", skip_all)]
    pub fn compress(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProofData,
        mut deferred_proofs: Vec<ShardProof<InnerSC>>,
    ) -> SP1ReduceProof<InnerSC> {
        // Observe all commitments and public values.
        //
        // This challenger will be witnessed into reduce program and used to verify sp1 proofs. It
        // will also be reconstructed over all the reduce steps to prove that the witnessed
        // challenger was correct.
        let mut core_challenger = self.core_machine.config().challenger();
        vk.vk.observe_into(&mut core_challenger);
        for shard_proof in proof.0.iter() {
            core_challenger.observe(shard_proof.commitment.main_commit);
            core_challenger.observe_slice(
                &shard_proof.public_values.to_vec()[0..self.core_machine.num_pv_elts()],
            );
        }

        // Map the existing shards to a self-reducing type of proof (i.e. Reduce: T[] -> T).
        let mut reduce_proofs = proof
            .0
            .into_iter()
            .map(|proof| SP1ReduceProofWrapper::Core(SP1ReduceProof { proof }))
            .collect::<Vec<_>>();

        // Keep reducing until we have only one shard.
        while reduce_proofs.len() > 1 {
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
                let config = InnerSC::default();
                self.verify_batch(
                    config,
                    &self.compress_pk,
                    vk,
                    core_challenger,
                    reconstruct_challenger,
                    state,
                    &[last_proof],
                    &deferred_proofs,
                    true,
                    false,
                    false,
                )
            }
        }
    }

    /// Reduce a set of shard proofs in groups of `batch_size` into a smaller set of shard proofs
    /// using the recursion prover.
    #[instrument(name = "reduce_layer", level = "info", skip_all)]
    fn reduce_layer(
        &self,
        vk: &SP1VerifyingKey,
        sp1_challenger: Challenger<CoreSC>,
        proofs: Vec<SP1ReduceProofWrapper>,
        deferred_proofs: Vec<ShardProof<InnerSC>>,
        batch_size: usize,
    ) -> Vec<SP1ReduceProofWrapper> {
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
                        }
                        SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                            let pv = RecursionPublicValues::from_vec(
                                reduce_proof.proof.public_values.clone(),
                            );
                            pv.end_reconstruct_challenger
                                .set_challenger(&mut reconstruct_challenger);
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

        // This is the last layer only if the outcome is a single proof. If there are deferred
        // proofs, it's not the last layer.
        let is_complete = chunks.len() == 1 && deferred_proofs.is_empty();
        let mut new_proofs: Vec<SP1ReduceProofWrapper> = chunks
            .into_par_iter()
            .zip(reconstruct_challengers.into_par_iter())
            .zip(start_states.into_par_iter())
            .map(|((chunk, reconstruct_challenger), start_state)| {
                let config = InnerSC::default();
                let proof = self.verify_batch(
                    config,
                    &self.compress_pk,
                    vk,
                    sp1_challenger.clone(),
                    reconstruct_challenger,
                    start_state,
                    chunk,
                    &[],
                    is_complete,
                    false,
                    false,
                );
                SP1ReduceProofWrapper::Recursive(proof)
            })
            .collect();

        // If there are deferred proofs, we want to add them to the end.
        // Here we get the end state of the last proof from above which will be the start state for
        // the deferred proofs. When verifying only deferred proofs, only reconstruct_deferred_digests
        // should change.
        let last_new_proof = &new_proofs[new_proofs.len() - 1];
        let mut reduce_state: ReduceState = match last_new_proof {
            SP1ReduceProofWrapper::Recursive(ref proof) => {
                ReduceState::from_reduce_end_state(proof)
            }
            _ => unreachable!(),
        };
        let deferred_chunks: Vec<_> = deferred_proofs.chunks(batch_size).collect();

        // For each reduce, we need to pass in the start state from the previous proof. Here we
        // need to compute updated reconstruct_deferred_digests since each proof is modifying it.
        let start_states = deferred_chunks
            .iter()
            .map(|chunk| {
                let start_state = reduce_state.clone();
                // Accumulate each deferred proof into the digest
                reduce_state.reconstruct_deferred_digest =
                    Self::hash_deferred_proofs(reduce_state.reconstruct_deferred_digest, chunk);
                start_state
            })
            .collect::<Vec<_>>();

        let new_deferred_proofs = deferred_chunks
            .into_par_iter()
            .zip(start_states.into_par_iter())
            .map(|(proofs, state)| {
                let config = InnerSC::default();
                self.verify_batch::<InnerSC>(
                    config,
                    &self.compress_pk,
                    vk,
                    sp1_challenger.clone(),
                    reconstruct_challenger.clone(),
                    state,
                    &[],
                    proofs,
                    false,
                    false,
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

    /// Verifies a batch of proofs using the recursion prover.
    #[instrument(name = "verify_batch", level = "info", skip_all)]
    fn verify_batch<SC>(
        &self,
        config: SC,
        pk: &StarkProvingKey<SC>,
        core_vk: &SP1VerifyingKey,
        core_challenger: Challenger<CoreSC>,
        reconstruct_challenger: Challenger<CoreSC>,
        state: ReduceState,
        reduce_proofs: &[SP1ReduceProofWrapper],
        deferred_proofs: &[ShardProof<InnerSC>],
        is_complete: bool,
        verifying_compressed_proof: bool,
        proving_with_skinny: bool,
    ) -> SP1ReduceProof<SC>
    where
        SC: StarkGenericConfig<Val = BabyBear>,
        SC::Challenger: Clone,
        Com<SC>: Send + Sync,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
        LocalProver<SC, RecursionAirSkinnyDeg7<BabyBear>>:
            Prover<SC, RecursionAirSkinnyDeg7<BabyBear>>,
        LocalProver<SC, RecursionAirWideDeg3<BabyBear>>: Prover<SC, RecursionAirWideDeg3<BabyBear>>,
    {
        // Setup the prover parameters.
        let rc = env::var(RECONSTRUCT_COMMITMENTS_ENV_VAR).unwrap_or_default();
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, "false");

        // Compute inputs.
        let is_recursive_flags: Vec<usize> = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(_) => 0,
                SP1ReduceProofWrapper::Recursive(_) => 1,
            })
            .collect();
        let chip_quotient_data: Vec<Vec<QuotientDataValues>> = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(reduce_proof) => {
                    get_chip_quotient_data(&self.core_machine, &reduce_proof.proof)
                }
                SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                    if verifying_compressed_proof {
                        get_chip_quotient_data(&self.shrink_machine, &reduce_proof.proof)
                    } else {
                        get_chip_quotient_data(&self.compress_machine, &reduce_proof.proof)
                    }
                }
            })
            .collect();
        let sorted_indices: Vec<Vec<usize>> = reduce_proofs
            .iter()
            .map(|p| match p {
                SP1ReduceProofWrapper::Core(reduce_proof) => {
                    get_sorted_indices(&self.core_machine, &reduce_proof.proof)
                }
                SP1ReduceProofWrapper::Recursive(reduce_proof) => {
                    if verifying_compressed_proof {
                        get_sorted_indices(&self.shrink_machine, &reduce_proof.proof)
                    } else {
                        get_sorted_indices(&self.compress_machine, &reduce_proof.proof)
                    }
                }
            })
            .collect();
        let (prep_sorted_indices, prep_domains): (Vec<usize>, Vec<Domain<CoreSC>>) =
            get_preprocessed_data(&self.core_machine, &core_vk.vk);
        let (reduce_prep_sorted_indices, reduce_prep_domains): (Vec<usize>, Vec<Domain<InnerSC>>) =
            get_preprocessed_data(&self.compress_machine, &self.compress_vk);
        let (compress_prep_sorted_indices, compress_prep_domains): (
            Vec<usize>,
            Vec<Domain<InnerSC>>,
        ) = get_preprocessed_data(&self.shrink_machine, &self.shrink_vk);
        let deferred_sorted_indices: Vec<Vec<usize>> = deferred_proofs
            .iter()
            .map(|proof| get_sorted_indices(&self.compress_machine, proof))
            .collect();
        let deferred_chip_quotient_data: Vec<Vec<QuotientDataValues>> = deferred_proofs
            .iter()
            .map(|p| get_chip_quotient_data(&self.compress_machine, p))
            .collect();

        // Convert the inputs into a witness stream.
        let mut witness_stream = Vec::new();
        witness_stream.extend(is_recursive_flags.write());
        witness_stream.extend(chip_quotient_data.write());
        witness_stream.extend(sorted_indices.write());
        witness_stream.extend(core_challenger.write());
        witness_stream.extend(reconstruct_challenger.write());
        witness_stream.extend(prep_sorted_indices.write());
        witness_stream.extend(Hintable::write(&prep_domains));
        witness_stream.extend(reduce_prep_sorted_indices.write());
        witness_stream.extend(Hintable::write(&reduce_prep_domains));
        witness_stream.extend(compress_prep_sorted_indices.write());
        witness_stream.extend(Hintable::write(&compress_prep_domains));
        witness_stream.extend(core_vk.vk.write());
        witness_stream.extend(self.compress_vk.write());
        witness_stream.extend(self.shrink_vk.write());
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
        witness_stream.extend(deferred_chip_quotient_data.write());
        witness_stream.extend(deferred_sorted_indices.write());
        witness_stream.extend(deferred_proofs.to_vec().write());
        let is_complete = if is_complete { 1usize } else { 0 };
        witness_stream.extend(is_complete.write());
        let is_compressed = if verifying_compressed_proof {
            1usize
        } else {
            0
        };
        witness_stream.extend(is_compressed.write());

        let machine = RecursionAirWideDeg3::machine(InnerSC::default());
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.recursion_setup_program,
            machine.config().perm.clone(),
        );
        runtime.witness_stream = witness_stream.into();
        runtime.run();
        let mut checkpoint = runtime.memory.clone();

        // Execute runtime.
        let machine = RecursionAirWideDeg3::machine(InnerSC::default());
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.recursion_program,
            machine.config().perm.clone(),
        );
        checkpoint.iter_mut().for_each(|e| {
            e.1.timestamp = BabyBear::zero();
        });
        runtime.memory = checkpoint;
        runtime.run();
        runtime.print_stats();
        tracing::info!(
            "runtime summary: cycles={}, nb_poseidons={}",
            runtime.timestamp,
            runtime.nb_poseidons
        );

        // Generate proof.
        let start = Instant::now();
        let proof = if proving_with_skinny && verifying_compressed_proof {
            let machine = RecursionAirSkinnyDeg7::wrap_machine(config);
            let mut challenger = machine.config().challenger();
            machine.prove::<LocalProver<_, _>>(pk, runtime.record.clone(), &mut challenger)
        } else if proving_with_skinny {
            let machine = RecursionAirSkinnyDeg7::machine(config);
            let mut challenger = machine.config().challenger();
            machine.prove::<LocalProver<_, _>>(pk, runtime.record.clone(), &mut challenger)
        } else {
            let machine = RecursionAirWideDeg3::machine(config);
            let mut challenger = machine.config().challenger();
            machine.prove::<LocalProver<_, _>>(pk, runtime.record.clone(), &mut challenger)
        };
        let elapsed = start.elapsed().as_secs_f64();

        let proof_size = bincode::serialize(&proof).unwrap().len();
        tracing::info!(
            "proving summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
            runtime.timestamp,
            elapsed,
            (runtime.timestamp as f64 / elapsed) / 1000f64,
            Size::from_bytes(proof_size),
        );

        // Restore the prover parameters.
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, rc);

        // Return the reduced proof.
        assert!(proof.shard_proofs.len() == 1);
        let proof = proof.shard_proofs.into_iter().next().unwrap();
        SP1ReduceProof { proof }
    }

    /// Shrink a compressed proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "shrink", level = "info", skip_all)]
    pub fn shrink(
        &self,
        vk: &SP1VerifyingKey,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> SP1ReduceProof<InnerSC> {
        // Get verify_start_challenger from the reduce proof's public values.
        let pv = RecursionPublicValues::from_vec(reduced_proof.proof.public_values.clone());
        let mut core_challenger = self.core_machine.config().challenger();
        pv.verify_start_challenger
            .set_challenger(&mut core_challenger);
        // Since the proof passed in should be complete already, the start reconstruct_challenger
        // should be in initial state with only vk observed.
        let reconstruct_challenger = self.setup_initial_core_challenger(vk);
        let state = ReduceState::from_reduce_start_state(&reduced_proof);
        let config = InnerSC::compressed();
        self.verify_batch::<InnerSC>(
            config,
            &self.shrink_pk,
            vk,
            core_challenger,
            reconstruct_challenger,
            state,
            &[SP1ReduceProofWrapper::Recursive(reduced_proof)],
            &[],
            true,
            false,
            true,
        )
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(
        &self,
        vk: &SP1VerifyingKey,
        reduced_proof: SP1ReduceProof<InnerSC>,
    ) -> ShardProof<OuterSC> {
        // Get verify_start_challenger from the reduce proof's public values.
        let pv = RecursionPublicValues::from_vec(reduced_proof.proof.public_values.clone());
        let mut core_challenger = self.core_machine.config().challenger();
        pv.verify_start_challenger
            .set_challenger(&mut core_challenger);
        // Since the proof passed in should be complete already, the start reconstruct_challenger
        // should be in initial state with only vk observed.
        let reconstruct_challenger = self.setup_initial_core_challenger(vk);
        let state = ReduceState::from_reduce_start_state(&reduced_proof);
        let config = OuterSC::default();
        self.verify_batch::<OuterSC>(
            config,
            &self.wrap_pk,
            vk,
            core_challenger,
            reconstruct_challenger,
            state,
            &[SP1ReduceProofWrapper::Recursive(reduced_proof)],
            &[],
            true,
            true,
            true,
        )
        .proof
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a Groth16 proof.
    #[instrument(name = "wrap_groth16", level = "info", skip_all)]
    pub fn wrap_groth16(&self, proof: ShardProof<OuterSC>, build_dir: PathBuf) -> Groth16Proof {
        let pv = RecursionPublicValues::from_vec(proof.public_values.clone());

        // Convert pv.vkey_digest to a bn254 field element
        let vkey_hash = babybears_to_bn254(&pv.sp1_vk_digest);

        // Convert pv.committed_value_digest to a bn254 field element
        let committed_values_digest_bytes: [BabyBear; 32] =
            words_to_bytes(&pv.committed_value_digest)
                .try_into()
                .unwrap();
        let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

        let mut witness = Witness::default();
        proof.write(&mut witness);
        witness.write_commited_values_digest(committed_values_digest);
        witness.write_vkey_hash(vkey_hash);

        let prover = Groth16Prover::new(build_dir);
        prover.prove(witness)
    }

    pub fn wrap_plonk(&self, proof: ShardProof<OuterSC>, build_dir: PathBuf) -> PlonkBn254Proof {
        let mut witness = Witness::default();
        proof.write(&mut witness);
        // TODO: write pv and vkey into witness
        PlonkBn254Prover::prove(witness, build_dir)
    }

    pub fn setup_initial_core_challenger(&self, vk: &SP1VerifyingKey) -> Challenger<CoreSC> {
        let mut core_challenger = self.core_machine.config().challenger();
        vk.vk.observe_into(&mut core_challenger);
        core_challenger
    }

    pub fn setup_core_challenger(
        &self,
        vk: &SP1VerifyingKey,
        proof: &SP1CoreProofData,
    ) -> Challenger<CoreSC> {
        let mut core_challenger = self.setup_initial_core_challenger(vk);
        for shard_proof in proof.0.iter() {
            core_challenger.observe(shard_proof.commitment.main_commit);
            core_challenger.observe_slice(
                &shard_proof.public_values.to_vec()[0..self.core_machine.num_pv_elts()],
            );
        }
        core_challenger
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use p3_field::PrimeField32;
    use sp1_core::air::{PublicValues, Word};
    use sp1_core::io::SP1Stdin;
    use sp1_core::utils::setup_logger;

    #[test]
    #[ignore]
    fn test_prove_sp1() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

        // Generate SP1 proof
        let elf = include_bytes!("../../tests/fibonacci/elf/riscv32im-succinct-zkvm-elf");

        tracing::info!("initializing prover");
        let prover = SP1Prover::new();

        tracing::info!("setup elf");
        let (pk, vk) = prover.setup(elf);

        tracing::info!("prove core");
        let stdin = SP1Stdin::new();
        let core_proof = prover.prove_core(&pk, &stdin);

        tracing::info!("verify core");
        prover.verify(&core_proof.proof, &vk).unwrap();

        tracing::info!("compress");
        let compressed_proof = prover.compress(&vk, core_proof, vec![]);

        tracing::info!("wrap bn254");
        let wrapped_bn254_proof = prover.wrap_bn254(&vk, compressed_proof);

        tracing::info!("groth16");
        prover.wrap_groth16(wrapped_bn254_proof, PathBuf::from("build"));
    }

    /// This test ensures that a proof can be deferred in the core vm and verified in recursion.
    #[test]
    #[ignore]
    fn test_deferred_verify() {
        setup_logger();
        std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");
        std::env::set_var("SHARD_SIZE", "262144");
        std::env::set_var("MAX_RECURSION_PROGRAM_SIZE", "1");

        // keccak program which proves keccak of various inputs
        let keccak_elf = include_bytes!("../../tests/keccak256/elf/riscv32im-succinct-zkvm-elf");
        // verify program which verifies proofs of a vkey and a list of committed inputs
        let verify_elf = include_bytes!("../../tests/verify-proof/elf/riscv32im-succinct-zkvm-elf");

        tracing::info!("initializing prover");
        let prover = SP1Prover::new();

        tracing::info!("setup elf");
        let (keccak_pk, keccak_vk) = prover.setup(keccak_elf);
        let (verify_pk, verify_vk) = prover.setup(verify_elf);

        // Prove keccak of various inputs
        tracing::info!("prove subproof 1");
        let mut stdin = SP1Stdin::new();
        stdin.write(&1usize);
        stdin.write(&vec![0u8, 0, 0]);
        let deferred_proof_1 = prover.prove_core(&keccak_pk, &stdin);
        let pv_1 = deferred_proof_1.public_values.as_slice().to_vec().clone();
        println!("proof 1 pv: {:?}", hex::encode(pv_1.clone()));
        let pv_digest_1 = deferred_proof_1.proof.0[0].public_values[..32]
            .iter()
            .map(|x| x.as_canonical_u32() as u8)
            .collect::<Vec<_>>();
        println!("proof 1 pv_digest: {:?}", hex::encode(pv_digest_1.clone()));

        // Generate a second proof of keccak of various inputs
        tracing::info!("prove subproof 2");
        let mut stdin = SP1Stdin::new();
        stdin.write(&3usize);
        stdin.write(&vec![0u8, 1, 2]);
        stdin.write(&vec![2, 3, 4]);
        stdin.write(&vec![5, 6, 7]);
        let deferred_proof_2 = prover.prove_core(&keccak_pk, &stdin);
        let pv_2 = deferred_proof_2.public_values.as_slice().to_vec().clone();
        println!("proof 2 pv: {:?}", hex::encode(pv_2.clone()));
        let pv_digest_2 = deferred_proof_2.proof.0[0].public_values[..32]
            .iter()
            .map(|x| x.as_canonical_u32() as u8)
            .collect::<Vec<_>>();
        println!("proof 2 pv_digest: {:?}", hex::encode(pv_digest_2.clone()));

        // Generate recursive proof of first subproof
        println!("reduce subproof 1");
        let deferred_reduce_1 = prover.compress(&keccak_vk, deferred_proof_1, vec![]);

        // Generate recursive proof of second subproof
        println!("reduce subproof 2");
        let deferred_reduce_2 = prover.compress(&keccak_vk, deferred_proof_2, vec![]);

        // Run verify program with keccak vkey, subproofs, and their committed values
        let mut stdin = SP1Stdin::new();
        let vkey_digest = keccak_vk.hash();
        let vkey_digest: [u32; 8] = vkey_digest
            .iter()
            .map(|n| n.as_canonical_u32())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        stdin.write(&vkey_digest);
        stdin.write(&vec![pv_1.clone(), pv_2.clone(), pv_2.clone()]);
        stdin.write_proof(deferred_reduce_1.proof.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.proof.clone(), keccak_vk.vk.clone());
        stdin.write_proof(deferred_reduce_2.proof.clone(), keccak_vk.vk.clone());

        // Prove verify program
        println!("proving verify program (core)");
        let verify_proof = prover.prove_core(&verify_pk, &stdin);
        let pv = PublicValues::<Word<BabyBear>, BabyBear>::from_vec(
            verify_proof.proof.0[0].public_values.clone(),
        );

        println!("deferred_hash: {:?}", pv.deferred_proofs_digest);

        // Generate recursive proof of verify program
        println!("proving verify program (recursion)");
        let verify_reduce = prover.compress(
            &verify_vk,
            verify_proof.proof.clone(),
            vec![
                deferred_reduce_1.proof,
                deferred_reduce_2.proof.clone(),
                deferred_reduce_2.proof,
            ],
        );
        let reduce_pv = RecursionPublicValues::from_vec(verify_reduce.proof.public_values.clone());
        println!("deferred_hash: {:?}", reduce_pv.deferred_proofs_digest);
        println!("complete: {:?}", reduce_pv.is_complete);

        let reduced_proof = SP1ReducedProofData(verify_reduce.proof);
        prover.verify_reduced(&reduced_proof, &verify_vk).unwrap();

        std::env::remove_var("RECONSTRUCT_COMMITMENTS");
        std::env::remove_var("SHARD_SIZE");
        std::env::remove_var("MAX_RECURSION_PROGRAM_SIZE");
    }
}
