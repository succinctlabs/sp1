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

use std::borrow::Borrow;

use crate::utils::RECONSTRUCT_COMMITMENTS_ENV_VAR;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_challenger::CanObserve;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rayon::prelude::*;
use sp1_core::air::PublicValues;
pub use sp1_core::io::{SP1PublicValues, SP1Stdin};
use sp1_core::runtime::Runtime;
use sp1_core::stark::ProgramVerificationError;
use sp1_core::stark::{Challenge, StarkProvingKey};
use sp1_core::utils::DIGEST_SIZE;
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
use sp1_recursion_compiler::config::InnerConfig;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_core::runtime::RecursionProgram;
use sp1_recursion_core::stark::RecursionAir;
use sp1_recursion_core::{
    air::RecursionPublicValues, runtime::Runtime as RecursionRuntime,
    stark::config::BabyBearPoseidon2Outer,
};
pub use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Proof;
use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Prover;
pub use sp1_recursion_gnark_ffi::Groth16Proof;
use sp1_recursion_gnark_ffi::Groth16Prover;
use sp1_recursion_program::hints::Hintable;
use sp1_recursion_program::reduce::ReduceProgramType;
use sp1_recursion_program::reduce::SP1DeferredMemoryLayout;
use sp1_recursion_program::reduce::SP1DeferredVerifier;
use sp1_recursion_program::reduce::SP1RecursionMemoryLayout;
use sp1_recursion_program::reduce::SP1RecursiveVerifier;
use sp1_recursion_program::reduce::SP1ReduceMemoryLayout;
use sp1_recursion_program::reduce::SP1ReduceVerifier;
use sp1_recursion_program::reduce::SP1RootMemoryLayout;
use sp1_recursion_program::reduce::SP1RootVerifier;
use std::env;
use std::path::PathBuf;
use tracing::instrument;
pub use types::*;
use utils::words_to_bytes;

/// The configuration for the core prover.
pub type CoreSC = BabyBearPoseidon2;

/// The configuration for the inner prover.
pub type InnerSC = BabyBearPoseidon2;

/// The configuration for the outer prover.
pub type OuterSC = BabyBearPoseidon2Outer;

const REDUCE_DEGREE: usize = 3;
const COMPRESS_DEGREE: usize = 9;
const WRAP_DEGREE: usize = 5;

pub type ReduceAir<F> = RecursionAir<F, REDUCE_DEGREE>;
pub type CompressAir<F> = RecursionAir<F, COMPRESS_DEGREE>;
pub type WrapAir<F> = RecursionAir<F, WRAP_DEGREE>;

/// A end-to-end prover implementation for SP1.
pub struct SP1Prover {
    /// The program that can recursively verify a set of proofs into a single proof.
    pub recursion_program: RecursionProgram<BabyBear>,

    /// The proving key for the recursion step.
    pub rec_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the recursion step.
    pub rec_vk: StarkVerifyingKey<InnerSC>,

    /// The program that recursively verifies deferred proofs and accumulates the digests.
    pub deferred_program: RecursionProgram<BabyBear>,

    /// The proving key for the reduce step.
    pub deferred_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the reduce step.
    pub deferred_vk: StarkVerifyingKey<InnerSC>,

    /// The program that reduces a set of recursive proofs into a single proof.
    pub reduce_program: RecursionProgram<BabyBear>,

    /// The proving key for the reduce step.
    pub reduce_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the reduce step.
    pub reduce_vk: StarkVerifyingKey<InnerSC>,

    /// The shrink program that compresses a proof into a succinct proof.
    pub shrink_program: RecursionProgram<BabyBear>,

    /// The proving key for the compress step.
    pub shrink_pk: StarkProvingKey<InnerSC>,

    /// The verification key for the compress step.
    pub shrink_vk: StarkVerifyingKey<InnerSC>,

    /// The wrap program that wraps a proof into a SNARK-friendly field.
    pub wrap_program: RecursionProgram<BabyBear>,

    /// The proving key for the wrap step.
    pub wrap_pk: StarkProvingKey<OuterSC>,

    /// The verification key for the wrapping step.
    pub wrap_vk: StarkVerifyingKey<OuterSC>,

    /// The machine used for proving the core step.
    pub core_machine: StarkMachine<CoreSC, RiscvAir<<CoreSC as StarkGenericConfig>::Val>>,

    /// The machine used for proving the recursive and reduction steps.
    pub reduce_machine: StarkMachine<InnerSC, ReduceAir<<InnerSC as StarkGenericConfig>::Val>>,

    /// The machine used for proving the shrink step.
    pub shrink_machine: StarkMachine<InnerSC, CompressAir<<InnerSC as StarkGenericConfig>::Val>>,

    /// The machine used for proving the wrapping step.
    pub wrap_machine: StarkMachine<OuterSC, WrapAir<<OuterSC as StarkGenericConfig>::Val>>,
}

impl SP1Prover {
    /// Initializes a new [SP1Prover].
    #[instrument(name = "initialize prover", level = "info", skip_all)]
    pub fn new() -> Self {
        let core_machine = RiscvAir::machine(CoreSC::default());

        // Get the recursive verifier and setup the proving and verifying keys.
        let recursion_program = SP1RecursiveVerifier::<InnerConfig, _>::build(&core_machine);
        let reduce_machine = ReduceAir::machine(InnerSC::default());
        let (rec_pk, rec_vk) = reduce_machine.setup(&recursion_program);

        // Get the deferred program and keys.
        let deferred_program = SP1DeferredVerifier::<InnerConfig, _, _>::build(&reduce_machine);
        let (deferred_pk, deferred_vk) = reduce_machine.setup(&deferred_program);

        // Make the reduce program and keys.
        let reduce_program =
            SP1ReduceVerifier::<InnerConfig, _, _>::build(&reduce_machine, &rec_vk, &deferred_vk);
        let (reduce_pk, reduce_vk) = reduce_machine.setup(&reduce_program);

        // Get the compress program, machine, and keys.
        let shrink_program =
            SP1RootVerifier::<InnerConfig, _, _>::build(&reduce_machine, &reduce_vk);
        let shrink_machine = CompressAir::machine(InnerSC::compressed());
        let (shrink_pk, shrink_vk) = shrink_machine.setup(&shrink_program);

        // Get the wrap program, machine, and keys.
        let wrap_program = SP1RootVerifier::<InnerConfig, _, _>::build(&shrink_machine, &shrink_vk);
        let wrap_machine = WrapAir::machine(OuterSC::default());
        let (wrap_pk, wrap_vk) = wrap_machine.setup(&wrap_program);

        Self {
            recursion_program,
            rec_pk,
            rec_vk,
            deferred_program,
            deferred_pk,
            deferred_vk,
            reduce_program,
            reduce_pk,
            reduce_vk,
            shrink_program,
            shrink_pk,
            shrink_vk,
            wrap_program,
            wrap_pk,
            wrap_vk,
            core_machine,
            reduce_machine,
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
        prev_digest: [Val<CoreSC>; DIGEST_SIZE],
        deferred_proofs: &[ShardProof<InnerSC>],
    ) -> [Val<CoreSC>; 8] {
        let mut digest = prev_digest;
        for proof in deferred_proofs.iter() {
            let pv: &RecursionPublicValues<Val<CoreSC>> = proof.public_values.as_slice().borrow();
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
    pub fn prove_core(&self, pk: &SP1ProvingKey, stdin: &SP1Stdin) -> SP1CoreProof {
        let config = CoreSC::default();
        let program = Program::from(&pk.elf);
        let (proof, public_values_stream) = run_and_prove(program, stdin, config);
        let public_values = SP1PublicValues::from(&public_values_stream);
        SP1CoreProof {
            proof: SP1CoreProofData(proof.shard_proofs),
            stdin: stdin.clone(),
            public_values,
        }
    }

    /// Reduce shards proofs to a single shard proof using the recursion prover.
    #[instrument(name = "reduce", level = "info", skip_all)]
    pub fn compress(
        &self,
        vk: &SP1VerifyingKey,
        proof: SP1CoreProof,
        deferred_proofs: Vec<ShardProof<InnerSC>>,
    ) -> SP1ReduceProof<InnerSC> {
        // Set the batch size for the reduction tree.
        let batch_size = 2;

        let shard_proofs = &proof.proof.0;

        // Setup the prover parameters.
        let rc = env::var(RECONSTRUCT_COMMITMENTS_ENV_VAR).unwrap_or_default();
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, "false");

        // Get the and leaf challenger.
        let mut leaf_challenger = self.core_machine.config().challenger();
        vk.vk.observe_into(&mut leaf_challenger);
        shard_proofs.iter().for_each(|proof| {
            leaf_challenger.observe(proof.commitment.main_commit);
            leaf_challenger.observe_slice(&proof.public_values[0..self.core_machine.num_pv_elts()]);
        });
        // Make sure leaf challenger is not mutable anymore.
        let leaf_challenger = leaf_challenger;

        let mut core_inputs = Vec::new();

        let mut reconstruct_challenger = self.core_machine.config().challenger();
        vk.vk.observe_into(&mut reconstruct_challenger);

        // Prepare the inputs for the recursion programs.
        let is_complete = shard_proofs.len() == 1 && deferred_proofs.is_empty();
        for batch in shard_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            core_inputs.push(SP1RecursionMemoryLayout {
                vk: &vk.vk,
                machine: &self.core_machine,
                shard_proofs: proofs,
                leaf_challenger: &leaf_challenger,
                initial_reconstruct_challenger: reconstruct_challenger.clone(),
                is_complete,
            });

            for proof in batch.iter() {
                reconstruct_challenger.observe(proof.commitment.main_commit);
                reconstruct_challenger
                    .observe_slice(&proof.public_values[0..self.core_machine.num_pv_elts()]);
            }
        }

        let last_proof_input =
            PublicValues::from_vec(shard_proofs.last().unwrap().public_values.clone());

        // Check that the leaf challenger is the same as the reconstruct challenger.
        assert_eq!(
            reconstruct_challenger.sponge_state,
            leaf_challenger.sponge_state
        );
        assert_eq!(
            reconstruct_challenger.input_buffer,
            leaf_challenger.input_buffer
        );
        assert_eq!(
            reconstruct_challenger.output_buffer,
            leaf_challenger.output_buffer
        );

        // Prepare the inputs for the deferred proofs recursive verification.
        let mut deferred_digest = [Val::<InnerSC>::zero(); DIGEST_SIZE];
        let mut deferred_inputs = Vec::new();

        let is_deferred_complete = shard_proofs.is_empty() && deferred_proofs.len() == 1;

        for batch in deferred_proofs.chunks(batch_size) {
            let proofs = batch.to_vec();

            deferred_inputs.push(SP1DeferredMemoryLayout {
                reduce_vk: &self.reduce_vk,
                machine: &self.reduce_machine,
                proofs,
                start_reconstruct_deferred_digest: deferred_digest.to_vec(),
                is_complete: is_deferred_complete,
                sp1_vk: &vk.vk,
                sp1_machine: &self.core_machine,
                end_pc: Val::<InnerSC>::zero(),
                end_shard: Val::<InnerSC>::from_canonical_usize(shard_proofs.len()),
                leaf_challenger: leaf_challenger.clone(),
                committed_value_digest: last_proof_input.committed_value_digest.to_vec(),
                deferred_proofs_digest: last_proof_input.deferred_proofs_digest.to_vec(),
            });

            deferred_digest = Self::hash_deferred_proofs(deferred_digest, batch);
        }

        // Run the recursion and reduce programs.

        // Run the recursion programs.
        let mut records = Vec::new();

        for input in core_inputs {
            let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                &self.recursion_program,
                self.reduce_machine.config().perm.clone(),
            );

            let mut witness_stream = Vec::new();
            witness_stream.extend(input.write());

            runtime.witness_stream = witness_stream.into();
            runtime.run();
            runtime.print_stats();

            records.push((runtime.record, ReduceProgramType::Core));
        }

        // Run the deferred proofs programs.
        for input in deferred_inputs {
            let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                &self.deferred_program,
                self.reduce_machine.config().perm.clone(),
            );

            let mut witness_stream = Vec::new();
            witness_stream.extend(input.write());

            runtime.witness_stream = witness_stream.into();
            runtime.run();
            runtime.print_stats();

            records.push((runtime.record, ReduceProgramType::Deferred));
        }

        // Prove all recursion programs and recursion deferred programs and verify the proofs.

        // Make the recursive proofs for core and deferred proofs.
        let time = std::time::Instant::now();
        let first_layer_proofs = records
            .into_par_iter()
            .map(|(record, kind)| {
                let pk = match kind {
                    ReduceProgramType::Core => &self.rec_pk,
                    ReduceProgramType::Deferred => &self.deferred_pk,
                    ReduceProgramType::Reduce => unreachable!(),
                };
                let mut recursive_challenger = self.reduce_machine.config().challenger();
                (
                    self.reduce_machine.prove::<LocalProver<_, _>>(
                        pk,
                        record,
                        &mut recursive_challenger,
                    ),
                    kind,
                )
            })
            .collect::<Vec<_>>();
        let elapsed = time.elapsed();
        tracing::debug!("Recursive first layer proving time: {:?}", elapsed);

        // Verify the recursive proofs.
        for (rec_proof, kind) in first_layer_proofs.iter() {
            let vk = match kind {
                ReduceProgramType::Core => &self.rec_vk,
                ReduceProgramType::Deferred => &self.deferred_vk,
                ReduceProgramType::Reduce => unreachable!(),
            };
            let mut recursive_challenger = self.reduce_machine.config().challenger();
            let result = self
                .reduce_machine
                .verify(vk, rec_proof, &mut recursive_challenger);

            match result {
                Ok(_) => tracing::info!("Proof verified successfully"),
                Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                    tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                }
                e => panic!("Proof verification failed: {:?}", e),
            }
        }

        tracing::info!("Recursive proofs verified successfully");

        // Chain all the individual shard proofs.
        let mut reduce_proofs = first_layer_proofs
            .into_iter()
            .flat_map(|(proof, kind)| proof.shard_proofs.into_iter().map(move |p| (p, kind)))
            .collect::<Vec<_>>();

        // Iterate over the recursive proof batches until there is one proof remaining.
        let mut is_complete;
        let time = std::time::Instant::now();
        loop {
            tracing::debug!("Recursive proof layer size: {}", reduce_proofs.len());
            is_complete = reduce_proofs.len() <= batch_size;
            reduce_proofs = reduce_proofs
                .par_chunks(batch_size)
                .map(|batch| {
                    let (shard_proofs, kinds) =
                        batch.iter().cloned().unzip::<_, _, Vec<_>, Vec<_>>();

                    let input = SP1ReduceMemoryLayout {
                        reduce_vk: &self.reduce_vk,
                        recursive_machine: &self.reduce_machine,
                        shard_proofs,
                        kinds,
                        is_complete,
                    };

                    let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
                        &self.reduce_program,
                        self.reduce_machine.config().perm.clone(),
                    );

                    let mut witness_stream = Vec::new();
                    witness_stream.extend(input.write());

                    runtime.witness_stream = witness_stream.into();
                    runtime.run();
                    runtime.print_stats();

                    let mut recursive_challenger = self.reduce_machine.config().challenger();
                    let mut proof = self.reduce_machine.prove::<LocalProver<_, _>>(
                        &self.reduce_pk,
                        runtime.record,
                        &mut recursive_challenger,
                    );
                    let mut recursive_challenger = self.reduce_machine.config().challenger();
                    let result = self.reduce_machine.verify(
                        &self.reduce_vk,
                        &proof,
                        &mut recursive_challenger,
                    );

                    match result {
                        Ok(_) => tracing::info!("Proof verified successfully"),
                        Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                            tracing::info!("Proof verification failed: NonZeroCumulativeSum")
                        }
                        e => panic!("Proof verification failed: {:?}", e),
                    }

                    assert_eq!(proof.shard_proofs.len(), 1);
                    (proof.shard_proofs.pop().unwrap(), ReduceProgramType::Reduce)
                })
                .collect();

            if reduce_proofs.len() == 1 {
                break;
            }
        }
        let elapsed = time.elapsed();
        tracing::debug!("Reduction successful, time: {:?}", elapsed);

        assert_eq!(reduce_proofs.len(), 1);
        let reduce_proof = reduce_proofs.pop().unwrap();

        // Restore the prover parameters.
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, rc);

        SP1ReduceProof {
            proof: reduce_proof.0,
        }
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "compress", level = "info", skip_all)]
    pub fn shrink(&self, reduced_proof: SP1ReduceProof<InnerSC>) -> SP1ReduceProof<InnerSC> {
        // Setup the prover parameters.
        let rc = env::var(RECONSTRUCT_COMMITMENTS_ENV_VAR).unwrap_or_default();
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, "false");

        // Make the compress proof.
        let input = SP1RootMemoryLayout {
            machine: &self.reduce_machine,
            proof: reduced_proof.proof,
            is_reduce: true,
        };

        // Run the compress program.
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.shrink_program,
            self.shrink_machine.config().perm.clone(),
        );

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();
        runtime.run();
        runtime.print_stats();
        tracing::debug!("Compress program executed successfully");

        // Prove the compress program.
        let mut compress_challenger = self.shrink_machine.config().challenger();

        let mut compress_proof = self.shrink_machine.prove::<LocalProver<_, _>>(
            &self.shrink_pk,
            runtime.record,
            &mut compress_challenger,
        );
        let mut compress_challenger = self.shrink_machine.config().challenger();
        let result =
            self.shrink_machine
                .verify(&self.shrink_vk, &compress_proof, &mut compress_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }

        // Restore the prover parameters.
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, rc);

        SP1ReduceProof {
            proof: compress_proof.shard_proofs.pop().unwrap(),
        }
    }

    /// Wrap a reduce proof into a STARK proven over a SNARK-friendly field.
    #[instrument(name = "wrap_bn254", level = "info", skip_all)]
    pub fn wrap_bn254(&self, compressed_proof: SP1ReduceProof<InnerSC>) -> ShardProof<OuterSC> {
        // Setup the prover parameters.
        let rc = env::var(RECONSTRUCT_COMMITMENTS_ENV_VAR).unwrap_or_default();
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, "false");

        let input = SP1RootMemoryLayout {
            machine: &self.shrink_machine,
            proof: compressed_proof.proof,
            is_reduce: false,
        };

        // Run the compress program.
        let mut runtime = RecursionRuntime::<Val<InnerSC>, Challenge<InnerSC>, _>::new(
            &self.wrap_program,
            self.shrink_machine.config().perm.clone(),
        );

        let mut witness_stream = Vec::new();
        witness_stream.extend(input.write());

        runtime.witness_stream = witness_stream.into();
        runtime.run();
        runtime.print_stats();
        tracing::debug!("Wrap program executed successfully");

        // Prove the wrap program.
        let mut wrap_challenger = self.wrap_machine.config().challenger();
        let time = std::time::Instant::now();
        let mut wrap_proof = self.wrap_machine.prove::<LocalProver<_, _>>(
            &self.wrap_pk,
            runtime.record,
            &mut wrap_challenger,
        );
        let elapsed = time.elapsed();
        tracing::debug!("Wrap proving time: {:?}", elapsed);
        let mut wrap_challenger = self.wrap_machine.config().challenger();
        let result = self
            .wrap_machine
            .verify(&self.wrap_vk, &wrap_proof, &mut wrap_challenger);
        match result {
            Ok(_) => tracing::info!("Proof verified successfully"),
            Err(ProgramVerificationError::NonZeroCumulativeSum) => {
                tracing::info!("Proof verification failed: NonZeroCumulativeSum")
            }
            e => panic!("Proof verification failed: {:?}", e),
        }
        tracing::info!("Wrapping successful");

        // Restore the prover parameters.
        env::set_var(RECONSTRUCT_COMMITMENTS_ENV_VAR, rc);

        wrap_proof.shard_proofs.pop().unwrap()
    }

    /// Wrap the STARK proven over a SNARK-friendly field into a Groth16 proof.
    #[instrument(name = "wrap_groth16", level = "info", skip_all)]
    pub fn wrap_groth16(&self, proof: ShardProof<OuterSC>, build_dir: PathBuf) -> Groth16Proof {
        let pv: &RecursionPublicValues<_> = proof.public_values.as_slice().borrow();

        // TODO: this is very subject to change as groth16 e2e is stabilized
        // Convert pv.vkey_digest to a bn254 field element
        let mut vkey_hash = Bn254Fr::zero();
        for (i, word) in pv.sp1_vk_digest.iter().enumerate() {
            if i == 0 {
                // Truncate top 3 bits
                vkey_hash = Bn254Fr::from_canonical_u32(word.as_canonical_u32() & 0x1fffffffu32);
            } else {
                vkey_hash *= Bn254Fr::from_canonical_u64(1 << 32);
                vkey_hash += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
            }
        }

        // Convert pv.committed_value_digest to a bn254 field element
        let mut committed_values_digest = Bn254Fr::zero();
        for (i, word) in pv.committed_value_digest.iter().enumerate() {
            for (j, byte) in word.0.iter().enumerate() {
                if i == 0 && j == 0 {
                    // Truncate top 3 bits
                    committed_values_digest =
                        Bn254Fr::from_canonical_u32(byte.as_canonical_u32() & 0x1f);
                } else {
                    committed_values_digest *= Bn254Fr::from_canonical_u32(256);
                    committed_values_digest += Bn254Fr::from_canonical_u32(byte.as_canonical_u32());
                }
            }
        }

        let mut witness = Witness::default();
        proof.write(&mut witness);
        witness.commited_values_digest = committed_values_digest;
        witness.vkey_hash = vkey_hash;

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

        tracing::info!("Shrink");
        let shrink_proof = prover.shrink(compressed_proof);

        tracing::info!("wrap bn254");
        let wrapped_bn254_proof = prover.wrap_bn254(shrink_proof);

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
            verify_proof,
            vec![
                deferred_reduce_1.proof,
                deferred_reduce_2.proof.clone(),
                deferred_reduce_2.proof,
            ],
        );
        let reduce_pv: &RecursionPublicValues<_> =
            verify_reduce.proof.public_values.as_slice().borrow();
        println!("deferred_hash: {:?}", reduce_pv.deferred_proofs_digest);
        println!("complete: {:?}", reduce_pv.is_complete);

        let reduced_proof = SP1ReducedProofData(verify_reduce.proof);
        prover.verify_reduced(&reduced_proof, &verify_vk).unwrap();

        std::env::remove_var("RECONSTRUCT_COMMITMENTS");
        std::env::remove_var("SHARD_SIZE");
        std::env::remove_var("MAX_RECURSION_PROGRAM_SIZE");
    }
}
