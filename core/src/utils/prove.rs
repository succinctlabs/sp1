use std::fs::File;
use std::io::Seek;
use std::io::{self};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use web_time::Instant;

use p3_maybe_rayon::prelude::*;

use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;
use thiserror::Error;

pub use baby_bear_blake3::BabyBearBlake3;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;

use crate::air::MachineAir;
use crate::io::{SP1PublicValues, SP1Stdin};
use crate::lookup::InteractionBuilder;
use crate::runtime::{ExecutionError, NoOpSubproofVerifier, SP1Context};
use crate::runtime::{ExecutionRecord, ExecutionReport};
use crate::stark::DebugConstraintBuilder;
use crate::stark::MachineProof;
use crate::stark::MachineProver;
use crate::stark::ProverConstraintFolder;
use crate::stark::StarkVerifyingKey;
use crate::stark::Val;
use crate::stark::VerifierConstraintFolder;
use crate::stark::{Com, PcsProverData, RiscvAir, StarkProvingKey, UniConfig};
use crate::stark::{MachineRecord, StarkMachine};
use crate::utils::SP1CoreOpts;
use crate::{
    runtime::{Program, Runtime},
    stark::StarkGenericConfig,
    stark::{DefaultProver, OpeningProof, ShardMainData},
};

const LOG_DEGREE_BOUND: usize = 31;

#[derive(Error, Debug)]
pub enum SP1CoreProverError {
    #[error("failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("io error: {0}")]
    IoError(io::Error),
    #[error("serialization error: {0}")]
    SerializationError(bincode::Error),
}

pub fn prove_simple<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    config: SC,
    mut runtime: Runtime,
) -> Result<(MachineProof<SC>, u64), SP1CoreProverError>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    // Setup the machine.
    let machine = RiscvAir::machine(config);
    let prover = P::new(machine);
    let (pk, _) = prover.setup(runtime.program.as_ref());

    // Set the shard numbers.
    runtime
        .records
        .iter_mut()
        .enumerate()
        .for_each(|(i, shard)| {
            shard.public_values.shard = (i + 1) as u32;
        });

    // Prove the program.
    let mut challenger = prover.config().challenger();
    let proving_start = Instant::now();
    let proof = prover
        .prove(
            &pk,
            runtime.records,
            &mut challenger,
            SP1CoreOpts::default(),
        )
        .unwrap();
    let proving_duration = proving_start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    // Print the summary.
    tracing::info!(
        "summary: cycles={}, e2e={}, khz={:.2}, proofSize={}",
        runtime.state.global_clk,
        proving_duration,
        (runtime.state.global_clk as f64 / proving_duration as f64),
        Size::from_bytes(nb_bytes),
    );

    Ok((proof, runtime.state.global_clk))
}

pub fn prove<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    program: Program,
    stdin: &SP1Stdin,
    config: SC,
    opts: SP1CoreOpts,
) -> Result<(MachineProof<SC>, Vec<u8>, u64), SP1CoreProverError>
where
    SC::Challenger: 'static + Clone + Send,
    <SC as StarkGenericConfig>::Val: PrimeField32,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    let machine = RiscvAir::machine(config);
    let prover = P::new(machine);
    prove_with_context::<SC, _>(&prover, program, stdin, opts, Default::default())
}

pub fn prove_with_context<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    prover: &P,
    program: Program,
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
) -> Result<(MachineProof<SC>, Vec<u8>, u64), SP1CoreProverError>
where
    SC::Val: PrimeField32,
    SC::Challenger: 'static + Clone + Send,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    // Record the start of the process.
    let proving_start = Instant::now();

    // Execute the program.
    let mut runtime = Runtime::with_context(program.clone(), opts, context);
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    // Setup the machine.
    let (pk, vk) = prover.setup(runtime.program.as_ref());

    // Execute the program, saving checkpoints at the start of every `shard_batch_size` cycle range.
    let create_checkpoints_span = tracing::debug_span!("create checkpoints").entered();
    let mut checkpoints = Vec::new();
    let (public_values_stream, public_values) = loop {
        // Execute the runtime until we reach a checkpoint.
        let (checkpoint, done) = runtime
            .execute_state()
            .map_err(SP1CoreProverError::ExecutionError)?;

        // Save the checkpoint to a temp file.
        let mut checkpoint_file = tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
        checkpoint
            .save(&mut checkpoint_file)
            .map_err(SP1CoreProverError::IoError)?;
        checkpoints.push(checkpoint_file);

        // If we've reached the final checkpoint, break out of the loop.
        if done {
            break (
                runtime.state.public_values_stream,
                runtime
                    .records
                    .last()
                    .expect("at least one record")
                    .public_values,
            );
        }
    };
    create_checkpoints_span.exit();

    // Commit to the shards.
    #[cfg(debug_assertions)]
    let mut debug_records: Vec<ExecutionRecord> = Vec::new();

    let mut deferred = ExecutionRecord::new(program.clone().into());
    let mut state = public_values.reset();
    let nb_checkpoints = checkpoints.len();
    let mut challenger = prover.config().challenger();
    vk.observe_into(&mut challenger);

    let scope_span = tracing::Span::current().clone();
    std::thread::scope(move |s| {
        let _span = scope_span.enter();

        // Spawn a thread for commiting to the shards.
        let span = tracing::Span::current().clone();
        let (records_tx, records_rx) =
            sync_channel::<Vec<ExecutionRecord>>(opts.commit_stream_capacity);
        let challenger_handle = s.spawn(move || {
            let _span = span.enter();
            tracing::debug_span!("phase 1 commiter").in_scope(|| {
                for records in records_rx.iter() {
                    let commitments = tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();
                        records
                            .par_iter()
                            .map(|record| {
                                let _span = span.enter();
                                prover.commit(record)
                            })
                            .collect::<Vec<_>>()
                    });
                    for (commit, record) in commitments.into_iter().zip(records) {
                        prover.update(
                            &mut challenger,
                            commit,
                            &record.public_values::<SC::Val>()[0..prover.machine().num_pv_elts()],
                        );
                    }
                }
            });

            challenger
        });

        tracing::debug_span!("phase 1 record generator").in_scope(|| {
            for (checkpoint_idx, checkpoint_file) in checkpoints.iter_mut().enumerate() {
                // Trace the checkpoint and reconstruct the execution records.
                let (mut records, _) = tracing::debug_span!("trace checkpoint")
                    .in_scope(|| trace_checkpoint(program.clone(), checkpoint_file, opts));
                reset_seek(&mut *checkpoint_file);

                // Update the public values & prover state for the shards which contain "cpu events".
                for record in records.iter_mut() {
                    state.shard += 1;
                    state.execution_shard = record.public_values.execution_shard;
                    state.start_pc = record.public_values.start_pc;
                    state.next_pc = record.public_values.next_pc;
                    record.public_values = state;
                }

                // Generate the dependencies.
                tracing::debug_span!("generate dependencies")
                    .in_scope(|| prover.machine().generate_dependencies(&mut records, &opts));

                // Defer events that are too expensive to include in every shard.
                for record in records.iter_mut() {
                    deferred.append(&mut record.defer());
                }

                // See if any deferred shards are ready to be commited to.
                let is_last_checkpoint = checkpoint_idx == nb_checkpoints - 1;
                let mut deferred = deferred.split(is_last_checkpoint, opts.split_opts);

                // Update the public values & prover state for the shards which do not contain "cpu events"
                // before committing to them.
                if !is_last_checkpoint {
                    state.execution_shard += 1;
                }
                for record in deferred.iter_mut() {
                    state.shard += 1;
                    state.previous_init_addr_bits = record.public_values.previous_init_addr_bits;
                    state.last_init_addr_bits = record.public_values.last_init_addr_bits;
                    state.previous_finalize_addr_bits =
                        record.public_values.previous_finalize_addr_bits;
                    state.last_finalize_addr_bits = record.public_values.last_finalize_addr_bits;
                    state.start_pc = state.next_pc;
                    record.public_values = state;
                }
                records.append(&mut deferred);

                #[cfg(debug_assertions)]
                {
                    debug_records.extend(records.clone());
                }

                records_tx.send(records).unwrap();
            }
        });
        drop(records_tx);
        let challenger = challenger_handle.join().unwrap();

        // Debug the constraints if debug assertions are enabled.
        #[cfg(debug_assertions)]
        {
            let mut challenger = prover.config().challenger();
            prover.debug_constraints(&pk, debug_records, &mut challenger);
        }

        // Prove the shards.
        let mut deferred = ExecutionRecord::new(program.clone().into());
        let mut state = public_values.reset();
        let mut report_aggregate = ExecutionReport::default();

        // Spawn a thread for proving the shards.
        let (records_tx, records_rx) =
            sync_channel::<Vec<ExecutionRecord>>(opts.prove_stream_capacity);

        let commit_and_open = tracing::Span::current().clone();
        let shard_proofs = s.spawn(move || {
            let _span = commit_and_open.enter();
            let mut shard_proofs = Vec::new();
            tracing::debug_span!("phase 2 prover").in_scope(|| {
                for records in records_rx.iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();
                        shard_proofs.par_extend(records.into_par_iter().map(|record| {
                            let _span = span.enter();
                            prover
                                .commit_and_open(&pk, record, &mut challenger.clone())
                                .unwrap()
                        }));
                    });
                }
            });
            shard_proofs
        });

        tracing::debug_span!("phase 2 record generator").in_scope(|| {
            for (checkpoint_idx, mut checkpoint_file) in checkpoints.into_iter().enumerate() {
                // Trace the checkpoint and reconstruct the execution records.
                let (mut records, report) = tracing::debug_span!("trace checkpoint")
                    .in_scope(|| trace_checkpoint(program.clone(), &checkpoint_file, opts));
                report_aggregate += report;
                reset_seek(&mut checkpoint_file);

                // Update the public values & prover state for the shards which contain "cpu events".
                for record in records.iter_mut() {
                    state.shard += 1;
                    state.execution_shard = record.public_values.execution_shard;
                    state.start_pc = record.public_values.start_pc;
                    state.next_pc = record.public_values.next_pc;
                    record.public_values = state;
                }

                // Generate the dependencies.
                tracing::debug_span!("generate dependencies")
                    .in_scope(|| prover.machine().generate_dependencies(&mut records, &opts));

                // Defer events that are too expensive to include in every shard.
                for record in records.iter_mut() {
                    deferred.append(&mut record.defer());
                }

                // See if any deferred shards are ready to be commited to.
                let is_last_checkpoint = checkpoint_idx == nb_checkpoints - 1;
                let mut deferred = deferred.split(is_last_checkpoint, opts.split_opts);

                // Update the public values & prover state for the shards which do not contain "cpu events"
                // before committing to them.
                if !is_last_checkpoint {
                    state.execution_shard += 1;
                }
                for record in deferred.iter_mut() {
                    state.shard += 1;
                    state.previous_init_addr_bits = record.public_values.previous_init_addr_bits;
                    state.last_init_addr_bits = record.public_values.last_init_addr_bits;
                    state.previous_finalize_addr_bits =
                        record.public_values.previous_finalize_addr_bits;
                    state.last_finalize_addr_bits = record.public_values.last_finalize_addr_bits;
                    state.start_pc = state.next_pc;
                    record.public_values = state;
                }
                records.append(&mut deferred);

                records_tx.send(records).unwrap();
            }
        });
        drop(records_tx);
        let shard_proofs = shard_proofs.join().unwrap();

        // Log some of the `ExecutionReport` information.
        tracing::info!(
            "execution report (totals): total_cycles={}, total_syscall_cycles={}",
            report_aggregate.total_instruction_count(),
            report_aggregate.total_syscall_count()
        );

        // Print the opcode and syscall count tables like `du`: sorted by count (descending) and with
        // the count in the first column.
        tracing::info!("execution report (opcode counts):");
        for line in ExecutionReport::sorted_table_lines(&report_aggregate.opcode_counts) {
            tracing::info!("  {line}");
        }
        tracing::info!("execution report (syscall counts):");
        for line in ExecutionReport::sorted_table_lines(&report_aggregate.syscall_counts) {
            tracing::info!("  {line}");
        }

        let proof = MachineProof::<SC> { shard_proofs };
        let cycles = runtime.state.global_clk;

        // Print the summary.
        let proving_time = proving_start.elapsed().as_secs_f64();
        tracing::info!(
            "summary: cycles={}, e2e={}s, khz={:.2}, proofSize={}",
            cycles,
            proving_time,
            (runtime.state.global_clk as f64 / (proving_time * 1000.0) as f64),
            bincode::serialize(&proof).unwrap().len(),
        );

        Ok((proof, public_values_stream, cycles))
    })
}

/// Runs a program and returns the public values stream.
pub fn run_test_io<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    program: Program,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, crate::stark::MachineVerificationError<BabyBearPoseidon2>> {
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);
    let _ = run_test_core::<P>(runtime, inputs)?;
    Ok(public_values)
}

pub fn run_test<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    program: Program,
) -> Result<
    crate::stark::MachineProof<BabyBearPoseidon2>,
    crate::stark::MachineVerificationError<BabyBearPoseidon2>,
> {
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
        runtime
    });
    run_test_core::<P>(runtime, SP1Stdin::new())
}

#[allow(unused_variables)]
pub fn run_test_core<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    runtime: Runtime,
    inputs: SP1Stdin,
) -> Result<
    crate::stark::MachineProof<BabyBearPoseidon2>,
    crate::stark::MachineVerificationError<BabyBearPoseidon2>,
> {
    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let prover = P::new(machine);
    let (proof, output, _) = prove_with_context(
        &prover,
        Program::clone(&runtime.program),
        &inputs,
        SP1CoreOpts::default(),
        SP1Context::default(),
    )
    .unwrap();

    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let mut challenger = machine.config().challenger();
    machine.verify(&vk, &proof, &mut challenger).unwrap();

    Ok(proof)
}

#[allow(unused_variables)]
pub fn run_test_machine<SC, A>(
    records: Vec<A::Record>,
    machine: StarkMachine<SC, A>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
) -> Result<crate::stark::MachineProof<SC>, crate::stark::MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<InteractionBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    A::Record: MachineRecord<Config = SP1CoreOpts>,
    SC: StarkGenericConfig,
    SC::Val: p3_field::PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    OpeningProof<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
{
    let start = Instant::now();
    let prover = DefaultProver::new(machine);
    let mut challenger = prover.config().challenger();
    let proof = prover
        .prove(&pk, records, &mut challenger, SP1CoreOpts::default())
        .unwrap();
    let time = start.elapsed().as_millis();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = prover.config().challenger();
    prover.machine().verify(&vk, &proof, &mut challenger)?;

    Ok(proof)
}

fn trace_checkpoint(
    program: Program,
    file: &File,
    opts: SP1CoreOpts,
) -> (Vec<ExecutionRecord>, ExecutionReport) {
    let mut reader = std::io::BufReader::new(file);
    let state = bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Runtime::recover(program.clone(), state, opts);
    // We already passed the deferred proof verifier when creating checkpoints, so the proofs were
    // already verified. So here we use a noop verifier to not print any warnings.
    runtime.subproof_verifier = Arc::new(NoOpSubproofVerifier);
    let (events, _) = runtime.execute_record().unwrap();
    (events, runtime.report)
}

fn reset_seek(file: &mut File) {
    file.seek(std::io::SeekFrom::Start(0))
        .expect("failed to seek to start of tempfile");
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, challenger, trace, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_prove<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    trace: RowMajorMatrix<SC::Val>,
) -> Proof<UniConfig<SC>>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::ProverConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::prove(&UniConfig(config.clone()), air, challenger, trace, &vec![])
}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>
        + for<'a> Air<p3_uni_stark::DebugConstraintBuilder<'a, SC::Val>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, challenger, proof, &vec![])
}

#[cfg(not(debug_assertions))]
pub fn uni_stark_verify<SC, A>(
    config: &SC,
    air: &A,
    challenger: &mut SC::Challenger,
    proof: &Proof<UniConfig<SC>>,
) -> Result<(), p3_uni_stark::VerificationError>
where
    SC: StarkGenericConfig,
    A: Air<p3_uni_stark::SymbolicAirBuilder<SC::Val>>
        + for<'a> Air<p3_uni_stark::VerifierConstraintFolder<'a, UniConfig<SC>>>,
{
    p3_uni_stark::verify(&UniConfig(config.clone()), air, challenger, proof, &vec![])
}

pub use baby_bear_keccak::BabyBearKeccak;
pub use baby_bear_poseidon2::BabyBearPoseidon2;
use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;

pub mod baby_bear_poseidon2 {

    use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::{extension::BinomialExtensionField, Field};
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::Poseidon2;
    use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use serde::{Deserialize, Serialize};
    use sp1_primitives::RC_16_30;

    use crate::stark::StarkGenericConfig;

    pub type Val = BabyBear;
    pub type Challenge = BinomialExtensionField<Val, 4>;

    pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
    pub type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    pub type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        8,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    pub type Dft = Radix2DitParallel;
    pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    pub fn my_perm() -> Perm {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 13;
        let mut round_constants = RC_16_30.to_vec();
        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = round_constants;
        Perm::new(
            ROUNDS_F,
            external_round_constants,
            Poseidon2ExternalMatrixGeneral,
            ROUNDS_P,
            internal_round_constants,
            DiffusionMatrixBabyBear,
        )
    }

    pub fn default_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 100,
        };
        FriConfig {
            log_blowup: 1,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    pub fn compressed_fri_config() -> FriConfig<ChallengeMmcs> {
        let perm = my_perm();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let challenge_mmcs = ChallengeMmcs::new(ValMmcs::new(hash, compress));
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(value) => value.parse().unwrap(),
            Err(_) => 33,
        };
        FriConfig {
            log_blowup: 3,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        }
    }

    enum BabyBearPoseidon2Type {
        Default,
        Compressed,
    }

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearPoseidon2>")]
    pub struct BabyBearPoseidon2 {
        pub perm: Perm,
        pcs: Pcs,
        config_type: BabyBearPoseidon2Type,
    }

    impl BabyBearPoseidon2 {
        pub fn new() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress);
            let dft = Dft {};
            let fri_config = default_fri_config();
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
            Self {
                pcs,
                perm,
                config_type: BabyBearPoseidon2Type::Default,
            }
        }

        pub fn compressed() -> Self {
            let perm = my_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm.clone());
            let val_mmcs = ValMmcs::new(hash, compress);
            let dft = Dft {};
            let fri_config = compressed_fri_config();
            let pcs = Pcs::new(27, dft, val_mmcs, fri_config);
            Self {
                pcs,
                perm,
                config_type: BabyBearPoseidon2Type::Compressed,
            }
        }
    }

    impl Clone for BabyBearPoseidon2 {
        fn clone(&self) -> Self {
            match self.config_type {
                BabyBearPoseidon2Type::Default => Self::new(),
                BabyBearPoseidon2Type::Compressed => Self::compressed(),
            }
        }
    }

    impl Default for BabyBearPoseidon2 {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Implement serialization manually instead of using serde to avoid cloing the config.
    impl Serialize for BabyBearPoseidon2 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearPoseidon2>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearPoseidon2>> for BabyBearPoseidon2 {
        fn from(_: std::marker::PhantomData<BabyBearPoseidon2>) -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearPoseidon2 {
        type Val = BabyBear;
        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;
        type Pcs = Pcs;
        type Challenge = Challenge;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            Challenger::new(self.perm.clone())
        }
    }
}

pub(super) mod baby_bear_keccak {

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::LOG_DEGREE_BOUND;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearKeccak>")]
    pub struct BabyBearKeccak {
        pcs: Pcs,
    }
    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearKeccak {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<BabyBearKeccak>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearKeccak>> for BabyBearKeccak {
        fn from(_: std::marker::PhantomData<BabyBearKeccak>) -> Self {
            Self::new()
        }
    }

    impl BabyBearKeccak {
        #[allow(dead_code)]
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries: 100,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(LOG_DEGREE_BOUND, dft, val_mmcs, fri_config);

            Self { pcs }
        }
    }

    impl Default for BabyBearKeccak {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearKeccak {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearKeccak {
        type Val = Val;
        type Challenge = Challenge;

        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            let byte_hash = ByteHash {};
            Challenger::from_hasher(vec![], byte_hash)
        }
    }
}

pub(super) mod baby_bear_blake3 {

    use p3_baby_bear::BabyBear;
    use p3_blake3::Blake3;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriConfig, TwoAdicFriPcs};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
    use serde::{Deserialize, Serialize};

    use crate::stark::StarkGenericConfig;

    use super::LOG_DEGREE_BOUND;

    pub type Val = BabyBear;

    pub type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Blake3;
    type FieldHash = SerializingHasher32<ByteHash>;

    type MyCompress = CompressionFunctionFromHasher<u8, ByteHash, 2, 32>;

    pub type ValMmcs = FieldMerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

    pub type Dft = Radix2DitParallel;

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

    #[derive(Deserialize)]
    #[serde(from = "std::marker::PhantomData<BabyBearBlake3>")]
    pub struct BabyBearBlake3 {
        pcs: Pcs,
    }

    // Implement serialization manually instead of using serde(into) to avoid cloing the config
    impl Serialize for BabyBearBlake3 {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            std::marker::PhantomData::<Self>.serialize(serializer)
        }
    }

    impl From<std::marker::PhantomData<BabyBearBlake3>> for BabyBearBlake3 {
        fn from(_: std::marker::PhantomData<BabyBearBlake3>) -> Self {
            Self::new()
        }
    }

    impl Clone for BabyBearBlake3 {
        fn clone(&self) -> Self {
            Self::new()
        }
    }

    impl BabyBearBlake3 {
        pub fn new() -> Self {
            let byte_hash = ByteHash {};
            let field_hash = FieldHash::new(byte_hash);

            let compress = MyCompress::new(byte_hash);

            let val_mmcs = ValMmcs::new(field_hash, compress);

            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft {};

            let num_queries = match std::env::var("FRI_QUERIES") {
                Ok(value) => value.parse().unwrap(),
                Err(_) => 100,
            };
            let fri_config = FriConfig {
                log_blowup: 1,
                num_queries,
                proof_of_work_bits: 16,
                mmcs: challenge_mmcs,
            };
            let pcs = Pcs::new(LOG_DEGREE_BOUND, dft, val_mmcs, fri_config);

            Self { pcs }
        }
    }

    impl Default for BabyBearBlake3 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl StarkGenericConfig for BabyBearBlake3 {
        type Val = Val;
        type Challenge = Challenge;

        type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;

        type Pcs = Pcs;
        type Challenger = Challenger;

        fn pcs(&self) -> &Self::Pcs {
            &self.pcs
        }

        fn challenger(&self) -> Self::Challenger {
            let byte_hash = ByteHash {};
            Challenger::from_hasher(vec![], byte_hash)
        }
    }
}
