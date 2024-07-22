use std::collections::VecDeque;
use std::fs::File;
use std::io::Seek;
use std::io::{self};
use std::sync::mpsc::sync_channel;
use std::sync::Arc;
use std::sync::Mutex;
use web_time::Instant;

use p3_challenger::CanObserve;
use p3_maybe_rayon::prelude::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use size::Size;
use std::thread::ScopedJoinHandle;
use thiserror::Error;

pub use baby_bear_blake3::BabyBearBlake3;
use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;

use crate::air::{MachineAir, PublicValues};
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
use crate::utils::concurrency::TurnBasedSync;
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
    let (pk, _) = prover.setup(&program);
    prove_with_context::<SC, _>(&prover, &pk, program, stdin, opts, Default::default())
}

pub fn prove_with_context<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    prover: &P,
    pk: &StarkProvingKey<SC>,
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
    // Setup the runtime.
    let mut runtime = Runtime::with_context(program.clone(), opts, context);
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        runtime.write_proof(proof.0.clone(), proof.1.clone());
    }

    // Record the start of the process.
    let proving_start = Instant::now();
    let span = tracing::Span::current().clone();
    std::thread::scope(move |s| {
        let _span = span.enter();

        // Spawn the checkpoint generator thread.
        let checkpoint_generator_span = tracing::Span::current().clone();
        let (checkpoints_tx, checkpoints_rx) =
            sync_channel::<(usize, File, bool)>(opts.checkpoints_channel_capacity);
        let checkpoint_generator_handle: ScopedJoinHandle<Result<_, SP1CoreProverError>> =
            s.spawn(move || {
                let _span = checkpoint_generator_span.enter();
                tracing::debug_span!("checkpoint generator").in_scope(|| {
                    let mut index = 0;
                    loop {
                        // Enter the span.
                        let span = tracing::debug_span!("batch");
                        let _span = span.enter();

                        // Execute the runtime until we reach a checkpoint.
                        let (checkpoint, done) = runtime
                            .execute_state()
                            .map_err(SP1CoreProverError::ExecutionError)?;

                        // Save the checkpoint to a temp file.
                        let mut checkpoint_file =
                            tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
                        checkpoint
                            .save(&mut checkpoint_file)
                            .map_err(SP1CoreProverError::IoError)?;

                        // Send the checkpoint.
                        checkpoints_tx.send((index, checkpoint_file, done)).unwrap();

                        // If we've reached the final checkpoint, break out of the loop.
                        if done {
                            break Ok(runtime.state.public_values_stream);
                        }

                        // Update the index.
                        index += 1;
                    }
                })
            });

        // Spawn the workers for phase 1 record generation.
        let p1_record_gen_sync = Arc::new(TurnBasedSync::new());
        let p1_trace_gen_sync = Arc::new(TurnBasedSync::new());
        let (p1_records_and_traces_tx, p1_records_and_traces_rx) =
            sync_channel::<(
                Vec<ExecutionRecord>,
                Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>,
            )>(opts.records_and_traces_channel_capacity);
        let p1_records_and_traces_tx = Arc::new(Mutex::new(p1_records_and_traces_tx));
        let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));

        let checkpoints = Arc::new(Mutex::new(VecDeque::new()));
        let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
        let mut p1_record_and_trace_gen_handles = Vec::new();
        for _ in 0..opts.trace_gen_workers {
            let record_gen_sync = Arc::clone(&p1_record_gen_sync);
            let trace_gen_sync = Arc::clone(&p1_trace_gen_sync);
            let checkpoints_rx = Arc::clone(&checkpoints_rx);
            let records_and_traces_tx = Arc::clone(&p1_records_and_traces_tx);

            let checkpoints = Arc::clone(&checkpoints);
            let state = Arc::clone(&state);
            let deferred = Arc::clone(&deferred);
            let program = program.clone();

            let span = tracing::Span::current().clone();
            let handle = s.spawn(move || {
                let _span = span.enter();
                tracing::debug_span!("phase 1 trace generation").in_scope(|| {
                    loop {
                        // Receive the latest checkpoint.
                        let received = { checkpoints_rx.lock().unwrap().recv() };
                        if let Ok((index, mut checkpoint, done)) = received {
                            // Trace the checkpoint and reconstruct the execution records.
                            let (mut records, _) = tracing::debug_span!("trace checkpoint")
                                .in_scope(|| trace_checkpoint(program.clone(), &checkpoint, opts));
                            reset_seek(&mut checkpoint);

                            // Generate the dependencies.
                            tracing::debug_span!("generate dependencies").in_scope(|| {
                                prover.machine().generate_dependencies(&mut records, &opts)
                            });

                            // Wait for our turn to update the state.
                            record_gen_sync.wait_for_turn(index);

                            // Update the public values & prover state for the shards which contain "cpu events".
                            let mut state = state.lock().unwrap();
                            for record in records.iter_mut() {
                                state.shard += 1;
                                state.execution_shard = record.public_values.execution_shard;
                                state.start_pc = record.public_values.start_pc;
                                state.next_pc = record.public_values.next_pc;
                                state.committed_value_digest =
                                    record.public_values.committed_value_digest;
                                state.deferred_proofs_digest =
                                    record.public_values.deferred_proofs_digest;
                                record.public_values = *state;
                            }

                            // Defer events that are too expensive to include in every shard.
                            let mut deferred = deferred.lock().unwrap();
                            for record in records.iter_mut() {
                                deferred.append(&mut record.defer());
                            }

                            // See if any deferred shards are ready to be commited to.
                            let mut deferred = deferred.split(done, opts.split_opts);

                            // Update the public values & prover state for the shards which do not contain "cpu events"
                            // before committing to them.
                            if !done {
                                state.execution_shard += 1;
                            }
                            for record in deferred.iter_mut() {
                                state.shard += 1;
                                state.previous_init_addr_bits =
                                    record.public_values.previous_init_addr_bits;
                                state.last_init_addr_bits =
                                    record.public_values.last_init_addr_bits;
                                state.previous_finalize_addr_bits =
                                    record.public_values.previous_finalize_addr_bits;
                                state.last_finalize_addr_bits =
                                    record.public_values.last_finalize_addr_bits;
                                state.start_pc = state.next_pc;
                                record.public_values = *state;
                            }
                            records.append(&mut deferred);

                            // Collect the checkpoints to be used again in the phase 2 prover.
                            let mut checkpoints = checkpoints.lock().unwrap();
                            checkpoints.push_back((index, checkpoint, done));

                            // Let another worker update the state.
                            record_gen_sync.advance_turn();

                            // Generate the traces.
                            let traces = records
                                .par_iter()
                                .map(|record| prover.generate_traces(record))
                                .collect::<Vec<_>>();

                            trace_gen_sync.wait_for_turn(index);

                            // Send the records to the phase 1 prover.
                            records_and_traces_tx
                                .lock()
                                .unwrap()
                                .send((records, traces))
                                .unwrap();

                            trace_gen_sync.advance_turn();
                        } else {
                            break;
                        }
                    }
                })
            });
            p1_record_and_trace_gen_handles.push(handle);
        }
        drop(p1_records_and_traces_tx);

        // Create the challenger and observe the verifying key.
        let mut challenger = prover.config().challenger();
        challenger.observe(pk.commit.clone());
        challenger.observe(pk.pc_start);

        // Spawn the phase 1 prover thread.
        let phase_1_prover_span = tracing::Span::current().clone();
        let phase_1_prover_handle = s.spawn(move || {
            let _span = phase_1_prover_span.enter();
            tracing::debug_span!("phase 1 prover").in_scope(|| {
                for (records, traces) in p1_records_and_traces_rx.iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        // Commit to the traces.
                        let span = tracing::Span::current().clone();
                        let commitments = records
                            .par_iter()
                            .zip(traces.into_par_iter())
                            .map(|(record, traces)| {
                                let _span = span.enter();
                                prover.commit(record, traces)
                            })
                            .collect::<Vec<_>>();

                        // Update the challenger.
                        for (commit, record) in commitments.into_iter().zip(records) {
                            prover.update(
                                &mut challenger,
                                commit,
                                &record.public_values::<SC::Val>()
                                    [0..prover.machine().num_pv_elts()],
                            );
                        }
                    });
                }
            });

            challenger
        });

        // Wait until the checkpoint generator handle has fully finished.
        let public_values_stream = checkpoint_generator_handle.join().unwrap().unwrap();

        // Wait until the records and traces have been fully generated.
        p1_record_and_trace_gen_handles
            .into_iter()
            .for_each(|handle| handle.join().unwrap());

        // Wait until the phase 1 prover has completely finished.
        let challenger = phase_1_prover_handle.join().unwrap();

        // Spawn the phase 2 record generator thread.
        let p2_record_gen_sync = Arc::new(TurnBasedSync::new());
        let p2_trace_gen_sync = Arc::new(TurnBasedSync::new());
        let (p2_records_and_traces_tx, p2_records_and_traces_rx) =
            sync_channel::<(
                Vec<ExecutionRecord>,
                Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>,
            )>(opts.records_and_traces_channel_capacity);
        let p2_records_and_traces_tx = Arc::new(Mutex::new(p2_records_and_traces_tx));

        let report_aggregate = Arc::new(Mutex::new(ExecutionReport::default()));
        let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
        let mut p2_record_and_trace_gen_handles = Vec::new();
        for _ in 0..opts.trace_gen_workers {
            let record_gen_sync = Arc::clone(&p2_record_gen_sync);
            let trace_gen_sync = Arc::clone(&p2_trace_gen_sync);
            let records_and_traces_tx = Arc::clone(&p2_records_and_traces_tx);

            let report_aggregate = Arc::clone(&report_aggregate);
            let checkpoints = Arc::clone(&checkpoints);
            let state = Arc::clone(&state);
            let deferred = Arc::clone(&deferred);
            let program = program.clone();

            let span = tracing::Span::current().clone();
            let handle = s.spawn(move || {
                let _span = span.enter();
                tracing::debug_span!("phase 2 trace generation").in_scope(|| {
                    loop {
                        // Receive the latest checkpoint.
                        let received = { checkpoints.lock().unwrap().pop_front() };
                        if let Some((index, mut checkpoint, done)) = received {
                            // Trace the checkpoint and reconstruct the execution records.
                            let (mut records, report) = tracing::debug_span!("trace checkpoint")
                                .in_scope(|| trace_checkpoint(program.clone(), &checkpoint, opts));
                            *report_aggregate.lock().unwrap() += report;
                            reset_seek(&mut checkpoint);

                            // Generate the dependencies.
                            tracing::debug_span!("generate dependencies").in_scope(|| {
                                prover.machine().generate_dependencies(&mut records, &opts)
                            });

                            // Wait for our turn to update the state.
                            record_gen_sync.wait_for_turn(index);

                            // Update the public values & prover state for the shards which contain "cpu events".
                            let mut state = state.lock().unwrap();
                            for record in records.iter_mut() {
                                state.shard += 1;
                                state.execution_shard = record.public_values.execution_shard;
                                state.start_pc = record.public_values.start_pc;
                                state.next_pc = record.public_values.next_pc;
                                state.committed_value_digest =
                                    record.public_values.committed_value_digest;
                                state.deferred_proofs_digest =
                                    record.public_values.deferred_proofs_digest;
                                record.public_values = *state;
                            }

                            // Defer events that are too expensive to include in every shard.
                            let mut deferred = deferred.lock().unwrap();
                            for record in records.iter_mut() {
                                deferred.append(&mut record.defer());
                            }

                            // See if any deferred shards are ready to be commited to.
                            let mut deferred = deferred.split(done, opts.split_opts);

                            // Update the public values & prover state for the shards which do not contain "cpu events"
                            // before committing to them.
                            if !done {
                                state.execution_shard += 1;
                            }
                            for record in deferred.iter_mut() {
                                state.shard += 1;
                                state.previous_init_addr_bits =
                                    record.public_values.previous_init_addr_bits;
                                state.last_init_addr_bits =
                                    record.public_values.last_init_addr_bits;
                                state.previous_finalize_addr_bits =
                                    record.public_values.previous_finalize_addr_bits;
                                state.last_finalize_addr_bits =
                                    record.public_values.last_finalize_addr_bits;
                                state.start_pc = state.next_pc;
                                record.public_values = *state;
                            }
                            records.append(&mut deferred);

                            // Let another worker update the state.
                            record_gen_sync.advance_turn();

                            // Generate the traces.
                            let traces = records
                                .par_iter()
                                .map(|record| prover.generate_traces(record))
                                .collect::<Vec<_>>();

                            trace_gen_sync.wait_for_turn(index);

                            // Send the records to the phase 1 prover.
                            records_and_traces_tx
                                .lock()
                                .unwrap()
                                .send((records, traces))
                                .unwrap();

                            trace_gen_sync.advance_turn();
                        } else {
                            break;
                        }
                    }
                })
            });
            p2_record_and_trace_gen_handles.push(handle);
        }
        drop(p2_records_and_traces_tx);

        // Spawn the phase 2 prover thread.
        let p2_prover_span = tracing::Span::current().clone();
        let p2_prover_handle = s.spawn(move || {
            let _span = p2_prover_span.enter();
            let mut shard_proofs = Vec::new();
            tracing::debug_span!("phase 2 prover").in_scope(|| {
                for (records, traces) in p2_records_and_traces_rx.into_iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();
                        shard_proofs.par_extend(
                            records.into_par_iter().zip(traces.into_par_iter()).map(
                                |(record, trace)| {
                                    let _span = span.enter();
                                    prover
                                        .commit_and_open(pk, record, trace, &mut challenger.clone())
                                        .unwrap()
                                },
                            ),
                        );
                    });
                }
            });
            shard_proofs
        });

        // Wait until the records and traces have been fully generated for phase 2.
        p2_record_and_trace_gen_handles
            .into_iter()
            .for_each(|handle| handle.join().unwrap());

        // Wait until the phase 2 prover has finished.
        let shard_proofs = p2_prover_handle.join().unwrap();

        // Log some of the `ExecutionReport` information.
        let report_aggregate = report_aggregate.lock().unwrap();
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
        let cycles = report_aggregate.total_instruction_count();

        // Print the summary.
        let proving_time = proving_start.elapsed().as_secs_f64();
        tracing::info!(
            "summary: cycles={}, e2e={}s, khz={:.2}, proofSize={}",
            cycles,
            proving_time,
            (cycles as f64 / (proving_time * 1000.0) as f64),
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
    let (pk, _) = prover.setup(runtime.program.as_ref());
    let (proof, output, _) = prove_with_context(
        &prover,
        &pk,
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
