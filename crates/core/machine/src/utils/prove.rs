use std::{
    collections::VecDeque,
    fs::File,
    io::{
        Seek, {self},
    },
    sync::{mpsc::sync_channel, Arc, Mutex},
};
use web_time::Instant;

use crate::riscv::{CoreShapeConfig, RiscvAir};
use p3_challenger::FieldChallenger;
use p3_maybe_rayon::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use size::Size;
use sp1_stark::{
    air::InteractionScope, baby_bear_poseidon2::BabyBearPoseidon2, MachineProvingKey,
    MachineVerificationError,
};
use std::thread::ScopedJoinHandle;
use thiserror::Error;

use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_matrix::Matrix;

use crate::{
    io::SP1Stdin,
    riscv::cost::CostEstimator,
    utils::{chunk_vec, concurrency::TurnBasedSync},
};
use sp1_core_executor::{events::sorted_table_lines, ExecutionState};
use sp1_primitives::io::SP1PublicValues;

use sp1_core_executor::{
    subproof::NoOpSubproofVerifier, ExecutionError, ExecutionRecord, ExecutionReport, Executor,
    Program, SP1Context,
};
use sp1_stark::{
    air::{MachineAir, PublicValues},
    Com, CpuProver, DebugConstraintBuilder, InteractionBuilder, MachineProof, MachineProver,
    MachineRecord, OpeningProof, PcsProverData, ProverConstraintFolder, SP1CoreOpts,
    StarkGenericConfig, StarkMachine, StarkProvingKey, StarkVerifyingKey, UniConfig, Val,
    VerifierConstraintFolder,
};

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
    mut runtime: Executor,
) -> Result<(MachineProof<SC>, u64), SP1CoreProverError>
where
    SC::Challenger: Clone,
    OpeningProof<SC>: Send + Sync,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    // ShardMainData<SC>: Serialize + DeserializeOwned,
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    // Setup the machine.
    let machine = RiscvAir::machine(config);
    let prover = P::new(machine);
    let (pk, _) = prover.setup(runtime.program.as_ref());

    // Set the shard numbers.
    runtime.records.iter_mut().enumerate().for_each(|(i, shard)| {
        shard.public_values.shard = (i + 1) as u32;
    });

    // Prove the program.
    let mut challenger = prover.config().challenger();
    let proving_start = Instant::now();
    let proof =
        prover.prove(&pk, runtime.records, &mut challenger, SP1CoreOpts::default()).unwrap();
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
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
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
    prove_with_context::<SC, _>(
        &prover,
        &pk,
        program,
        stdin,
        opts,
        Default::default(),
        shape_config,
    )
}

pub fn prove_with_context<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    prover: &P,
    pk: &P::DeviceProvingKey,
    program: Program,
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
) -> Result<(MachineProof<SC>, Vec<u8>, u64), SP1CoreProverError>
where
    SC::Val: PrimeField32,
    SC::Challenger: 'static + Clone + Send,
    OpeningProof<SC>: Send,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    // Setup the runtime.
    let mut runtime = Executor::with_context(program.clone(), opts, context);
    runtime.maximal_shapes = shape_config
        .map(|config| config.maximal_core_shapes().into_iter().map(|s| s.inner).collect());
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        let (proof, vk) = proof.clone();
        runtime.write_proof(proof, vk);
    }

    #[cfg(feature = "debug")]
    let (all_records_tx, all_records_rx) = std::sync::mpsc::channel::<Vec<ExecutionRecord>>();

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
                        let (checkpoint, done) =
                            runtime.execute_state().map_err(SP1CoreProverError::ExecutionError)?;

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
            sync_channel::<(Vec<ExecutionRecord>, Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>)>(
                opts.records_and_traces_channel_capacity,
            );
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
                                .in_scope(|| {
                                    trace_checkpoint::<SC>(
                                        program.clone(),
                                        &checkpoint,
                                        opts,
                                        shape_config,
                                    )
                                });
                            log::info!("generated {} records", records.len());
                            reset_seek(&mut checkpoint);

                            // Wait for our turn to update the state.
                            log::info!("waiting for turn {}", index);
                            record_gen_sync.wait_for_turn(index);

                            // Update the public values & prover state for the shards which contain
                            // "cpu events".
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

                            // See if any deferred shards are ready to be committed to.
                            let mut deferred = deferred.split(done, opts.split_opts);
                            log::info!("deferred {} records", deferred.len());

                            // Update the public values & prover state for the shards which do not
                            // contain "cpu events" before committing to them.
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
                            log::info!("collecting checkpoints");
                            let mut checkpoints = checkpoints.lock().unwrap();
                            checkpoints.push_back((index, checkpoint, done));

                            // Let another worker update the state.
                            record_gen_sync.advance_turn();

                            // Fix the shape of the records.
                            if let Some(shape_config) = shape_config {
                                for record in records.iter_mut() {
                                    tracing::info!("fixing shape");
                                    shape_config.fix_shape(record).unwrap();
                                }
                            }

                            // Generate the traces.
                            let mut traces = vec![];
                            tracing::debug_span!("generate traces", index).in_scope(|| {
                                traces = records
                                    .par_iter()
                                    .map(|record| {
                                        prover.generate_traces(record, InteractionScope::Global)
                                    })
                                    .collect::<Vec<_>>();
                            });

                            // Wait for our turn.
                            trace_gen_sync.wait_for_turn(index);

                            // Send the records to the phase 1 prover.
                            let chunked_records = chunk_vec(records, opts.shard_batch_size);
                            let chunked_traces = chunk_vec(traces, opts.shard_batch_size);
                            chunked_records.into_iter().zip(chunked_traces).for_each(
                                |(records, traces)| {
                                    records_and_traces_tx
                                        .lock()
                                        .unwrap()
                                        .send((records, traces))
                                        .unwrap();
                                },
                            );

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
        pk.observe_into(&mut challenger);

        // Spawn the phase 1 prover thread.
        let phase_1_prover_span = tracing::Span::current().clone();
        let phase_1_prover_handle = s.spawn(move || {
            let _span = phase_1_prover_span.enter();
            tracing::debug_span!("phase 1 prover").in_scope(|| {
                for (records, traces) in p1_records_and_traces_rx.iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();

                        // Collect the public values.
                        let public_values = records
                            .iter()
                            .map(|record| {
                                record.public_values::<SC::Val>()[0..prover.machine().num_pv_elts()]
                                    .to_vec()
                            })
                            .collect::<Vec<_>>();

                        // Commit to each shard.
                        let commitments = records
                            .into_par_iter()
                            .zip(traces.into_par_iter())
                            .map(|(record, traces)| {
                                let _span = span.enter();

                                for (name, trace) in traces.clone() {
                                    let trace_width = trace.width();
                                    let trace_height = trace.height();
                                    tracing::debug!(
                                        "Phase 1 area: {:<15} | Main Cols = {:<5} | Rows = {:<5} | Cells = {:<10}",
                                        name,
                                        trace_width,
                                        trace_height,
                                        trace_width * trace_height,
                                    );

                                }

                                let data = prover.commit(&record, traces);
                                let phase1_main_commit = data.main_commit.clone();
                                drop(data);
                                phase1_main_commit
                            })
                            .collect::<Vec<_>>();

                        //  the commitments.
                        for (commit, public_values) in
                            commitments.into_iter().zip(public_values.into_iter())
                        {
                            prover.observe(&mut challenger, commit.clone(), &public_values);
                        }
                    });
                }
            });

            challenger
        });

        // Wait until the checkpoint generator handle has fully finished.
        let public_values_stream = checkpoint_generator_handle.join().unwrap().unwrap();

        // Wait until the records and traces have been fully generated.
        p1_record_and_trace_gen_handles.into_iter().for_each(|handle| handle.join().unwrap());

        // Wait until the phase 1 prover has completely finished.
        let mut challenger = phase_1_prover_handle.join().unwrap();

        // Sample for the global permutation challenges.
        // Obtain the challenges used for the global permutation argument.
        let mut global_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            global_permutation_challenges.push(challenger.sample_ext_element());
        }

        // Spawn the phase 2 record generator thread.
        let p2_record_gen_sync = Arc::new(TurnBasedSync::new());
        let p2_trace_gen_sync = Arc::new(TurnBasedSync::new());
        let (p2_records_and_traces_tx, p2_records_and_traces_rx) =
            sync_channel::<(
                Vec<ExecutionRecord>,
                (
                    Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>,
                    Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>,
                ),
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

            #[cfg(feature = "debug")]
            let all_records_tx = all_records_tx.clone();

            let handle = s.spawn(move || {
                let _span = span.enter();
                tracing::debug_span!("phase 2 trace generation").in_scope(|| {
                    loop {
                        // Receive the latest checkpoint.
                        let received = { checkpoints.lock().unwrap().pop_front() };
                        if let Some((index, mut checkpoint, done)) = received {
                            // Trace the checkpoint and reconstruct the execution records.
                            let (mut records, report) = tracing::debug_span!("trace checkpoint")
                                .in_scope(|| {
                                    trace_checkpoint::<SC>(
                                        program.clone(),
                                        &checkpoint,
                                        opts,
                                        shape_config,
                                    )
                                });
                            log::info!("generated {} records", records.len());
                            *report_aggregate.lock().unwrap() += report;
                            reset_seek(&mut checkpoint);

                            // Wait for our turn to update the state.
                            record_gen_sync.wait_for_turn(index);

                            // Update the public values & prover state for the shards which contain
                            // "cpu events".
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

                            // See if any deferred shards are ready to be committed to.
                            let mut deferred = deferred.split(done, opts.split_opts);
                            log::info!("deferred {} records", deferred.len());

                            // Update the public values & prover state for the shards which do not
                            // contain "cpu events" before committing to them.
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

                            // Generate the dependencies.
                            tracing::debug_span!("generate dependencies", index).in_scope(|| {
                                prover.machine().generate_dependencies(&mut records, &opts, None);
                            });

                            // Let another worker update the state.
                            record_gen_sync.advance_turn();

                            // Fix the shape of the records.
                            if let Some(shape_config) = shape_config {
                                for record in records.iter_mut() {
                                    shape_config.fix_shape(record).unwrap();
                                }
                            }

                            #[cfg(feature = "debug")]
                            all_records_tx.send(records.clone()).unwrap();

                            // Generate the traces.
                            let mut local_traces = Vec::new();
                            tracing::debug_span!("generate local traces", index).in_scope(|| {
                                local_traces = records
                                    .par_iter()
                                    .map(|record| {
                                        prover.generate_traces(record, InteractionScope::Local)
                                    })
                                    .collect::<Vec<_>>();
                            });

                            let mut global_traces = Vec::new();
                            tracing::debug_span!("generate global traces", index).in_scope(|| {
                                global_traces = records
                                    .par_iter()
                                    .map(|record| {
                                        prover.generate_traces(record, InteractionScope::Global)
                                    })
                                    .collect::<Vec<_>>();
                            });

                            trace_gen_sync.wait_for_turn(index);

                            // Send the records to the phase 2 prover.
                            let chunked_records = chunk_vec(records, opts.shard_batch_size);
                            let chunked_global_traces =
                                chunk_vec(global_traces, opts.shard_batch_size);
                            let chunked_local_traces =
                                chunk_vec(local_traces, opts.shard_batch_size);
                            chunked_records
                                .into_iter()
                                .zip(chunked_global_traces.into_iter())
                                .zip(chunked_local_traces.into_iter())
                                .for_each(|((records, global_traces), local_traces)| {
                                    records_and_traces_tx
                                        .lock()
                                        .unwrap()
                                        .send((records, (global_traces, local_traces)))
                                        .unwrap();
                                });

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
        #[cfg(feature = "debug")]
        drop(all_records_tx);

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
                                |(record, (global_traces, local_traces))| {
                                    let _span = span.enter();

                                    let global_commit_span =
                                        tracing::debug_span!("commit to global traces").entered();
                                    let global_data = prover.commit(&record, global_traces);
                                    global_commit_span.exit();
                                    let local_commit_span =
                                        tracing::debug_span!("commit to local traces").entered();
                                    let local_data = prover.commit(&record, local_traces);
                                    local_commit_span.exit();

                                    let opening_span = tracing::debug_span!("opening").entered();
                                    let proof = prover
                                        .open(
                                            pk,
                                            Some(global_data),
                                            local_data,
                                            &mut challenger.clone(),
                                            &global_permutation_challenges,
                                        )
                                        .unwrap();
                                    opening_span.exit();

                                    #[cfg(debug_assertions)]
                                    {
                                        if let Some(shape) = record.shape {
                                            assert_eq!(
                                                proof.shape(),
                                                shape.clone().into_iter().collect(),
                                            );
                                        }
                                    }
                                    proof
                                },
                            ),
                        );
                    });
                }
            });
            shard_proofs
        });

        // Wait until the records and traces have been fully generated for phase 2.
        p2_record_and_trace_gen_handles.into_iter().for_each(|handle| handle.join().unwrap());

        // Wait until the phase 2 prover has finished.
        let shard_proofs = p2_prover_handle.join().unwrap();

        // Log some of the `ExecutionReport` information.
        let report_aggregate = report_aggregate.lock().unwrap();
        tracing::info!(
            "execution report (totals): total_cycles={}, total_syscall_cycles={}, touched_memory_addresses={}",
            report_aggregate.total_instruction_count(),
            report_aggregate.total_syscall_count(),
            report_aggregate.touched_memory_addresses,
        );

        // Print the opcode and syscall count tables like `du`: sorted by count (descending) and
        // with the count in the first column.
        tracing::info!("execution report (opcode counts):");
        for line in sorted_table_lines(report_aggregate.opcode_counts.as_ref()) {
            tracing::info!("  {line}");
        }
        tracing::info!("execution report (syscall counts):");
        for line in sorted_table_lines(report_aggregate.syscall_counts.as_ref()) {
            tracing::info!("  {line}");
        }

        let proof = MachineProof::<SC> { shard_proofs };
        let cycles = report_aggregate.total_instruction_count();

        // Print the summary.
        let proving_time = proving_start.elapsed().as_secs_f64();
        tracing::info!(
            "summary: cycles={}, gas={}, e2e={}s, khz={:.2}, proofSize={}",
            cycles,
            report_aggregate.estimate_gas(),
            proving_time,
            (cycles as f64 / (proving_time * 1000.0) as f64),
            bincode::serialize(&proof).unwrap().len(),
        );

        #[cfg(feature = "debug")]
        {
            let all_records = all_records_rx.iter().flatten().collect::<Vec<_>>();
            let mut challenger = prover.machine().config().challenger();
            prover.machine().debug_constraints(&pk.to_host(), all_records, &mut challenger);
        }

        Ok((proof, public_values_stream, cycles))
    })
}

/// Runs a program and returns the public values stream.
pub fn run_test_io<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    mut program: Program,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, MachineVerificationError<BabyBearPoseidon2>> {
    let shape_config = CoreShapeConfig::<BabyBear>::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.maximal_shapes =
            Some(shape_config.maximal_core_shapes().into_iter().map(|s| s.inner).collect());
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);

    let _ = run_test_core::<P>(runtime, inputs, Some(&shape_config))?;
    Ok(public_values)
}

pub fn run_test<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    mut program: Program,
) -> Result<MachineProof<BabyBearPoseidon2>, MachineVerificationError<BabyBearPoseidon2>> {
    let shape_config = CoreShapeConfig::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();
    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.maximal_shapes =
            Some(shape_config.maximal_core_shapes().into_iter().map(|s| s.inner).collect());
        runtime.run().unwrap();
        runtime
    });
    run_test_core::<P>(runtime, SP1Stdin::new(), Some(&shape_config))
}

#[allow(unused_variables)]
pub fn run_test_core<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    runtime: Executor,
    inputs: SP1Stdin,
    shape_config: Option<&CoreShapeConfig<BabyBear>>,
) -> Result<MachineProof<BabyBearPoseidon2>, MachineVerificationError<BabyBearPoseidon2>> {
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
        shape_config,
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
pub fn run_test_machine_with_prover<SC, A, P: MachineProver<SC, A>>(
    prover: &P,
    records: Vec<A::Record>,
    pk: P::DeviceProvingKey,
    vk: StarkVerifyingKey<SC>,
) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
where
    A: MachineAir<SC::Val>
        + Air<InteractionBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    A::Record: MachineRecord<Config = SP1CoreOpts>,
    SC: StarkGenericConfig,
    SC::Val: p3_field::PrimeField32,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
{
    let mut challenger = prover.config().challenger();
    let prove_span = tracing::debug_span!("prove").entered();

    #[cfg(feature = "debug")]
    prover.machine().debug_constraints(&pk.to_host(), records.clone(), &mut challenger.clone());

    let proof = prover.prove(&pk, records, &mut challenger, SP1CoreOpts::default()).unwrap();
    prove_span.exit();
    let nb_bytes = bincode::serialize(&proof).unwrap().len();

    let mut challenger = prover.config().challenger();
    prover.machine().verify(&vk, &proof, &mut challenger)?;

    Ok(proof)
}

#[allow(unused_variables)]
pub fn run_test_machine<SC, A>(
    records: Vec<A::Record>,
    machine: StarkMachine<SC, A>,
    pk: StarkProvingKey<SC>,
    vk: StarkVerifyingKey<SC>,
) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
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
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
{
    let prover = CpuProver::new(machine);
    run_test_machine_with_prover::<SC, A, CpuProver<_, _>>(&prover, records, pk, vk)
}

fn trace_checkpoint<SC: StarkGenericConfig>(
    program: Program,
    file: &File,
    opts: SP1CoreOpts,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
) -> (Vec<ExecutionRecord>, ExecutionReport)
where
    <SC as StarkGenericConfig>::Val: PrimeField32,
{
    let mut reader = std::io::BufReader::new(file);
    let state: ExecutionState =
        bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Executor::recover(program.clone(), state.clone(), opts);
    runtime.maximal_shapes = shape_config
        .map(|config| config.maximal_core_shapes().into_iter().map(|s| s.inner).collect());

    // We already passed the deferred proof verifier when creating checkpoints, so the proofs were
    // already verified. So here we use a noop verifier to not print any warnings.
    runtime.subproof_verifier = Arc::new(NoOpSubproofVerifier);

    // Execute from the checkpoint.
    let (records, _) = runtime.execute_record().unwrap();

    (records, runtime.report)
}

fn reset_seek(file: &mut File) {
    file.seek(std::io::SeekFrom::Start(0)).expect("failed to seek to start of tempfile");
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

use p3_air::Air;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::Proof;
