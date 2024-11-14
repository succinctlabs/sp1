use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Seek, SeekFrom},
    sync::{
        mpsc::{channel, sync_channel, Sender},
        Arc, Mutex,
    },
    thread::ScopedJoinHandle,
};

use crate::{
    io::SP1Stdin,
    riscv::{CoreShapeConfig, RiscvAir},
    utils::{chunk_vec, concurrency::TurnBasedSync},
};

use p3_challenger::FieldChallenger;
use p3_field::PrimeField32;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use thiserror::Error;
use web_time::Instant;

use sp1_core_executor::{
    events::sorted_table_lines, subproof::NoOpSubproofVerifier, ExecutionError, ExecutionRecord,
    ExecutionReport, ExecutionState, Executor, Program, SP1Context,
};
use sp1_stark::{
    air::{InteractionScope, PublicValues},
    Com, MachineProof, MachineProver, MachineProvingKey, MachineRecord, OpeningProof,
    PcsProverData, ProofShape, SP1CoreOpts, ShardProof, StarkGenericConfig, Val,
};

pub fn prove_core<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
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
    let (proof_tx, proof_rx) = channel();
    let (shape_tx, shape_rx) = channel();
    let (public_values, cycles) = prove_core_stream(
        prover,
        pk,
        program,
        stdin,
        opts,
        context,
        shape_config,
        proof_tx,
        shape_tx,
    )?;

    let _: Vec<_> = shape_rx.iter().collect();
    let shard_proofs: Vec<ShardProof<SC>> = proof_rx.iter().collect();
    let proof = MachineProof { shard_proofs };

    Ok((proof, public_values, cycles))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_core_stream<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    prover: &P,
    pk: &P::DeviceProvingKey,
    program: Program,
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
    proof_tx: Sender<ShardProof<SC>>,
    shape_tx: Sender<ProofShape>,
) -> Result<(Vec<u8>, u64), SP1CoreProverError>
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
            sync_channel::<(usize, File, bool, u64)>(opts.checkpoints_channel_capacity);
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
                            .execute_state(false)
                            .map_err(SP1CoreProverError::ExecutionError)?;

                        // Save the checkpoint to a temp file.
                        let mut checkpoint_file =
                            tempfile::tempfile().map_err(SP1CoreProverError::IoError)?;
                        checkpoint
                            .save(&mut checkpoint_file)
                            .map_err(SP1CoreProverError::IoError)?;

                        // Send the checkpoint.
                        checkpoints_tx
                            .send((index, checkpoint_file, done, runtime.state.global_clk))
                            .unwrap();

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
                bool,
                u64,
                ExecutionReport,
            )>(opts.records_and_traces_channel_capacity);
        let p1_records_and_traces_tx = Arc::new(Mutex::new(p1_records_and_traces_tx));
        let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));

        let cached_records = Arc::new(Mutex::new(None));
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

                        if let Ok((index, mut checkpoint, done, num_cycles)) = received {
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
                            checkpoint
                                .seek(SeekFrom::Start(0))
                                .expect("failed to seek to start of tempfile");

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

                            // IF DONE & DEFERRED IS "SMALL", then just combine into the most recent shard.
                            let last_record = if done
                                && num_cycles < 1 << 26
                                && deferred.global_memory_initialize_events.len()
                                    < opts.split_opts.memory / 4
                                && deferred.global_memory_finalize_events.len()
                                    < opts.split_opts.memory / 4
                            {
                                tracing::info!("Number of cycles: {}", num_cycles);
                                records.last_mut()
                            } else {
                                None
                            };

                            tracing::info!("Last record is some: {:?}", last_record.is_some());

                            // See if any deferred shards are ready to be committed to.
                            let mut deferred = deferred.split(done, last_record, opts.split_opts);

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
                            checkpoints.push_back((index, checkpoint, done, num_cycles));

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
                                        .send((records, traces, done, num_cycles, report.clone()))
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
        let phase_1_cached_records = Arc::clone(&cached_records);
        let phase_1_prover_handle = s.spawn(move || {
            let _span = phase_1_prover_span.enter();
            tracing::debug_span!("phase 1 prover").in_scope(|| {
                for (records, traces, done, num_cycles, report) in p1_records_and_traces_rx.iter() {
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
                            .par_iter()
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

                                let data = prover.commit(record, traces);
                                data.main_commit.clone()
                            })
                            .collect::<Vec<_>>();

                            if done && num_cycles < (opts.shard_size as u64) * 2 {
                                let mut cached_records = phase_1_cached_records.lock().unwrap();
                                let (mut new_records, mut new_report): (Vec<ExecutionRecord>, ExecutionReport) = cached_records.clone().unwrap_or_default();
                                new_records.extend(records);
                                new_report+=report;
                                *cached_records = tracing::debug_span!("clone records")
                                    .in_scope(|| Some((new_records, new_report)));
                            }

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

        let shape_tx = Arc::new(Mutex::new(shape_tx));
        let report_aggregate = Arc::new(Mutex::new(ExecutionReport::default()));
        let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
        let mut p2_record_and_trace_gen_handles = Vec::new();
        for _ in 0..opts.trace_gen_workers {
            let record_gen_sync = Arc::clone(&p2_record_gen_sync);
            let trace_gen_sync = Arc::clone(&p2_trace_gen_sync);
            let records_and_traces_tx = Arc::clone(&p2_records_and_traces_tx);

            let shape_tx = Arc::clone(&shape_tx);
            let report_aggregate = Arc::clone(&report_aggregate);
            let checkpoints = Arc::clone(&checkpoints);
            let state = Arc::clone(&state);
            let deferred = Arc::clone(&deferred);
            let program = program.clone();
            let span = tracing::Span::current().clone();
            let cached_records = Arc::clone(&cached_records);

            #[cfg(feature = "debug")]
            let all_records_tx = all_records_tx.clone();

            let handle = s.spawn(move || {
                let _span = span.enter();
                tracing::debug_span!("phase 2 trace generation").in_scope(|| {
                    loop {
                        // Receive the latest checkpoint.
                        let received = { checkpoints.lock().unwrap().pop_front() };
                        if let Some((index, mut checkpoint, done, num_cycles)) = received {
                            let (mut records, report) =
                                if done && num_cycles < (opts.shard_size as u64) * 2 {
                                    let mut cached_records = cached_records.lock().unwrap();
                                    let (mut records, report) = cached_records.take().unwrap();
                                    for record in records.iter_mut() {
                                        record.shape = None;
                                    }
                                    (records, report)
                                } else {
                                    tracing::debug_span!("trace checkpoint").in_scope(|| {
                                        trace_checkpoint::<SC>(
                                            program.clone(),
                                            &checkpoint,
                                            opts,
                                            shape_config,
                                        )
                                    })
                                };

                            if !(done && num_cycles < (opts.shard_size as u64) * 2) {
                                // Trace the checkpoint and reconstruct the execution records.
                                log::info!("generated {} records", records.len());
                                *report_aggregate.lock().unwrap() += report;
                                checkpoint
                                    .seek(SeekFrom::Start(0))
                                    .expect("failed to seek to start of tempfile");

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

                                tracing::info!("Records length:{}, done: {}", records.len(), done);

                                // Defer events that are too expensive to include in every shard.
                                let mut deferred = deferred.lock().unwrap();
                                for record in records.iter_mut() {
                                    deferred.append(&mut record.defer());
                                }

                                // tracing::info!("Deferred length: {}", deferred.len());

                                let last_record = if done
                                    && num_cycles < 1 << 26
                                    && deferred.global_memory_initialize_events.len()
                                        < opts.split_opts.memory / 4
                                    && deferred.global_memory_finalize_events.len()
                                        < opts.split_opts.memory / 4
                                {
                                    tracing::info!("Number of cycles: {}", num_cycles);
                                    records.last_mut()
                                } else {
                                    None
                                };

                                tracing::info!("Last record is some: {:?}", last_record.is_some());

                                // See if any deferred shards are ready to be committed to.
                                let mut deferred =
                                    deferred.split(done, last_record, opts.split_opts);
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
                            }

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

                            // Send the shapes to the channel, if necessary.
                            for (global_trace, local_trace) in
                                global_traces.iter().zip(local_traces.iter())
                            {
                                shape_tx
                                    .lock()
                                    .unwrap()
                                    .send(ProofShape::from_traces(Some(global_trace), local_trace))
                                    .unwrap();
                            }

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
        let proof_tx = Arc::new(Mutex::new(proof_tx));
        let p2_prover_handle = s.spawn(move || {
            let _span = p2_prover_span.enter();
            tracing::debug_span!("phase 2 prover").in_scope(|| {
                for (records, traces) in p2_records_and_traces_rx.into_iter() {
                    tracing::debug_span!("batch").in_scope(|| {
                        let span = tracing::Span::current().clone();
                        let proofs = records
                            .into_par_iter()
                            .zip(traces.into_par_iter())
                            .map(|(record, (global_traces, local_traces))| {
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
                                    if let Some(shape) = record.shape.as_ref() {
                                        assert_eq!(
                                            proof.shape(),
                                            shape.clone().into_iter().collect(),
                                        );
                                    }
                                }

                                rayon::spawn(move || {
                                    drop(record);
                                });

                                proof
                            })
                            .collect::<Vec<_>>();

                        // Send the batch of proofs to the channel.
                        let proof_tx = proof_tx.lock().unwrap();
                        for proof in proofs {
                            proof_tx.send(proof).unwrap();
                        }
                    });
                }
            });
        });

        // Wait until the records and traces have been fully generated for phase 2.
        p2_record_and_trace_gen_handles.into_iter().for_each(|handle| handle.join().unwrap());

        // Wait until the phase 2 prover has finished.
        p2_prover_handle.join().unwrap();

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

        let cycles = report_aggregate.total_instruction_count();

        // Print the summary.
        let proving_time = proving_start.elapsed().as_secs_f64();
        tracing::info!(
            "summary: cycles={}, e2e={}s, khz={:.2}",
            cycles,
            proving_time,
            (cycles as f64 / (proving_time * 1000.0) as f64),
        );

        #[cfg(feature = "debug")]
        {
            let all_records = all_records_rx.iter().flatten().collect::<Vec<_>>();
            let mut challenger = prover.machine().config().challenger();
            let pk_host = prover.pk_to_host(pk);
            prover.machine().debug_constraints(&pk_host, all_records, &mut challenger);
        }

        Ok((public_values_stream, cycles))
    })
}

pub fn trace_checkpoint<SC: StarkGenericConfig>(
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
    let (records, _) = runtime.execute_record(true).unwrap();

    (records, runtime.report)
}

#[derive(Error, Debug)]
pub enum SP1CoreProverError {
    #[error("failed to execute program: {0}")]
    ExecutionError(ExecutionError),
    #[error("io error: {0}")]
    IoError(io::Error),
    #[error("serialization error: {0}")]
    SerializationError(bincode::Error),
}
