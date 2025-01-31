use p3_matrix::dense::RowMajorMatrix;
use std::{
    fs::File,
    io::{self, Seek, SeekFrom},
    str::FromStr,
    sync::{
        mpsc::{channel, sync_channel, Sender},
        Arc, Mutex,
    },
    thread::ScopedJoinHandle,
};
use web_time::Instant;

use crate::riscv::RiscvAir;
use crate::shape::CoreShapeConfig;
use crate::utils::test::MaliciousTracePVGeneratorType;
use p3_maybe_rayon::prelude::*;
use sp1_stark::MachineProvingKey;
use sp1_stark::StarkVerifyingKey;
use thiserror::Error;

use p3_field::PrimeField32;
use sp1_stark::air::MachineAir;

use crate::{
    io::SP1Stdin,
    utils::{chunk_vec, concurrency::TurnBasedSync},
};
use sp1_core_executor::{
    events::{format_table_line, sorted_table_lines},
    ExecutionState, RiscvAirId,
};

use sp1_core_executor::{
    subproof::NoOpSubproofVerifier, ExecutionError, ExecutionRecord, ExecutionReport, Executor,
    Program, SP1Context,
};
use sp1_stark::{
    air::PublicValues, shape::OrderedShape, Com, MachineProof, MachineProver, MachineRecord,
    OpeningProof, PcsProverData, SP1CoreOpts, ShardProof, StarkGenericConfig, Val,
};

#[allow(clippy::too_many_arguments)]
pub fn prove_core<SC: StarkGenericConfig, P: MachineProver<SC, RiscvAir<SC::Val>>>(
    prover: &P,
    pk: &P::DeviceProvingKey,
    _: &StarkVerifyingKey<SC>,
    program: Program,
    stdin: &SP1Stdin,
    opts: SP1CoreOpts,
    context: SP1Context,
    shape_config: Option<&CoreShapeConfig<SC::Val>>,
    malicious_trace_pv_generator: Option<MaliciousTracePVGeneratorType<SC::Val, P>>,
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
        malicious_trace_pv_generator,
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
    shape_and_done_tx: Sender<(OrderedShape, bool)>,
    malicious_trace_pv_generator: Option<MaliciousTracePVGeneratorType<SC::Val, P>>, // This is used for failure test cases that generate malicious traces and public values.
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
    runtime.maximal_shapes = shape_config.map(|config| {
        config.maximal_core_shapes(opts.shard_size.ilog2() as usize).into_iter().collect()
    });
    runtime.write_vecs(&stdin.buffer);
    for proof in stdin.proofs.iter() {
        let (proof, vk) = proof.clone();
        runtime.write_proof(proof, vk);
    }

    #[cfg(feature = "debug")]
    let (all_records_tx, all_records_rx) = std::sync::mpsc::channel::<Vec<ExecutionRecord>>();

    // Need to create an optional reference, because of the `move` below.
    let malicious_trace_pv_generator: Option<&MaliciousTracePVGeneratorType<SC::Val, P>> =
        malicious_trace_pv_generator.as_ref();

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
                        let (checkpoint, _, done) = runtime
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

        // Create the challenger and observe the verifying key.
        let mut challenger = prover.config().challenger();
        pk.observe_into(&mut challenger);

        // Spawn the phase 2 record generator thread.
        let p2_record_gen_sync = Arc::new(TurnBasedSync::new());
        let p2_trace_gen_sync = Arc::new(TurnBasedSync::new());
        let (p2_records_and_traces_tx, p2_records_and_traces_rx) =
            sync_channel::<(Vec<ExecutionRecord>, Vec<Vec<(String, RowMajorMatrix<Val<SC>>)>>)>(
                opts.records_and_traces_channel_capacity,
            );
        let p2_records_and_traces_tx = Arc::new(Mutex::new(p2_records_and_traces_tx));

        let shape_tx = Arc::new(Mutex::new(shape_and_done_tx));
        let report_aggregate = Arc::new(Mutex::new(ExecutionReport::default()));
        let state = Arc::new(Mutex::new(PublicValues::<u32, u32>::default().reset()));
        let deferred = Arc::new(Mutex::new(ExecutionRecord::new(program.clone().into())));
        let mut p2_record_and_trace_gen_handles = Vec::new();
        let checkpoints_rx = Arc::new(Mutex::new(checkpoints_rx));
        for _ in 0..opts.trace_gen_workers {
            let record_gen_sync = Arc::clone(&p2_record_gen_sync);
            let trace_gen_sync = Arc::clone(&p2_trace_gen_sync);
            let records_and_traces_tx = Arc::clone(&p2_records_and_traces_tx);
            let checkpoints_rx = Arc::clone(&checkpoints_rx);

            let shape_tx = Arc::clone(&shape_tx);
            let report_aggregate = Arc::clone(&report_aggregate);
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
                        let received = { checkpoints_rx.lock().unwrap().recv() };
                        if let Ok((index, mut checkpoint, done, num_cycles)) = received {
                            let (mut records, report) = tracing::debug_span!("trace checkpoint")
                                .in_scope(|| {
                                    trace_checkpoint::<SC>(
                                        program.clone(),
                                        &checkpoint,
                                        opts,
                                        shape_config,
                                    )
                                });

                            // Trace the checkpoint and reconstruct the execution records.
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

                            // Defer events that are too expensive to include in every shard.
                            let mut deferred = deferred.lock().unwrap();
                            for record in records.iter_mut() {
                                deferred.append(&mut record.defer());
                            }

                            // We combine the memory init/finalize events if they are "small"
                            // and would affect performance.
                            let mut shape_fixed_records = if done
                                && num_cycles < 1 << 21
                                && deferred.global_memory_initialize_events.len()
                                    < opts.split_opts.combine_memory_threshold
                                && deferred.global_memory_finalize_events.len()
                                    < opts.split_opts.combine_memory_threshold
                            {
                                let mut records_clone = records.clone();
                                let last_record = records_clone.last_mut();
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
                                records_clone.append(&mut deferred);

                                // Generate the dependencies.
                                tracing::debug_span!("generate dependencies", index).in_scope(
                                    || {
                                        prover.machine().generate_dependencies(
                                            &mut records_clone,
                                            &opts,
                                            None,
                                        );
                                    },
                                );

                                // Let another worker update the state.
                                record_gen_sync.advance_turn();

                                // Fix the shape of the records.
                                let mut fixed_shape = true;
                                if let Some(shape_config) = shape_config {
                                    for record in records_clone.iter_mut() {
                                        if shape_config.fix_shape(record).is_err() {
                                            fixed_shape = false;
                                        }
                                    }
                                }
                                fixed_shape.then_some(records_clone)
                            } else {
                                None
                            };

                            if shape_fixed_records.is_none() {
                                // See if any deferred shards are ready to be committed to.
                                let mut deferred = deferred.split(done, None, opts.split_opts);
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
                                tracing::debug_span!("generate dependencies", index).in_scope(
                                    || {
                                        prover.machine().generate_dependencies(
                                            &mut records,
                                            &opts,
                                            None,
                                        );
                                    },
                                );

                                // Let another worker update the state.
                                record_gen_sync.advance_turn();

                                // Fix the shape of the records.
                                if let Some(shape_config) = shape_config {
                                    for record in records.iter_mut() {
                                        shape_config.fix_shape(record).unwrap();
                                    }
                                }
                                shape_fixed_records = Some(records);
                            }

                            let mut records = shape_fixed_records.unwrap();

                            // Send the shapes to the channel, if necessary.
                            for record in records.iter() {
                                let mut heights = vec![];
                                let chips = prover.shard_chips(record).collect::<Vec<_>>();
                                if let Some(shape) = record.shape.as_ref() {
                                    for chip in chips.iter() {
                                        let id = RiscvAirId::from_str(&chip.name()).unwrap();
                                        let height = shape.log2_height(&id).unwrap();
                                        heights.push((chip.name().clone(), height));
                                    }
                                    shape_tx
                                        .lock()
                                        .unwrap()
                                        .send((OrderedShape::from_log2_heights(&heights), done))
                                        .unwrap();
                                }
                            }

                            #[cfg(feature = "debug")]
                            all_records_tx.send(records.clone()).unwrap();

                            let mut main_traces = Vec::new();
                            if let Some(malicious_trace_pv_generator) = malicious_trace_pv_generator
                            {
                                tracing::info_span!("generate main traces", index).in_scope(|| {
                                    main_traces = records
                                        .par_iter_mut()
                                        .map(|record| malicious_trace_pv_generator(prover, record))
                                        .collect::<Vec<_>>();
                                });
                            } else {
                                tracing::info_span!("generate main traces", index).in_scope(|| {
                                    main_traces = records
                                        .par_iter()
                                        .map(|record| prover.generate_traces(record))
                                        .collect::<Vec<_>>();
                                });
                            }

                            trace_gen_sync.wait_for_turn(index);

                            // Send the records to the phase 2 prover.
                            let chunked_records = chunk_vec(records, opts.shard_batch_size);
                            let chunked_main_traces = chunk_vec(main_traces, opts.shard_batch_size);
                            chunked_records
                                .into_iter()
                                .zip(chunked_main_traces.into_iter())
                                .for_each(|(records, main_traces)| {
                                    records_and_traces_tx
                                        .lock()
                                        .unwrap()
                                        .send((records, main_traces))
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
                            .map(|(record, main_traces)| {
                                let _span = span.enter();

                                let main_data = prover.commit(&record, main_traces);

                                let opening_span = tracing::debug_span!("opening").entered();
                                let proof =
                                    prover.open(pk, main_data, &mut challenger.clone()).unwrap();
                                opening_span.exit();

                                #[cfg(debug_assertions)]
                                {
                                    if let Some(shape) = record.shape.as_ref() {
                                        assert_eq!(
                                            proof.shape(),
                                            shape
                                                .clone()
                                                .into_iter()
                                                .map(|(k, v)| (k.to_string(), v as usize))
                                                .collect(),
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

        // Wait until the checkpoint generator handle has fully finished.
        let public_values_stream = checkpoint_generator_handle.join().unwrap().unwrap();

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
        let (width, lines) = sorted_table_lines(report_aggregate.opcode_counts.as_ref());
        for (label, count) in lines {
            if *count > 0 {
                tracing::info!("  {}", format_table_line(&width, &label, count));
            } else {
                tracing::debug!("  {}", format_table_line(&width, &label, count));
            }
        }

        tracing::info!("execution report (syscall counts):");
        let (width, lines) = sorted_table_lines(report_aggregate.syscall_counts.as_ref());
        for (label, count) in lines {
            if *count > 0 {
                tracing::info!("  {}", format_table_line(&width, &label, count));
            } else {
                tracing::debug!("  {}", format_table_line(&width, &label, count));
            }
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
    let noop = NoOpSubproofVerifier;

    let mut reader = std::io::BufReader::new(file);
    let state: ExecutionState =
        bincode::deserialize_from(&mut reader).expect("failed to deserialize state");
    let mut runtime = Executor::recover(program, state, opts);
    runtime.maximal_shapes = shape_config.map(|config| {
        config.maximal_core_shapes(opts.shard_size.ilog2() as usize).into_iter().collect()
    });

    // We already passed the deferred proof verifier when creating checkpoints, so the proofs were
    // already verified. So here we use a noop verifier to not print any warnings.
    runtime.subproof_verifier = Some(&noop);

    // Execute from the checkpoint.
    let (records, _) = runtime.execute_record(true).unwrap();

    (records.into_iter().map(|r| *r).collect(), runtime.report)
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
