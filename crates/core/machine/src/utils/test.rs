use std::sync::Arc;

use slop_basefold::FriConfig;
use sp1_core_executor::{Program, SP1Context, SP1CoreOpts};
use sp1_core_executor_runner::MinimalExecutorRunner;
use sp1_hypercube::{
    prover::{CpuShardProver, SP1InnerPcsProver, SimpleProver},
    Machine, MachineProof, MachineVerifierConfigError, SP1InnerPcs, SP1PcsProofInner,
    ShardVerifier,
};
use sp1_primitives::{io::SP1PublicValues, SP1Field, SP1GlobalContext};
use tracing::Instrument;

use crate::{io::SP1Stdin, riscv::RiscvAir};

use super::prove_core;

/// Like [`run_test`] but with a caller-supplied [`Machine`] (e.g. one carrying APC chips built via
/// [`crate::autoprecompiles::create_apcs`]).
pub async fn run_test_with_machine(
    program: Arc<Program>,
    inputs: SP1Stdin,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
) -> Result<SP1PublicValues, MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
    let mut executor = MinimalExecutorRunner::simple(program.clone());
    for buf in &inputs.buffer {
        executor.with_input(buf);
    }
    while executor.execute_chunk().is_some() {}
    let public_values = SP1PublicValues::from(executor.public_values_stream());

    let _ = run_test_core_with_machine(program, inputs, 21, 22, machine, SP1CoreOpts::default())
        .await?;
    Ok(public_values)
}

// /// This type is the function signature used for malicious trace and public values generators for
// /// failure test cases.
// pub(crate) type MaliciousTracePVGeneratorType<Val, P> =
//     Box<dyn Fn(&P, &mut ExecutionRecord) -> Vec<(String, RowMajorMatrix<Val>)> + Send + Sync>;

/// The canonical entry point for testing a [`Program`] and [`SP1Stdin`] with a [`MachineProver`].
pub async fn run_test(
    program: Arc<Program>,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
    // Run MinimalExecutorRunner to get public values
    let mut executor = MinimalExecutorRunner::simple(program.clone());
    for buf in &inputs.buffer {
        executor.with_input(buf);
    }
    while executor.execute_chunk().is_some() {}
    let public_values = SP1PublicValues::from(executor.public_values_stream());

    let _ = run_test_core(program, inputs, 21, 22).await?;
    Ok(public_values)
}

/// This function tests cases where `max_log_row_count` is potentially larger than the `log(trace)`.
pub async fn run_test_small_trace(
    program: Arc<Program>,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>> {
    // Run MinimalExecutorRunner to get public values
    let mut executor = MinimalExecutorRunner::simple(program.clone());
    for buf in &inputs.buffer {
        executor.with_input(buf);
    }
    while executor.execute_chunk().is_some() {}
    let public_values = SP1PublicValues::from(executor.public_values_stream());

    let _ = run_test_core(program, inputs, 20, 23).await?;
    Ok(public_values)
}

// pub fn run_malicious_test<P: MachineProver<SP1InnerPcs, RiscvAir<SP1Field>>>(
//     mut program: Program,
//     inputs: SP1Stdin,
//     malicious_trace_pv_generator: MaliciousTracePVGeneratorType<SP1Field, P>,
// ) -> Result<SP1PublicValues, MachineVerificationError<SP1InnerPcs>> {
//     let shape_config = CoreShapeConfig::<SP1Field>::default();
//     shape_config.fix_preprocessed_shape(&mut program).unwrap();

//     let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.maximal_shapes = Some(
//             shape_config
//                 .maximal_core_shapes(SP1CoreOpts::default().shard_size.ilog2() as usize)
//                 .into_iter()
//                 .collect(),
//         );
//         runtime.write_vecs(&inputs.buffer);
//         runtime.run::<Trace>().unwrap();
//         runtime
//     });
//     let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);

//     let result = run_test_core::<P>(
//         runtime,
//         inputs,
//         Some(&shape_config),
//         Some(malicious_trace_pv_generator),
//     );
//     if let Err(verification_error) = result {
//         Err(verification_error)
//     } else {
//         Ok(public_values)
//     }
// }

pub async fn run_test_core(
    program: Arc<Program>,
    inputs: SP1Stdin,
    log_stacking_height: u32,
    max_log_row_count: usize,
) -> Result<
    MachineProof<SP1GlobalContext, SP1PcsProofInner>,
    MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>,
> {
    let verifier = ShardVerifier::from_basefold_parameters(
        FriConfig::default_fri_config(),
        log_stacking_height,
        max_log_row_count,
        RiscvAir::machine(),
    );
    let shard_prover = CpuShardProver::<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, _>::new(
        verifier.clone(),
    );
    let prover = SimpleProver::new(verifier, shard_prover);

    let (pk, vk) =
        prover.setup(program.clone()).instrument(tracing::debug_span!("setup").or_current()).await;
    let pk = unsafe { pk.into_inner() };
    let machine = RiscvAir::machine();

    let (proof, _) = prove_core(
        &prover,
        pk,
        program,
        inputs,
        SP1CoreOpts::default(),
        SP1Context::default(),
        machine,
    )
    .instrument(tracing::debug_span!("prove core"))
    .await
    .unwrap();

    prover.verify(&vk, &proof)?;
    Ok(proof)
}

/// Like [`run_test_core`] but proves with a caller-supplied [`Machine`] (e.g. one carrying APC
/// chips) instead of the default `RiscvAir::machine()`.
pub async fn run_test_core_with_machine(
    program: Arc<Program>,
    inputs: SP1Stdin,
    log_stacking_height: u32,
    max_log_row_count: usize,
    machine: Machine<SP1Field, RiscvAir<SP1Field>>,
    opts: SP1CoreOpts,
) -> Result<
    MachineProof<SP1GlobalContext, SP1PcsProofInner>,
    MachineVerifierConfigError<SP1GlobalContext, SP1InnerPcs>,
> {
    let verifier = ShardVerifier::from_basefold_parameters(
        FriConfig::default_fri_config(),
        log_stacking_height,
        max_log_row_count,
        machine.clone(),
    );
    let shard_prover = CpuShardProver::<SP1GlobalContext, SP1InnerPcs, SP1InnerPcsProver, _>::new(
        verifier.clone(),
    );
    let prover = SimpleProver::new(verifier, shard_prover);

    let (pk, vk) =
        prover.setup(program.clone()).instrument(tracing::debug_span!("setup").or_current()).await;
    let pk = unsafe { pk.into_inner() };

    let (proof, _) = prove_core(&prover, pk, program, inputs, opts, SP1Context::default(), machine)
        .instrument(tracing::debug_span!("prove core"))
        .await
        .unwrap();

    prover.verify(&vk, &proof)?;
    Ok(proof)
}

// #[allow(unused_variables)]
// pub fn run_test_machine_with_prover<SC, A, P: MachineProver<SC, A>>(
//     prover: &P,
//     records: Vec<A::Record>,
//     pk: P::DeviceProvingKey,
//     vk: StarkVerifyingKey<SC>,
// ) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
// where
//     A: MachineAir<SC::Val>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Val, SC::Challenge>>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Challenge, SC::Challenge>>
//         + Air<InteractionBuilder<Val<SC>>>
//         + for<'a> Air<VerifierConstraintFolder<'a, SC>>
//         + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
//         + Air<SymbolicAirBuilder<SC::Val>>,
//     A::Record: MachineRecord<Config = SP1CoreOpts>,
//     SC: StarkGenericConfig,
//     SC::Val: p3_field::PrimeField32,
//     SC::Challenger: Clone,
//     Com<SC>: Send + Sync,
//     PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
//     OpeningProof<SC>: Send + Sync,
// {
//     let mut challenger = prover.config().challenger();
//     let prove_span = tracing::debug_span!("prove").entered();

//     #[cfg(feature = "debug")]
//     prover.machine().debug_constraints(
//         &prover.pk_to_host(&pk),
//         records.clone(),
//         &mut challenger.clone(),
//     );

//     let proof = prover.prove(&pk, records, &mut challenger, SP1CoreOpts::default()).unwrap();
//     prove_span.exit();
//     let nb_bytes = bincode::serialize(&proof).unwrap().len();

//     let mut challenger = prover.config().challenger();
//     prover.machine().verify(&vk, &proof, &mut challenger)?;

//     Ok(proof)
// }

// #[allow(unused_variables)]
// pub fn run_test_machine<SC, A>(
//     records: Vec<A::Record>,
//     machine: StarkMachine<SC, A>,
//     pk: StarkProvingKey<SC>,
//     vk: StarkVerifyingKey<SC>,
// ) -> Result<MachineProof<SC>, MachineVerificationError<SC>>
// where
//     A: MachineAir<SC::Val>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Val, SC::Challenge>>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Challenge, SC::Challenge>>
//         + Air<InteractionBuilder<Val<SC>>>
//         + for<'a> Air<VerifierConstraintFolder<'a, SC>>
//         + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
//         + Air<SymbolicAirBuilder<SC::Val>>,
//     A::Record: MachineRecord<Config = SP1CoreOpts>,
//     SC: StarkGenericConfig,
//     SC::Val: p3_field::PrimeField32,
//     SC::Challenger: Clone,
//     Com<SC>: Send + Sync,
//     PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
//     OpeningProof<SC>: Send + Sync,
// {
//     let prover = CpuProver::new(machine);
//     run_test_machine_with_prover::<SC, A, CpuProver<_, _>>(&prover, records, pk, vk)
// }

// pub fn setup_test_machine<SC, A>(
//     machine: StarkMachine<SC, A>,
// ) -> (StarkProvingKey<SC>, StarkVerifyingKey<SC>)
// where
//     A: MachineAir<SC::Val, Program = Program>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Val, SC::Challenge>>
//         + for<'a> Air<ConstraintSumcheckFolder<'a, SC::Val, SC::Challenge, SC::Challenge>>
//         + Air<InteractionBuilder<Val<SC>>>
//         + for<'a> Air<VerifierConstraintFolder<'a, SC>>
//         + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
//         + Air<SymbolicAirBuilder<SC::Val>>,
//     A::Record: MachineRecord<Config = SP1CoreOpts>,
//     SC: StarkGenericConfig,
//     SC::Val: p3_field::PrimeField32,
//     SC::Challenger: Clone,
//     Com<SC>: Send + Sync,
//     PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
//     OpeningProof<SC>: Send + Sync,
// {
//     let prover = CpuProver::new(machine);
//     let empty_program = Program::new(vec![], 0, 0);
//     let (pk, vk) = prover.setup(&empty_program);

//     (pk, vk)
// }
