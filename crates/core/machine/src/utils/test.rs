use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicAirBuilder;
use serde::{de::DeserializeOwned, Serialize};
use sp1_core_executor::{ExecutionRecord, Executor, Program, SP1Context};
use sp1_primitives::io::SP1PublicValues;
use sp1_stark::{
    air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, Com, CpuProver,
    DebugConstraintBuilder, InteractionBuilder, MachineProof, MachineProver, MachineRecord,
    MachineVerificationError, OpeningProof, PcsProverData, ProverConstraintFolder, SP1CoreOpts,
    StarkGenericConfig, StarkMachine, StarkProvingKey, StarkVerifyingKey, Val,
    VerifierConstraintFolder,
};

use crate::{io::SP1Stdin, riscv::RiscvAir, shape::CoreShapeConfig};

use super::prove_core;

/// This type is the function signature used for malicious trace and public values generators for failure test cases.
pub(crate) type MaliciousTracePVGeneratorType<Val, P> =
    Box<dyn Fn(&P, &mut ExecutionRecord) -> Vec<(String, RowMajorMatrix<Val>)> + Send + Sync>;

/// The canonical entry point for testing a [`Program`] and [`SP1Stdin`] with a [`MachineProver`].
pub fn run_test<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    mut program: Program,
    inputs: SP1Stdin,
) -> Result<SP1PublicValues, MachineVerificationError<BabyBearPoseidon2>> {
    let shape_config = CoreShapeConfig::<BabyBear>::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();

    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.maximal_shapes = Some(
            shape_config
                .maximal_core_shapes(SP1CoreOpts::default().shard_size.ilog2() as usize)
                .into_iter()
                .collect(),
        );
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);

    let _ = run_test_core::<P>(runtime, inputs, Some(&shape_config), None)?;
    Ok(public_values)
}

pub fn run_malicious_test<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    mut program: Program,
    inputs: SP1Stdin,
    malicious_trace_pv_generator: MaliciousTracePVGeneratorType<BabyBear, P>,
) -> Result<SP1PublicValues, MachineVerificationError<BabyBearPoseidon2>> {
    let shape_config = CoreShapeConfig::<BabyBear>::default();
    shape_config.fix_preprocessed_shape(&mut program).unwrap();

    let runtime = tracing::debug_span!("runtime.run(...)").in_scope(|| {
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.maximal_shapes = Some(
            shape_config
                .maximal_core_shapes(SP1CoreOpts::default().shard_size.ilog2() as usize)
                .into_iter()
                .collect(),
        );
        runtime.write_vecs(&inputs.buffer);
        runtime.run().unwrap();
        runtime
    });
    let public_values = SP1PublicValues::from(&runtime.state.public_values_stream);

    let result = run_test_core::<P>(
        runtime,
        inputs,
        Some(&shape_config),
        Some(malicious_trace_pv_generator),
    );
    if let Err(verification_error) = result {
        Err(verification_error)
    } else {
        Ok(public_values)
    }
}

#[allow(unused_variables)]
pub fn run_test_core<P: MachineProver<BabyBearPoseidon2, RiscvAir<BabyBear>>>(
    runtime: Executor,
    inputs: SP1Stdin,
    shape_config: Option<&CoreShapeConfig<BabyBear>>,
    malicious_trace_pv_generator: Option<MaliciousTracePVGeneratorType<BabyBear, P>>,
) -> Result<MachineProof<BabyBearPoseidon2>, MachineVerificationError<BabyBearPoseidon2>> {
    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let prover = P::new(machine);

    let (pk, vk) = prover.setup(runtime.program.as_ref());
    let (proof, output, _) = prove_core(
        &prover,
        &pk,
        &vk,
        Program::clone(&runtime.program),
        &inputs,
        SP1CoreOpts::default(),
        SP1Context::default(),
        shape_config,
        malicious_trace_pv_generator,
    )
    .unwrap();

    let config = BabyBearPoseidon2::new();
    let machine = RiscvAir::machine(config);
    let (pk, vk) = machine.setup(runtime.program.as_ref());
    let mut challenger = machine.config().challenger();
    if let Err(e) = machine.verify(&vk, &proof, &mut challenger) {
        Err(e)
    } else {
        Ok(proof)
    }
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
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + Air<SymbolicAirBuilder<SC::Val>>,
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
    prover.machine().debug_constraints(
        &prover.pk_to_host(&pk),
        records.clone(),
        &mut challenger.clone(),
    );

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
        + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>
        + Air<SymbolicAirBuilder<SC::Val>>,
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
