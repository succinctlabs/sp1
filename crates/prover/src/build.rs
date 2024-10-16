use std::{borrow::Borrow, path::PathBuf};

use p3_baby_bear::BabyBear;
use sp1_core_executor::SP1Context;
use sp1_core_machine::io::SP1Stdin;
use sp1_recursion_circuit::{
    hash::FieldHasherVariable,
    machine::{SP1CompressWitnessValues, SP1WrapVerifier},
};
use sp1_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::Builder,
};

use sp1_recursion_core::air::RecursionPublicValues;
pub use sp1_recursion_core::stark::sp1_dev_mode;

pub use sp1_recursion_circuit::witness::{OuterWitness, Witnessable};

use sp1_recursion_gnark_ffi::{Groth16Bn254Prover, PlonkBn254Prover};
use sp1_stark::{SP1ProverOpts, ShardProof, StarkVerifyingKey};

use crate::{
    utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
    OuterSC, SP1Prover, WrapAir,
};

/// Tries to build the PLONK artifacts inside the development directory.
pub fn try_build_plonk_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = plonk_bn254_artifacts_dev_dir();
    println!("[sp1] building plonk bn254 artifacts in development mode");
    build_plonk_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Tries to build the groth16 bn254 artifacts in the current environment.
pub fn try_build_groth16_bn254_artifacts_dev(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> PathBuf {
    let build_dir = groth16_bn254_artifacts_dev_dir();
    println!("[sp1] building groth16 bn254 artifacts in development mode");
    build_groth16_bn254_artifacts(template_vk, template_proof, &build_dir);
    build_dir
}

/// Gets the directory where the PLONK artifacts are installed in development mode.
pub fn plonk_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".sp1").join("circuits").join("dev")
}

/// Gets the directory where the groth16 artifacts are installed in development mode.
pub fn groth16_bn254_artifacts_dev_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".sp1").join("circuits").join("dev")
}

/// Build the plonk bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_plonk_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    PlonkBn254Prover::build(constraints, witness, build_dir);
}

/// Build the groth16 bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_groth16_bn254_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir).expect("failed to create build directory");
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    Groth16Bn254Prover::build(constraints, witness, build_dir);
}

/// Builds the plonk bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_plonk_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    let wrap_vk_bytes = bincode::serialize(&wrap_vk).unwrap();
    let wrapped_proof_bytes = bincode::serialize(&wrapped_proof).unwrap();
    std::fs::write("wrap_vk.bin", wrap_vk_bytes).unwrap();
    std::fs::write("wrapped_proof.bin", wrapped_proof_bytes).unwrap();
    let wrap_vk_bytes = std::fs::read("wrap_vk.bin").unwrap();
    let wrapped_proof_bytes = std::fs::read("wrapped_proof.bin").unwrap();
    let wrap_vk = bincode::deserialize(&wrap_vk_bytes).unwrap();
    let wrapped_proof = bincode::deserialize(&wrapped_proof_bytes).unwrap();
    crate::build::build_plonk_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Builds the groth16 bn254 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_groth16_bn254_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    let wrap_vk_bytes = bincode::serialize(&wrap_vk).unwrap();
    let wrapped_proof_bytes = bincode::serialize(&wrapped_proof).unwrap();
    std::fs::write("wrap_vk.bin", wrap_vk_bytes).unwrap();
    std::fs::write("wrapped_proof.bin", wrapped_proof_bytes).unwrap();
    let wrap_vk_bytes = std::fs::read("wrap_vk.bin").unwrap();
    let wrapped_proof_bytes = std::fs::read("wrapped_proof.bin").unwrap();
    let wrap_vk = bincode::deserialize(&wrap_vk_bytes).unwrap();
    let wrapped_proof = bincode::deserialize(&wrapped_proof_bytes).unwrap();
    crate::build::build_groth16_bn254_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> (Vec<Constraint>, OuterWitness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let template_input = SP1CompressWitnessValues {
        vks_and_proofs: vec![(template_vk.clone(), template_proof.clone())],
        is_complete: true,
    };
    let constraints =
        tracing::info_span!("wrap circuit").in_scope(|| build_outer_circuit(&template_input));

    let pv: &RecursionPublicValues<BabyBear> = template_proof.public_values.as_slice().borrow();
    let vkey_hash = babybears_to_bn254(&pv.sp1_vk_digest);
    let committed_values_digest_bytes: [BabyBear; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().unwrap();
    let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = OuterWitness::default();
    template_input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
pub fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
    let elf = include_bytes!("../elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover: SP1Prover = SP1Prover::new();
    let opts = SP1ProverOpts::default();
    let context = SP1Context::default();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let mut stdin = SP1Stdin::new();
    stdin.write(&500u32);
    let core_proof = prover.prove_core(&pk, &stdin, opts, context).unwrap();

    tracing::info!("compress");
    let compressed_proof = prover.compress(&vk, core_proof, vec![], opts).unwrap();

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(compressed_proof, opts).unwrap();

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(shrink_proof, opts).unwrap();

    (wrapped_proof.vk, wrapped_proof.proof)
}

fn build_outer_circuit(template_input: &SP1CompressWitnessValues<OuterSC>) -> Vec<Constraint> {
    let wrap_machine = WrapAir::wrap_machine(OuterSC::default());

    let wrap_span = tracing::debug_span!("build wrap circuit").entered();
    let mut builder = Builder::<OuterConfig>::default();

    // Get the value of the vk.
    let template_vk = template_input.vks_and_proofs.first().unwrap().0.clone();
    // Get an input variable.
    let input = template_input.read(&mut builder);
    // Fix the `wrap_vk` value to be the same as the template `vk`. Since the chip information and
    // the ordering is already a constant, we just need to constrain the commitment and pc_start.

    // Get the vk variable from the input.
    let vk = input.vks_and_proofs.first().unwrap().0.clone();
    // Get the expected commitment.
    let expected_commitment: [_; 1] = template_vk.commit.into();
    let expected_commitment = expected_commitment.map(|x| builder.eval(x));
    // Constrain `commit` to be the same as the template `vk`.
    OuterSC::assert_digest_eq(&mut builder, expected_commitment, vk.commitment);
    // Constrain `pc_start` to be the same as the template `vk`.
    builder.assert_felt_eq(vk.pc_start, template_vk.pc_start);

    // Verify the proof.
    SP1WrapVerifier::verify(&mut builder, &wrap_machine, input);

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    let operations = backend.emit(builder.into_operations());
    wrap_span.exit();

    operations
}
