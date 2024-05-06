use std::path::PathBuf;

use p3_baby_bear::BabyBear;
use sp1_core::stark::StarkVerifyingKey;
use sp1_core::{io::SP1Stdin, stark::ShardProof};
pub use sp1_recursion_circuit::stark::build_wrap_circuit;
pub use sp1_recursion_circuit::witness::Witnessable;
pub use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_compiler::{config::OuterConfig, constraints::Constraint};
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Prover;
use sp1_recursion_gnark_ffi::Groth16Prover;

use crate::utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes};
use crate::{OuterSC, SP1Prover};

/// Build the groth16 artifacts to the given directory for the given verification key and template
/// proof.
pub fn groth16_artifacts(
    wrap_vk: &StarkVerifyingKey<OuterSC>,
    wrapped_proof: &ShardProof<OuterSC>,
    build_dir: PathBuf,
) {
    let (constraints, witness) = build_constraints(wrap_vk, wrapped_proof);
    Groth16Prover::build(constraints, witness, build_dir);
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SP1Prover::new();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let mut stdin = SP1Stdin::new();
    stdin.write(&500u32);
    let core_proof = prover.prove_core(&pk, &stdin);

    tracing::info!("compress");
    let compressed_proof = prover.compress(&vk, core_proof, vec![]);

    tracing::info!("shrink");
    let shrink_proof = prover.shrink(&vk, compressed_proof);

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(&vk, shrink_proof);

    (prover.wrap_vk, wrapped_proof)
}

/// Build the verifier constraints and template witness for the circuit.
fn build_constraints(
    wrap_vk: &StarkVerifyingKey<OuterSC>,
    wrapped_proof: &ShardProof<OuterSC>,
) -> (Vec<Constraint>, Witness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(wrap_vk, wrapped_proof.clone()));

    let pv = RecursionPublicValues::from_vec(wrapped_proof.public_values.clone());
    let vkey_hash = babybears_to_bn254(&pv.sp1_vk_digest);
    let committed_values_digest_bytes: [BabyBear; 32] = words_to_bytes(&pv.committed_value_digest)
        .try_into()
        .unwrap();
    let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    wrapped_proof.write(&mut witness);
    witness.write_commited_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

/// Create a directory if it doesn't exist.
fn mkdirs(dir: &PathBuf) {
    if !dir.exists() {
        std::fs::create_dir_all(dir).expect("Failed to create directory");
    }
}

/// Build the groth16 circuit artifacts.
pub fn build_groth16_artifacts(build_dir: PathBuf) {
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    let (wrap_vk, wrapped_proof) = dummy_proof();
    let (constraints, witness) = build_constraints(&wrap_vk, &wrapped_proof);

    tracing::info!("sanity check gnark test");
    Groth16Prover::test(constraints.clone(), witness.clone());

    mkdirs(&build_dir);

    tracing::info!("gnark build");
    Groth16Prover::build(constraints.clone(), witness.clone(), build_dir.clone());

    tracing::info!("gnark prove");
    let groth16_prover = Groth16Prover::new(build_dir.clone());
    groth16_prover.prove(witness.clone());
}

/// Build the plonk circuit artifacts.
pub fn build_plonk_artifacts(build_dir: PathBuf) {
    std::env::set_var("RECONSTRUCT_COMMITMENTS", "false");

    let (wrap_vk, wrapped_proof) = dummy_proof();
    let (constraints, witness) = build_constraints(&wrap_vk, &wrapped_proof);

    mkdirs(&build_dir);

    tracing::info!("plonk bn254 build");
    PlonkBn254Prover::build(constraints.clone(), witness.clone(), build_dir.clone());

    // tracing::info!("sanity check plonk bn254 prove");
    // PlonkBn254Prover::prove(witness.clone(), build_dir.clone());
}
