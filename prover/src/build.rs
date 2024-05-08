use std::path::PathBuf;

use p3_baby_bear::BabyBear;
use sp1_core::stark::StarkVerifyingKey;
use sp1_core::{io::SP1Stdin, stark::ShardProof};
pub use sp1_recursion_circuit::stark::build_wrap_circuit;
pub use sp1_recursion_circuit::witness::Witnessable;
pub use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_compiler::{config::OuterConfig, constraints::Constraint};
use sp1_recursion_core::air::RecursionPublicValues;
use sp1_recursion_core::stark::utils::sp1_dev_mode;
use sp1_recursion_gnark_ffi::Groth16Prover;

use crate::install::{install_groth16_artifacts, install_groth16_artifacts_dir};
use crate::utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes};
use crate::{OuterSC, SP1Prover};

/// Build the groth16 artifacts to the given directory for the given verification key and template
/// proof.
pub fn build_groth16_artifacts(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
    build_dir: impl Into<PathBuf>,
) {
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof);
    Groth16Prover::build(constraints, witness, build_dir.into());
}

/// Builds the groth16 artifacts to the given directory.
///
/// This may take a while as it needs to first generate a dummy proof and then it needs to compile
/// the circuit.
pub fn build_groth16_artifacts_with_dummy(build_dir: impl Into<PathBuf>) {
    let (wrap_vk, wrapped_proof) = dummy_proof();
    crate::build::build_groth16_artifacts(&wrap_vk, &wrapped_proof, build_dir.into());
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &StarkVerifyingKey<OuterSC>,
    template_proof: &ShardProof<OuterSC>,
) -> (Vec<Constraint>, Witness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(template_vk, template_proof.clone()));

    let pv = RecursionPublicValues::from_vec(template_proof.public_values.clone());
    let vkey_hash = babybears_to_bn254(&pv.sp1_vk_digest);
    let committed_values_digest_bytes: [BabyBear; 32] = words_to_bytes(&pv.committed_value_digest)
        .try_into()
        .unwrap();
    let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    template_proof.write(&mut witness);
    witness.write_commited_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);

    (constraints, witness)
}

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
pub fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
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

    (prover.wrap_vk, wrapped_proof.proof)
}

/// Gets the artifacts directory for Groth16 based on the current environment variables.
///
/// - If `SP1_DEV` is enabled, we will use a smaller version of the final
/// circuit and rebuild it for every proof. This is useful for development and testing purposes, as
/// it allows us to test the end-to-end proving without having to wait for the circuit to compile or
/// download.
///
/// - Otherwise, assume this is an official release and download the artifacts from the official
/// download url.
pub fn get_groth16_artifacts_dir() -> PathBuf {
    if sp1_dev_mode() {
        let build_dir = dirs::home_dir()
            .unwrap()
            .join(".sp1")
            .join("circuits")
            .join("dev");
        if let Err(err) = std::fs::create_dir_all(&build_dir) {
            panic!(
                "failed to create build directory for groth16 artifacts: {}",
                err
            );
        }
        build_dir
    } else {
        install_groth16_artifacts();
        install_groth16_artifacts_dir()
    }
}
