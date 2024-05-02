//! This module contains functions for building the groth16 and plonk circuits. These are in
//! sp1_prover because they require a dummy proof to be generated during the build process.

use std::path::PathBuf;

use sp1_core::stark::StarkVerifyingKey;
use sp1_core::{io::SP1Stdin, stark::ShardProof};
use sp1_recursion_circuit::stark::build_wrap_circuit;
use sp1_recursion_circuit::witness::Witnessable;
use sp1_recursion_compiler::ir::Witness;
use sp1_recursion_compiler::{config::OuterConfig, constraints::Constraint};
use sp1_recursion_gnark_ffi::plonk_bn254::PlonkBn254Prover;
use sp1_recursion_gnark_ffi::Groth16Prover;

use crate::{OuterSC, SP1Prover};

/// Generate a dummy proof that we can use to build the circuit. We need this to know the shape of
/// the proof.
fn dummy_proof() -> (StarkVerifyingKey<OuterSC>, ShardProof<OuterSC>) {
    let elf = include_bytes!("../../examples/fibonacci/program/elf/riscv32im-succinct-zkvm-elf");

    tracing::info!("initializing prover");
    let prover = SP1Prover::new();

    tracing::info!("setup elf");
    let (pk, vk) = prover.setup(elf);

    tracing::info!("prove core");
    let stdin = SP1Stdin::new();
    let core_proof = prover.prove_core(&pk, &stdin);

    tracing::info!("reduce");
    let reduced_proof = prover.compress(&vk, core_proof, vec![]);

    tracing::info!("compress");
    let compressed_proof = prover.shrink(&vk, reduced_proof);

    tracing::info!("wrap");
    let wrapped_proof = prover.wrap_bn254(&vk, compressed_proof);

    (prover.wrap_vk, wrapped_proof)
}

/// Build the verifier constraints and template witness for the circuit.
fn build_circuit(
    wrap_vk: StarkVerifyingKey<OuterSC>,
    wrapped_proof: ShardProof<OuterSC>,
) -> (Vec<Constraint>, Witness<OuterConfig>) {
    tracing::info!("building verifier constraints");
    let constraints = tracing::info_span!("wrap circuit")
        .in_scope(|| build_wrap_circuit(&wrap_vk, wrapped_proof.clone()));

    tracing::info!("building template witness");
    let mut witness = Witness::default();
    wrapped_proof.write(&mut witness);

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
    let (constraints, witness) = build_circuit(wrap_vk, wrapped_proof);

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
    let (constraints, witness) = build_circuit(wrap_vk, wrapped_proof);

    mkdirs(&build_dir);

    tracing::info!("plonk bn254 build");
    PlonkBn254Prover::build(constraints.clone(), witness.clone(), build_dir.clone());

    // tracing::info!("sanity check plonk bn254 prove");
    // PlonkBn254Prover::prove(witness.clone(), build_dir.clone());
}
