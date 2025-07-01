use crate::{Groth16Bn254Proof, PlonkBn254Proof, ProofBn254, SP1_CIRCUIT_VERSION};
use anyhow::{anyhow, Result};
use std::{io::Write, process::Command};

/// Represents the proof system being used
enum ProofSystem {
    Plonk,
    Groth16,
}

impl ProofSystem {
    fn as_str(&self) -> &'static str {
        match self {
            ProofSystem::Plonk => "plonk",
            ProofSystem::Groth16 => "groth16",
        }
    }
}

/// Checks that docker is installed and running.
fn check_docker() -> bool {
    let output = Command::new("docker").arg("info").output();
    output.is_ok() && output.unwrap().status.success()
}

/// Panics if docker is not installed and running.
fn assert_docker() {
    if !check_docker() {
        panic!("Failed to run `docker info`. Please ensure that docker is installed and running.");
    }
}

fn get_docker_image() -> String {
    std::env::var("SP1_GNARK_IMAGE")
        .unwrap_or_else(|_| format!("ghcr.io/succinctlabs/sp1-gnark:{SP1_CIRCUIT_VERSION}"))
}

/// Calls `docker run` with the given arguments and bind mounts.
///
/// Note: files created here by `call_docker` are read-only for after the process exits.
/// To fix this, manually set the docker user to the current user by supplying a `-u` flag.
fn call_docker(args: &[&str], mounts: &[(&str, &str)]) -> Result<()> {
    tracing::info!("Running {} in docker", args[0]);
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm"]);
    for (src, dest) in mounts {
        cmd.arg("-v").arg(format!("{src}:{dest}"));
    }
    cmd.arg(get_docker_image());
    cmd.args(args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let result = cmd.output()?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stdout = String::from_utf8_lossy(&result.stdout);
        tracing::error!("Failed to run `docker run`: {:?}", cmd);
        tracing::error!("status: {:?}", result.status);
        tracing::error!("stderr: {:?}", stderr);

        return Err(anyhow!("Docker command failed \n stdout: {:?}\n stderr: {:?}", stdout, stderr));
    }
    Ok(())
}

fn prove(system: ProofSystem, data_dir: &str, witness_path: &str) -> Result<Vec<u8>> {
    let output_file = tempfile::NamedTempFile::new()?;
    let mounts = [
        (data_dir, "/circuit"),
        (witness_path, "/witness"),
        (output_file.path().to_str().unwrap(), "/output"),
    ];
    assert_docker();
    call_docker(
        &["prove", "--system", system.as_str(), "/circuit", "/witness", "/output"],
        &mounts,
    )?;
    Ok(std::fs::read(output_file.path())?)
}

pub fn prove_plonk_bn254(data_dir: &str, witness_path: &str) -> PlonkBn254Proof {
    let result =
        prove(ProofSystem::Plonk, data_dir, witness_path).expect("failed to prove with docker");
    let deserialized: ProofBn254 =
        bincode::deserialize(&result).expect("failed to deserialize result");
    match deserialized {
        ProofBn254::Plonk(proof) => proof,
        _ => panic!("unexpected proof type"),
    }
}

pub fn prove_groth16_bn254(data_dir: &str, witness_path: &str) -> Groth16Bn254Proof {
    let result =
        prove(ProofSystem::Groth16, data_dir, witness_path).expect("failed to prove with docker");
    let deserialized: ProofBn254 =
        bincode::deserialize(&result).expect("failed to deserialize result");
    match deserialized {
        ProofBn254::Groth16(proof) => proof,
        _ => panic!("unexpected proof type"),
    }
}

fn build(system: ProofSystem, data_dir: &str) -> Result<()> {
    let circuit_dir = if data_dir.ends_with("dev") { "/circuit_dev" } else { "/circuit" };
    let mounts = [(data_dir, circuit_dir)];
    assert_docker();
    call_docker(&["build", "--system", system.as_str(), circuit_dir], &mounts)
}

pub fn build_plonk_bn254(data_dir: &str) {
    build(ProofSystem::Plonk, data_dir).expect("failed to build with docker");
}

pub fn build_groth16_bn254(data_dir: &str) {
    build(ProofSystem::Groth16, data_dir).expect("failed to build with docker");
}

fn verify(
    system: ProofSystem,
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
) -> Result<()> {
    let mut proof_file = tempfile::NamedTempFile::new()?;
    proof_file.write_all(proof.as_bytes())?;
    let output_file = tempfile::NamedTempFile::new()?;
    let mounts = [
        (data_dir, "/circuit"),
        (proof_file.path().to_str().unwrap(), "/proof"),
        (output_file.path().to_str().unwrap(), "/output"),
    ];
    assert_docker();
    call_docker(
        &[
            "verify",
            "--system",
            system.as_str(),
            "/circuit",
            "/proof",
            vkey_hash,
            committed_values_digest,
            "/output",
        ],
        &mounts,
    )?;
    let result = std::fs::read_to_string(output_file.path())?;
    if result == "OK" {
        Ok(())
    } else {
        Err(anyhow!(result))
    }
}

pub fn verify_plonk_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
) -> Result<()> {
    verify(ProofSystem::Plonk, data_dir, proof, vkey_hash, committed_values_digest)
}

pub fn verify_groth16_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
) -> Result<()> {
    verify(ProofSystem::Groth16, data_dir, proof, vkey_hash, committed_values_digest)
}

fn test(system: ProofSystem, witness_json: &str, constraints_json: &str) -> Result<()> {
    let mounts = [(witness_json, "/witness"), (constraints_json, "/constraints")];
    assert_docker();
    call_docker(&["test", "--system", system.as_str(), "/witness", "/constraints"], &mounts)
}

pub fn test_plonk_bn254(witness_json: &str, constraints_json: &str) {
    test(ProofSystem::Plonk, witness_json, constraints_json).expect("failed to test with docker");
}

pub fn test_groth16_bn254(witness_json: &str, constraints_json: &str) {
    test(ProofSystem::Groth16, witness_json, constraints_json).expect("failed to test with docker");
}

pub fn test_babybear_poseidon2() {
    unimplemented!()
}
