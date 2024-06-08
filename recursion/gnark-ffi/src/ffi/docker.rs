use sp1_core::SP1_CIRCUIT_VERSION;

use crate::PlonkBn254Proof;
use std::io::Write;
use std::process::Command;

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
        .unwrap_or_else(|_| format!("ghcr.io/succinctlabs/sp1-gnark:{}", SP1_CIRCUIT_VERSION))
}

/// Calls `docker run` with the given arguments and bind mounts.
fn call_docker(args: &[&str], mounts: &[(&str, &str)]) -> anyhow::Result<()> {
    log::info!("Running {} in docker", args[0]);
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm"]);
    for (src, dest) in mounts {
        cmd.arg("-v").arg(format!("{}:{}", src, dest));
    }
    cmd.arg(get_docker_image());
    cmd.args(args);
    if !cmd.status()?.success() {
        log::error!("Failed to run `docker run`: {:?}", cmd);
        return Err(anyhow::anyhow!("docker command failed"));
    }
    Ok(())
}

pub fn prove_plonk_bn254(data_dir: &str, witness_path: &str) -> PlonkBn254Proof {
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let mounts = [
        (data_dir, "/circuit"),
        (witness_path, "/witness"),
        (output_file.path().to_str().unwrap(), "/output"),
    ];
    assert_docker();
    call_docker(&["prove-plonk", "/circuit", "/witness", "/output"], &mounts)
        .expect("failed to prove with docker");
    bincode::deserialize_from(&output_file).expect("failed to deserialize result")
}

pub fn build_plonk_bn254(data_dir: &str) {
    let circuit_dir = if data_dir.ends_with("dev") {
        "/circuit_dev"
    } else {
        "/circuit"
    };
    let mounts = [(data_dir, circuit_dir)];
    assert_docker();
    call_docker(&["build-plonk", circuit_dir], &mounts).expect("failed to build with docker");
}

pub fn verify_plonk_bn254(
    data_dir: &str,
    proof: &str,
    vkey_hash: &str,
    committed_values_digest: &str,
) -> Result<(), String> {
    // Write proof string to a file since it can be large.
    let mut proof_file = tempfile::NamedTempFile::new().unwrap();
    proof_file.write_all(proof.as_bytes()).unwrap();
    let output_file = tempfile::NamedTempFile::new().unwrap();
    let mounts = [
        (data_dir, "/circuit"),
        (proof_file.path().to_str().unwrap(), "/proof"),
        (output_file.path().to_str().unwrap(), "/output"),
    ];
    assert_docker();
    call_docker(
        &[
            "verify-plonk",
            "/circuit",
            "/proof",
            vkey_hash,
            committed_values_digest,
            "/output",
        ],
        &mounts,
    )
    .expect("failed to verify with docker");
    let result = std::fs::read_to_string(output_file.path()).unwrap();
    if result == "OK" {
        Ok(())
    } else {
        Err(result)
    }
}

pub fn test_plonk_bn254(witness_json: &str, constraints_json: &str) {
    let mounts = [
        (constraints_json, "/constraints"),
        (witness_json, "/witness"),
    ];
    assert_docker();
    call_docker(&["test-plonk", "/constraints", "/witness"], &mounts)
        .expect("failed to test with docker");
}

pub fn test_babybear_poseidon2() {
    unimplemented!()
}
