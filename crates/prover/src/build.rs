#![allow(clippy::print_stdout)] // This prints a progress bar

use anyhow::{anyhow, Context, Result};
use itertools::Itertools;
use sha2::{Digest, Sha256};
use slop_algebra::{AbstractField, PrimeField32};
use slop_bn254::Bn254Fr;
use sp1_hypercube::{koalabears_to_bn254, MachineVerifyingKey, SP1PcsProofOuter, ShardProof};
use sp1_primitives::{io::sha256_hash, SP1Field, SP1OuterGlobalContext};
use sp1_recursion_circuit::{
    hash::FieldHasherVariable,
    machine::{SP1ShapedWitnessValues, SP1WrapVerifier},
    utils::{koalabear_bytes_to_bn254, koalabears_proof_nonce_to_bn254},
};
use sp1_recursion_compiler::{
    config::OuterConfig,
    constraints::{Constraint, ConstraintCompiler},
    ir::Builder,
};
use sp1_recursion_executor::RecursionPublicValues;
use sp1_recursion_gnark_ffi::{
    ffi::{build_groth16_bn254, build_plonk_bn254},
    GnarkWitness,
};
use sp1_verifier::VK_ROOT_BYTES;
use std::{
    borrow::Borrow,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

pub use sp1_recursion_circuit::witness::{OuterWitness, Witnessable};

use {
    futures::StreamExt,
    indicatif::{ProgressBar, ProgressStyle},
    reqwest::Client,
    std::cmp::min,
    tokio::io::AsyncWriteExt,
    tokio::process::Command,
};

use crate::{
    components::{CpuSP1ProverComponents, SP1ProverComponents},
    utils::words_to_bytes,
    SP1_CIRCUIT_VERSION,
};

pub(crate) fn get_or_create_plonk_artifacts_dev_build_dir(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
) -> Result<PathBuf> {
    let dev_dir = plonk_bn254_artifacts_dev_dir(template_vk)?;
    if dev_dir.exists() {
        Ok(dev_dir)
    } else {
        crate::build::try_build_plonk_bn254_artifacts_dev(template_vk, template_proof)
    }
}

pub(crate) fn get_or_create_groth16_artifacts_dev_build_dir(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
) -> Result<PathBuf> {
    let dev_dir = groth16_bn254_artifacts_dev_dir(template_vk)?;
    if dev_dir.exists() {
        Ok(dev_dir)
    } else {
        crate::build::try_build_groth16_bn254_artifacts_dev(template_vk, template_proof)
    }
}

/// Tries to build the PLONK artifacts inside the development directory.
fn try_build_plonk_bn254_artifacts_dev(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
) -> Result<PathBuf> {
    let build_dir = plonk_bn254_artifacts_dev_dir(template_vk)?;
    if build_dir.exists() {
        tracing::info!("[sp1] plonk bn254 found (build_dir: {})", build_dir.display());
    } else {
        tracing::info!(
            "[sp1] building plonk bn254 artifacts in development mode (build_dir: {})",
            build_dir.display()
        );
        build_plonk_bn254_artifacts(template_vk, template_proof, &build_dir)?;
    }
    Ok(build_dir)
}

/// Tries to build the groth16 bn254 artifacts in the current environment.
fn try_build_groth16_bn254_artifacts_dev(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
) -> Result<PathBuf> {
    let build_dir = groth16_bn254_artifacts_dev_dir(template_vk)?;
    if build_dir.exists() {
        tracing::info!("[sp1] groth16 bn254 found (build_dir: {})", build_dir.display());
    } else {
        tracing::info!(
            "[sp1] building groth16 bn254 artifacts in development mode (build_dir: {})",
            build_dir.display()
        );
        build_groth16_bn254_artifacts(template_vk, template_proof, &build_dir)?;
    }
    Ok(build_dir)
}

/// Gets the directory where the PLONK artifacts are installed in development mode.
pub(crate) fn plonk_bn254_artifacts_dev_dir(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
) -> Result<PathBuf> {
    let serialized_vk = bincode::serialize(template_vk)?;
    let vk_hash_prefix = hex_prefix(sha256_hash(&serialized_vk));
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
    Ok(home_dir.join(".sp1").join("circuits").join(format!("{vk_hash_prefix}-plonk-dev")))
}

/// Gets the directory where the groth16 artifacts are installed in development mode.
pub(crate) fn groth16_bn254_artifacts_dev_dir(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
) -> Result<PathBuf> {
    let serialized_vk = bincode::serialize(template_vk)?;
    let vk_hash_prefix = hex_prefix(sha256_hash(&serialized_vk));
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
    Ok(home_dir.join(".sp1").join("circuits").join(format!("{vk_hash_prefix}-groth16-dev")))
}

fn hex_prefix(input: Vec<u8>) -> String {
    format!("{:016x}", u64::from_be_bytes(input[..8].try_into().unwrap()))
}

/// Build the plonk bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_plonk_bn254_artifacts(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
    build_dir: impl Into<PathBuf>,
) -> Result<()> {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir)?;
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof)?;

    // Serialize and write constraints.
    let serialized = serde_json::to_string(&constraints)?;
    let constraints_path = build_dir.join("constraints.json");
    let mut file = File::create(constraints_path)?;
    file.write_all(serialized.as_bytes())?;

    // Serialize and write witness.
    let witness_path = build_dir.join("plonk_witness.json");
    let gnark_witness = GnarkWitness::new(witness);
    let mut file = File::create(witness_path)?;
    let serialized = serde_json::to_string(&gnark_witness)?;
    file.write_all(serialized.as_bytes())?;

    // Build the circuit.
    let build_dir_str = build_dir
        .to_str()
        .ok_or_else(|| anyhow!("failed to convert path to string: {:?}", build_dir))?;
    build_plonk_bn254(build_dir_str);

    // Build the contracts.
    build_plonk_bn254_contracts(&build_dir)?;
    Ok(())
}

/// Build the groth16 bn254 artifacts to the given directory for the given verification key and
/// template proof.
pub fn build_groth16_bn254_artifacts(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
    build_dir: impl Into<PathBuf>,
) -> Result<()> {
    let build_dir = build_dir.into();
    std::fs::create_dir_all(&build_dir)?;
    let (constraints, witness) = build_constraints_and_witness(template_vk, template_proof)?;

    // Serialize and write constraints.
    let serialized = serde_json::to_string(&constraints)?;
    let constraints_path = build_dir.join("constraints.json");
    let mut file = File::create(constraints_path)?;
    file.write_all(serialized.as_bytes())?;

    // Serialize and write witness.
    let witness_path = build_dir.join("groth16_witness.json");
    let gnark_witness = GnarkWitness::new(witness);
    let mut file = File::create(witness_path)?;
    let serialized = serde_json::to_string(&gnark_witness)?;
    file.write_all(serialized.as_bytes())?;

    // Build the circuit.
    let build_dir_str = build_dir
        .to_str()
        .ok_or_else(|| anyhow!("failed to convert path to string: {:?}", build_dir))?;
    build_groth16_bn254(build_dir_str);

    // Build the contracts.
    build_groth16_bn254_contracts(&build_dir)?;
    Ok(())
}

/// Get the vkey hash for Plonk.
pub fn get_plonk_vkey_hash(build_dir: &Path) -> Result<[u8; 32]> {
    let vkey_path = build_dir.join("plonk_vk.bin");
    let vk_bin_bytes = std::fs::read(vkey_path)?;
    Ok(Sha256::digest(vk_bin_bytes).into())
}

/// Get the vkey hash for Groth16.
pub fn get_groth16_vkey_hash(build_dir: &Path) -> Result<[u8; 32]> {
    let vkey_path = build_dir.join("groth16_vk.bin");
    let vk_bin_bytes = std::fs::read(vkey_path)?;
    Ok(Sha256::digest(vk_bin_bytes).into())
}

/// Get the vk root as a hex string.
pub fn get_vk_root() -> String {
    hex::encode(*VK_ROOT_BYTES)
}

/// Build the Plonk contracts.
pub fn build_plonk_bn254_contracts(build_dir: &Path) -> Result<()> {
    let sp1_verifier_path = build_dir.join("SP1VerifierPlonk.sol");
    let vkey_hash = get_plonk_vkey_hash(build_dir)?;
    let vk_root = get_vk_root();
    let sp1_verifier_str = include_str!("../assets/SP1VerifierPlonk.txt")
        .replace("{SP1_CIRCUIT_VERSION}", SP1_CIRCUIT_VERSION)
        .replace("{VERIFIER_HASH}", format!("0x{}", hex::encode(vkey_hash)).as_str())
        .replace("{VK_ROOT}", format!("0x00{}", vk_root).as_str()) // Pad with a 0 byte because it's in a bn254.
        .replace("{PROOF_SYSTEM}", "Plonk");
    std::fs::write(sp1_verifier_path, sp1_verifier_str)?;
    Ok(())
}

/// Build the Groth16 contracts.
pub fn build_groth16_bn254_contracts(build_dir: &Path) -> Result<()> {
    let sp1_verifier_path = build_dir.join("SP1VerifierGroth16.sol");
    let vkey_hash = get_groth16_vkey_hash(build_dir)?;
    let vk_root = get_vk_root();
    let sp1_verifier_str = include_str!("../assets/SP1VerifierGroth16.txt")
        .replace("{SP1_CIRCUIT_VERSION}", SP1_CIRCUIT_VERSION)
        .replace("{VERIFIER_HASH}", format!("0x{}", hex::encode(vkey_hash)).as_str())
        .replace("{VK_ROOT}", format!("0x00{}", vk_root).as_str()) // Pad with a 0 byte because it's in a bn254.
        .replace("{PROOF_SYSTEM}", "Groth16");
    std::fs::write(sp1_verifier_path, sp1_verifier_str)?;
    Ok(())
}

/// Build the verifier constraints and template witness for the circuit.
pub fn build_constraints_and_witness(
    template_vk: &MachineVerifyingKey<SP1OuterGlobalContext>,
    template_proof: &ShardProof<SP1OuterGlobalContext, SP1PcsProofOuter>,
) -> Result<(Vec<Constraint>, OuterWitness<OuterConfig>)> {
    tracing::info!("building verifier constraints");
    let template_input = SP1ShapedWitnessValues {
        vks_and_proofs: vec![(template_vk.clone(), template_proof.clone())],
        is_complete: true,
    };
    let constraints =
        tracing::info_span!("wrap circuit").in_scope(|| build_outer_circuit(&template_input));

    let pv: &RecursionPublicValues<SP1Field> = template_proof.public_values.as_slice().borrow();
    let vkey_hash = koalabears_to_bn254(&pv.sp1_vk_digest);
    let committed_values_digest_bytes: [SP1Field; 32] =
        words_to_bytes(&pv.committed_value_digest).try_into().map_err(|_| {
            anyhow!("committed_value_digest has invalid length, expected exactly 32 elements")
        })?;
    let committed_values_digest = koalabear_bytes_to_bn254(&committed_values_digest_bytes);
    let exit_code = Bn254Fr::from_canonical_u32(pv.exit_code.as_canonical_u32());
    let vk_root = koalabears_to_bn254(&pv.vk_root);
    let proof_nonce = koalabears_proof_nonce_to_bn254(&pv.proof_nonce);
    tracing::info!("building template witness");
    let mut witness = OuterWitness::default();
    template_input.write(&mut witness);
    witness.write_committed_values_digest(committed_values_digest);
    witness.write_vkey_hash(vkey_hash);
    witness.write_exit_code(exit_code);
    witness.write_vk_root(vk_root);
    witness.write_proof_nonce(proof_nonce);
    Ok((constraints, witness))
}

fn build_outer_circuit(
    template_input: &SP1ShapedWitnessValues<SP1OuterGlobalContext, SP1PcsProofOuter>,
) -> Vec<Constraint> {
    let wrap_verifier = CpuSP1ProverComponents::wrap_verifier();
    let wrap_verifier = wrap_verifier.shard_verifier();
    let recursive_wrap_verifier =
        crate::recursion::recursive_verifier::<_, _, OuterConfig>(wrap_verifier);

    let wrap_span = tracing::debug_span!("build wrap circuit").entered();
    let mut builder = Builder::<OuterConfig>::default();

    // Get the value of the vk.
    let template_vk = template_input.vks_and_proofs.first().unwrap().0.clone();
    // Get an input variable.
    let input = template_input.read(&mut builder);

    // Fix the `wrap_vk` value to be the same as the template `vk`. Since the chip information and
    // the ordering is already a constant, we just need to constrain the commitment and pc_start.

    // Get the vk variable from the input.
    let vk = &input.vks_and_proofs.first().unwrap().0;
    // Get the expected commitment.
    let expected_commitment: [_; 1] = template_vk.preprocessed_commit.into();
    let expected_commitment = expected_commitment.map(|x| builder.eval(x));
    // Constrain `commit` to be the same as the template `vk`.
    SP1OuterGlobalContext::assert_digest_eq(
        &mut builder,
        expected_commitment,
        vk.preprocessed_commit,
    );
    // Constrain `pc_start` to be the same as the template `vk`.
    for (vk_pc, template_vk_pc) in vk.pc_start.iter().zip_eq(template_vk.pc_start.iter()) {
        builder.assert_felt_eq(*vk_pc, *template_vk_pc);
    }
    // Verify the proof.
    SP1WrapVerifier::verify(&mut builder, &recursive_wrap_verifier, input);

    let mut backend = ConstraintCompiler::<OuterConfig>::default();
    let operations = backend.emit(builder.into_operations());
    wrap_span.exit();

    operations
}

/// The base URL for the S3 bucket containing the circuit artifacts.
pub const CIRCUIT_ARTIFACTS_URL_BASE: &str = "https://sp1-circuits.s3-us-east-2.amazonaws.com";

/// Whether use the development mode for the circuit artifacts.
pub(crate) fn use_development_mode() -> bool {
    // TODO: Change this after v6.0.0 binary release
    std::env::var("SP1_CIRCUIT_MODE").unwrap_or("release".to_string()) == "dev"
}

/// The directory where the groth16 circuit artifacts will be stored.
pub fn groth16_circuit_artifacts_dir() -> Result<PathBuf> {
    let base_path = match std::env::var("SP1_GROTH16_CIRCUIT_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
            home_dir.join(".sp1").join("circuits/groth16")
        }
    };
    Ok(base_path.join(SP1_CIRCUIT_VERSION))
}

/// The directory where the plonk circuit artifacts will be stored.
pub fn plonk_circuit_artifacts_dir() -> Result<PathBuf> {
    let base_path = match std::env::var("SP1_PLONK_CIRCUIT_PATH") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("home directory not found"))?;
            home_dir.join(".sp1").join("circuits/plonk")
        }
    };
    Ok(base_path.join(SP1_CIRCUIT_VERSION))
}

/// Tries to install the circuit artifacts if they are not already installed.
pub async fn try_install_circuit_artifacts(artifacts_type: &str) -> Result<PathBuf> {
    let build_dir = if artifacts_type == "groth16" {
        groth16_circuit_artifacts_dir()?
    } else if artifacts_type == "plonk" {
        plonk_circuit_artifacts_dir()?
    } else {
        return Err(anyhow!("unsupported artifacts type: {}", artifacts_type));
    };

    if build_dir.exists() {
        tracing::info!(
            "[sp1] {} circuit artifacts already seem to exist at {}. if you want to re-download them, delete the directory",
            artifacts_type,
            build_dir.display()
        );
    } else {
        tracing::info!(
            "[sp1] {} circuit artifacts for version {} do not exist at {}. downloading...",
            artifacts_type,
            SP1_CIRCUIT_VERSION,
            build_dir.display()
        );

        install_circuit_artifacts(build_dir.clone(), artifacts_type).await?;
    }
    Ok(build_dir)
}

/// Install the latest circuit artifacts.
///
/// This function will download the latest circuit artifacts from the S3 bucket and extract them
/// to the directory specified by [`build_dir`].
#[allow(clippy::needless_pass_by_value)]
pub async fn install_circuit_artifacts(build_dir: PathBuf, artifacts_type: &str) -> Result<()> {
    // Create the build directory.
    std::fs::create_dir_all(&build_dir)?;

    // Download the artifacts.
    let download_url =
        format!("{CIRCUIT_ARTIFACTS_URL_BASE}/{SP1_CIRCUIT_VERSION}-{artifacts_type}.tar.gz");

    // Create a file in the build directory to store the tar.
    let tar_path = build_dir.join("artifacts.tar.gz");

    // Create a tokio friendly file to write the tarball to.
    let mut file = tokio::fs::File::create(&tar_path).await?;

    // Download the file.
    let client = Client::builder().build().context("failed to create reqwest client")?;
    download_file(&client, &download_url, &mut file).await?;
    file.flush().await?;

    // Extract the tarball to the build directory.
    let tar_path_str = tar_path
        .to_str()
        .ok_or_else(|| anyhow!("failed to convert path to string: {:?}", tar_path))?;
    let build_dir_str = build_dir
        .to_str()
        .ok_or_else(|| anyhow!("failed to convert path to string: {:?}", build_dir))?;

    let res =
        Command::new("tar").args(["-Pxzf", tar_path_str, "-C", build_dir_str]).output().await?;

    // Remove the tarball after extraction.
    tokio::fs::remove_file(&tar_path).await?;

    if !res.status.success() {
        return Err(anyhow!("failed to extract tarball to {}", build_dir_str));
    }

    eprintln!("[sp1] downloaded {} to {}", download_url, build_dir_str);
    Ok(())
}

/// Download the file with a progress bar that indicates the progress.
pub async fn download_file(
    client: &Client,
    url: &str,
    file: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<()> {
    let res =
        client.get(url).send().await.with_context(|| format!("failed to GET from '{}'", url))?;

    let total_size = res
        .content_length()
        .ok_or_else(|| anyhow!("failed to get content length from '{}'", url))?;

    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .context("failed to set progress bar style")?
            .progress_chars("#>-"),
    );

    let mut downloaded: u64 = 0;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.context("error while downloading file")?;
        file.write_all(&chunk).await?;
        let new = min(downloaded + (chunk.len() as u64), total_size);
        downloaded = new;
        pb.set_position(new);
    }
    pb.finish();

    Ok(())
}

#[cfg(test)]
mod tests {
    use sp1_core_executor::SP1Context;
    use sp1_core_machine::utils::setup_logger;
    use sp1_prover_types::network_base_types::ProofMode;

    use crate::{
        verify::WRAP_VK_BYTES,
        worker::{cpu_worker_builder, SP1LocalNodeBuilder},
    };

    #[tokio::test]
    #[ignore = "should be invoked when changing the wrap circuit"]
    async fn set_wrap_vk_and_wrapped_proof() {
        setup_logger();

        let elf = test_artifacts::FIBONACCI_ELF;

        tracing::info!("initializing prover");
        let client = SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder())
            .build()
            .await
            .expect("failed to build client");

        tracing::info!("prove compressed");
        let stdin = sp1_core_machine::io::SP1Stdin::new();
        let compressed_proof = client
            .prove_with_mode(&elf, stdin, SP1Context::default(), ProofMode::Compressed)
            .await
            .expect("failed to prove compressed");

        tracing::info!("shrink wrap");
        let wrapped_proof =
            client.shrink_wrap(&compressed_proof.proof).await.expect("failed to shrink wrap");
        let wrap_vk = wrapped_proof.vk;
        let wrapped_proof = wrapped_proof.proof;

        let wrap_vk_bytes = bincode::serialize(&wrap_vk).expect("failed to serialize wrap_vk");
        let wrapped_proof_bytes =
            bincode::serialize(&wrapped_proof).expect("failed to serialize wrapped_proof");
        std::fs::write("wrap_vk.bin", wrap_vk_bytes).expect("failed to write wrap_vk.bin");
        std::fs::write("wrapped_proof.bin", wrapped_proof_bytes)
            .expect("failed to write wrapped_proof.bin");
    }

    #[tokio::test]
    async fn test_wrap_vk() {
        setup_logger();

        tracing::info!("initializing prover");
        let client = SP1LocalNodeBuilder::from_worker_client_builder(cpu_worker_builder())
            .build()
            .await
            .expect("failed to build client");

        // Check that the wrap vk is the same as the one included in the binary.
        let client_wrap_vk = client.wrap_vk().clone();
        let expected_wrap_vk =
            bincode::deserialize(WRAP_VK_BYTES).expect("failed to deserialize WRAP_VK_BYTES");
        assert_eq!(client_wrap_vk, expected_wrap_vk);
    }
}
