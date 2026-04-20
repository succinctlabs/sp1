use std::{
    io::{Error, Result},
    path::PathBuf,
};

use sp1_build::{build_program_with_args, BuildArgs};

fn main() -> Result<()> {
    let tests_path =
        [env!("CARGO_MANIFEST_DIR"), "programs"].iter().collect::<PathBuf>().canonicalize()?;

    build_program_with_args(
        tests_path
            .to_str()
            .ok_or_else(|| Error::other(format!("expected {tests_path:?} to be valid UTF-8")))?,
        Default::default(),
    );

    let fibo_blake3_path = [env!("CARGO_MANIFEST_DIR"), "programs", "fibonacci-blake3"]
        .iter()
        .collect::<PathBuf>()
        .canonicalize()?;

    build_program_with_args(
        fibo_blake3_path
            .to_str()
            .ok_or_else(|| Error::other(format!("expected {tests_path:?} to be valid UTF-8")))?,
        Default::default(),
    );

    // Build trap test programs separately because they enable the `untrusted_programs` feature
    // on sp1-zkvm. Building them in the main workspace would enable this feature for all programs.
    for trap_program in ["trap-exec", "trap-load-store"] {
        let trap_path = [env!("CARGO_MANIFEST_DIR"), "programs", trap_program]
            .iter()
            .collect::<PathBuf>()
            .canonicalize()?;

        build_program_with_args(
            trap_path
                .to_str()
                .ok_or_else(|| Error::other(format!("expected {trap_path:?} to be valid UTF-8")))?,
            Default::default(),
        );
    }

    build_program_with_args(
        "../verifier/guest-verify-programs",
        BuildArgs {
            binaries: vec!["groth16_verify".to_string(), "plonk_verify".to_string()],
            ..Default::default()
        },
    );

    build_program_with_args(
        "../verifier/guest-verify-programs",
        BuildArgs {
            binaries: vec!["groth16_verify_blake3".to_string(), "plonk_verify_blake3".to_string()],
            features: vec!["blake3".to_string()],
            ..Default::default()
        },
    );

    Ok(())
}
