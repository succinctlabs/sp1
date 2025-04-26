use std::{
    io::{Error, Result},
    path::PathBuf,
};

use sp1_build::build_program_with_args;

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

    Ok(())
}
