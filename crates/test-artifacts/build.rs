use std::{
    fs::read_dir,
    io::{Error, Result},
    path::PathBuf,
};

use sp1_build::{build_program_with, BuildScriptOpts};

fn main() -> Result<()> {
    let tests_path =
        [env!("CARGO_MANIFEST_DIR"), "programs"].iter().collect::<PathBuf>().canonicalize()?;
    let tests_dir = read_dir(tests_path)?;
    for dir in tests_dir {
        let dir_path = dir?.path();
        eprintln!("{:?}", dir_path);
        match dir_path.to_str() {
            Some(path) => {
                build_program_with(path, BuildScriptOpts { quiet: true, ..Default::default() })
            }
            None => return Err(Error::other(format!("expected {dir_path:?} to be valid UTF-8"))),
        }
    }
    Ok(())
}
