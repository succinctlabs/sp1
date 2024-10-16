use std::{env, process::Command};

use crate::{BuildArgs, HELPER_TARGET_SUBDIR};
use cargo_metadata::camino::Utf8PathBuf;
use dirs::home_dir;

use super::utils::{get_program_build_args, get_rust_compiler_flags};

/// Get the command to build the program locally.
pub(crate) fn create_local_command(
    args: &BuildArgs,
    program_dir: &Utf8PathBuf,
    program_metadata: &cargo_metadata::Metadata,
) -> Command {
    let mut command = Command::new("cargo");
    let canonicalized_program_dir =
        program_dir.canonicalize().expect("Failed to canonicalize program directory");

    // If CC_riscv32im_succinct_zkvm_elf is not set, set it to the default C++ toolchain
    // downloaded by 'sp1up --c-toolchain'.
    if env::var("CC_riscv32im_succinct_zkvm_elf").is_err() {
        if let Some(home_dir) = home_dir() {
            let cc_path = home_dir.join(".sp1").join("bin").join("riscv32-unknown-elf-gcc");
            if cc_path.exists() {
                command.env("CC_riscv32im_succinct_zkvm_elf", cc_path);
            }
        }
    }

    // When executing the local command:
    // 1. Set the target directory to a subdirectory of the program's target directory to avoid
    //    build
    // conflicts with the parent process. Source: https://github.com/rust-lang/cargo/issues/6412
    // 2. Set the rustup toolchain to succinct.
    // 3. Set the encoded rust flags.
    // 4. Remove the rustc configuration, otherwise in a build script it will attempt to compile the
    //    program with the toolchain of the normal build process, rather than the Succinct
    //    toolchain.
    // 5. Remove all the environment variables related to cargo activated features and configuration
    //    options.
    command
        .current_dir(canonicalized_program_dir)
        .env("RUSTUP_TOOLCHAIN", "succinct")
        .env("CARGO_ENCODED_RUSTFLAGS", get_rust_compiler_flags(args))
        .env_remove("RUSTC")
        .env("CARGO_TARGET_DIR", program_metadata.target_directory.join(HELPER_TARGET_SUBDIR))
        // TODO: remove once trim-paths is supported - https://github.com/rust-lang/rust/issues/111540
        .env("RUSTC_BOOTSTRAP", "1") // allows trim-paths.
        .args(get_program_build_args(args));
    env::vars()
        .map(|v| v.0)
        .filter(|v| v.starts_with("CARGO_FEATURE_") || v.starts_with("CARGO_CFG_"))
        .fold(&mut command, Command::env_remove);
    command
}
