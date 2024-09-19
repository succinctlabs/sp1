use clap::Parser;

use crate::{create_local_command, execute_command};
use anyhow::{Ok, Result};
use cargo_metadata::camino::Utf8PathBuf;
use std::path::PathBuf;

#[derive(Clone, Parser, Debug)]
pub struct CheckArgs {
    #[clap(
        long,
        action,
        value_delimiter = ',',
        help = "Space or comma separated list of features to activate"
    )]
    pub features: Vec<String>,

    #[clap(long, action, help = "Do not activate the `default` feature")]
    pub no_default_features: bool,

    #[clap(long, action, help = "Ignore `rust-version` specification in packages")]
    pub ignore_rust_version: bool,

    #[clap(
        alias = "bin",
        long,
        action,
        help = "Check only the specified binary",
        default_value = ""
    )]
    pub binary: String,
}

impl Default for CheckArgs {
    fn default() -> Self {
        Self {
            features: vec![],
            no_default_features: false,
            ignore_rust_version: false,
            binary: "".to_string(),
        }
    }
}

impl CheckArgs {
    pub fn get_command_args(&self) -> Vec<String> {
        let mut command_args = vec![
            "check".to_string(),
            "--release".to_string(),
            "--target".to_string(),
            crate::BUILD_TARGET.to_string(),
        ];

        if self.ignore_rust_version {
            command_args.push("--ignore-rust-version".to_string());
        }

        if !self.binary.is_empty() {
            command_args.push("--bin".to_string());
            command_args.push(self.binary.clone());
        }

        if !self.features.is_empty() {
            command_args.push("--features".to_string());
            command_args.push(self.features.join(","));
        }

        command_args
    }

    pub fn check_program(&self, program_dir: Option<PathBuf>) -> Result<()> {
        // If the program directory is not specified, use the current directory.
        let program_dir = program_dir
            .unwrap_or_else(|| std::env::current_dir().expect("Failed to get current directory."));
        let program_dir: Utf8PathBuf = program_dir
            .try_into()
            .expect("Failed to convert PathBuf to Utf8PathBuf");

        let cmd = create_local_command(&self.get_command_args(), &program_dir);

        let program_metadata_file = program_dir.join("Cargo.toml");
        let mut program_metadata_cmd = cargo_metadata::MetadataCommand::new();
        let program_metadata = program_metadata_cmd
            .manifest_path(program_metadata_file)
            .exec()
            .unwrap();

        // We don't support docker for cargo check.
        execute_command(cmd, false, &program_metadata)?;

        Ok(())
    }
}
