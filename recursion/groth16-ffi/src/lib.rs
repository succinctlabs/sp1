#![warn(unused_extern_crates)]

pub mod witness;

use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};
use sp1_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};
use witness::Groth16Witness;

/// A prover that can be prove circuits using Groth16 given a circuit definition and witness
/// defined by the recursion compiler.
pub struct Groth16Prover {
    pub binary: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    a: [String; 2],
    b: [[String; 2]; 2],
    c: [String; 2],
    public_inputs: [String; 2],
}

impl Groth16Prover {
    /// Creates a nejw verifier.
    pub fn new() -> Self {
        Groth16Prover {
            binary: concat!(env!("CARGO_MANIFEST_DIR"), "/build/bin").into(),
        }
    }

    /// Executes the prover with a given set of arguments.
    pub fn cmd(&self, args: &[&str]) {
        let result = Command::new(self.binary.clone())
            .args(args)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        if !result.status.success() {
            panic!("failed to call go binary");
        }
    }

    /// Executes the prover in testing mode with a circuit definition and witness.
    pub fn test<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let groth16_dir = format!("{}/../groth16", manifest_dir);

        // Write constraints.
        let mut constraints_file = tempfile::NamedTempFile::new().unwrap();
        constraints_file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = Groth16Witness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        let result = Command::new("go")
            .args([
                "test",
                "-tags=prover_checks",
                "-v",
                "-timeout",
                "100000s",
                "-run",
                "^TestMain$",
                "github.com/succinctlabs/sp1-recursion-groth16",
            ])
            .current_dir(groth16_dir)
            .env("WITNESS_JSON", witness_file.path().to_str().unwrap())
            .env(
                "CONSTRAINTS_JSON",
                constraints_file.path().to_str().unwrap(),
            )
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        if !result.status.success() {
            panic!("failed to run test circuit");
        }
    }

    pub fn build<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>, build_dir: PathBuf) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let groth16_dir = manifest_dir.join("../groth16");
        let cwd = std::env::current_dir().unwrap();

        // Write constraints.
        let constraints_path = build_dir.join("constraints.json");
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = build_dir.join("witness.json");
        let gnark_witness = Groth16Witness::new(witness);
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Run `make`.
        let make = Command::new("make")
            .current_dir(&groth16_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        if !make.status.success() {
            panic!("failed to run make");
        }

        // Run the build script.
        let result = Command::new("go")
            .args([
                "run",
                "main.go",
                "build",
                "--data",
                cwd.join(build_dir).to_str().unwrap(),
            ])
            .current_dir(groth16_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        if !result.status.success() {
            panic!("failed to run build script");
        }
    }

    pub fn prove<C: Config>(witness: Witness<C>, build_dir: PathBuf) -> Groth16Proof {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let groth16_dir = manifest_dir.join("../groth16");
        let cwd = std::env::current_dir().unwrap();

        // Write witness.
        let mut witness_file = tempfile::NamedTempFile::new().unwrap();
        let gnark_witness = Groth16Witness::new(witness);
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        witness_file.write_all(serialized.as_bytes()).unwrap();

        // Run `make`.
        let make = Command::new("make")
            .current_dir(&groth16_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        if !make.status.success() {
            panic!("failed to run make");
        }

        // Run the prove script.
        let proof_file = tempfile::NamedTempFile::new().unwrap();
        let result = Command::new("go")
            .args([
                "run",
                "main.go",
                "prove",
                "--data",
                cwd.join(build_dir).to_str().unwrap(),
                "--witness",
                witness_file.path().to_str().unwrap(),
                "--proof",
                proof_file.path().to_str().unwrap(),
            ])
            .current_dir(groth16_dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        if !result.status.success() {
            panic!("failed to run build script");
        }

        // Read the contents back from the tempfile.
        let mut buffer = String::new();
        proof_file
            .reopen()
            .unwrap()
            .read_to_string(&mut buffer)
            .unwrap();

        // Deserialize the JSON string back to a Groth16Proof instance
        let deserialized: Groth16Proof =
            serde_json::from_str(&buffer).expect("Error deserializing the proof");

        deserialized
    }
}

impl Default for Groth16Prover {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use crate::Groth16Prover;

    #[test]
    fn test_groth16_prove() {
        let prover = Groth16Prover::new();
        prover.cmd(&["prove", "--data", "./build"]);
    }
}
