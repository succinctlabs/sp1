pub mod witness;

use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

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
        let dir = format!("{}/../groth16", manifest_dir);

        // Write constraints.
        let constraints_path = format!("{}/constraints.json", dir);
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = format!("{}/witness.json", dir);
        let gnark_witness: Groth16Witness = witness.into();
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

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
            .current_dir(dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        if !result.status.success() {
            panic!("failed to run test circuit");
        }
    }

    pub fn build<C: Config>(constraints: Vec<Constraint>, witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let dir = format!("{}/../groth16", manifest_dir);

        // Write constraints.
        let constraints_path = format!("{}/constraints.json", dir);
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = format!("{}/witness.json", dir);
        let gnark_witness: Groth16Witness = witness.into();
        let mut file = File::create(witness_path).unwrap();
        let serialized = serde_json::to_string(&gnark_witness).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        let result = Command::new("go")
            .args(["run", "main.go", "build"])
            .current_dir(dir)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();

        if !result.status.success() {
            panic!("failed to run test circuit");
        }
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
