use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::PrimeField;
use serde::Deserialize;
use serde::Serialize;
use sp1_recursion_compiler::{
    constraints::Constraint,
    ir::{Config, Witness},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Groth16Witness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
}

impl<C: Config> From<Witness<C>> for Groth16Witness {
    fn from(witness: Witness<C>) -> Self {
        Groth16Witness {
            vars: witness
                .vars
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            felts: witness
                .felts
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            exts: witness
                .exts
                .into_iter()
                .map(|w| {
                    w.as_base_slice()
                        .iter()
                        .map(|x| x.as_canonical_biguint().to_string())
                        .collect()
                })
                .collect(),
        }
    }
}

impl Groth16Witness {
    pub fn save(&self, path: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
}

pub struct Groth16Verifier {
    pub binary: PathBuf,
}

impl Groth16Verifier {
    pub fn new(binary: PathBuf) -> Self {
        Groth16Verifier { binary }
    }

    fn go_run(&self, args: &[&str]) {
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

    fn go_test(&self) {
        let result = Command::new("go")
            .args(["test", "-v", "-timeout", "100000s", "-run", "^TestMain$"])
            .current_dir(self.binary.parent().unwrap())
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stdin(Stdio::inherit())
            .output()
            .unwrap();
        if !result.status.success() {
            panic!("failed to run test circuit");
        }
    }

    pub fn prove_test<C: Config>(&self, constraints: Vec<Constraint>, mut witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let dir = self.binary.parent().unwrap();

        // Append some dummy elements to the witness to avoid compilation errors.
        witness.vars.push(C::N::from_canonical_usize(999));
        witness.felts.push(C::F::from_canonical_usize(999));
        witness.exts.push(C::EF::from_canonical_usize(999));

        // Write constraints.
        let constraints_path = format!("{}/constraints.json", dir.display());
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = format!("{}/witness.json", dir.display());
        let gnark_witness: Groth16Witness = witness.into();
        gnark_witness.save(&witness_path);

        self.go_run(&["test", "-v", "-timeout", "100000s", "-run", "^TestMain$"]);
    }

    pub fn prove<C: Config>(&self, constraints: Vec<Constraint>, mut witness: Witness<C>) {
        let serialized = serde_json::to_string(&constraints).unwrap();
        let dir = self.binary.parent().unwrap();

        // Append some dummy elements to the witness to avoid compilation errors.
        witness.vars.push(C::N::from_canonical_usize(999));
        witness.felts.push(C::F::from_canonical_usize(999));
        witness.exts.push(C::EF::from_canonical_usize(999));

        // Write constraints.
        let constraints_path = format!("{}/constraints.json", dir.display());
        let mut file = File::create(constraints_path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();

        // Write witness.
        let witness_path = format!("{}/witness.json", dir.display());
        let gnark_witness: Groth16Witness = witness.into();
        gnark_witness.save(&witness_path);

        self.go_run(&["run", "-v", "-timeout", "100000s"]);
    }

    
}

pub fn prove_test<C: Config>(constraints: Vec<Constraint>, mut witness: Witness<C>) {
    let serialized = serde_json::to_string(&constraints).unwrap();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dir = format!("{}/../groth16", manifest_dir);

    // Append some dummy elements to the witness to avoid compilation errors.
    witness.vars.push(C::N::from_canonical_usize(999));
    witness.felts.push(C::F::from_canonical_usize(999));
    witness.exts.push(C::EF::from_canonical_usize(999));

    // Write constraints.
    let constraints_path = format!("{}/constraints.json", dir);
    let mut file = File::create(constraints_path).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    // Write witness.
    let witness_path = format!("{}/witness.json", dir);
    let gnark_witness: Groth16Witness = witness.into();
    gnark_witness.save(&witness_path);

    let result = Command::new("go")
        .args([
            "test",
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
