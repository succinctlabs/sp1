//! Checks Docker exit-code policy and public-input binding with small real gnark proofs.

#![cfg(not(feature = "native"))]

use sp1_recursion_gnark_ffi::ffi::{verify_groth16_bn254, verify_plonk_bn254};
use std::{fs, path::Path, process::Command};

type Verify = fn(&str, &str, &str, &str, &str, &str, &str) -> anyhow::Result<()>;

#[test]
#[ignore = "requires a freshly built SP1_GNARK_IMAGE and Go"]
fn docker_verification_exit_code_policy() {
    assert!(std::env::var("SP1_GNARK_IMAGE").is_ok(), "Set SP1_GNARK_IMAGE to the test image");
    let dir = tempfile::tempdir().unwrap();
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new("go")
        .arg("run")
        .arg(manifest.join("tests/fixtures/main.go"))
        .arg(dir.path())
        .current_dir(manifest.join("go"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    for (system, verify) in
        [("plonk", verify_plonk_bn254 as Verify), ("groth16", verify_groth16_bn254)]
    {
        for code in [0, 1, 3] {
            let proof =
                fs::read_to_string(dir.path().join(format!("{system}-{code}.proof"))).unwrap();
            let result = verify(
                dir.path().to_str().unwrap(),
                &proof,
                "11",
                "22",
                &code.to_string(),
                "33",
                "44",
            );
            assert_eq!(
                result.is_ok(),
                code == 0 || cfg!(feature = "experimental"),
                "{system}, exit code {code}: {result:?}"
            );
        }

        let proof = fs::read_to_string(dir.path().join(format!("{system}-1.proof"))).unwrap();
        // Opt-in must not bypass public-input binding or numeric parsing.
        for invalid in ["2", "invalid", "-1", "4294967296"] {
            assert!(
                verify(dir.path().to_str().unwrap(), &proof, "11", "22", invalid, "33", "44")
                    .is_err(),
                "{system} accepted exit code {invalid}"
            );
        }
    }
}
