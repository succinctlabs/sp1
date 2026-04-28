use sp1_core_machine::io::SP1Stdin;
use test_artifacts::{FIBONACCI_ELF, KECCAK256_ELF, SHA2_ELF};

/// Load a program and its stdin using the same `(program, param)` convention as the
/// `sp1-gpu-perf` `node` binary.
///
/// - `local-<name>`: built-in ELF from `test-artifacts`. `param` is interpreted per program.
/// - anything else: download `program.bin` and `stdin.bin` (or `input/<param>.bin`) from
///   `s3://sp1-testing-suite/<program>/` via the `aws` CLI.
pub fn get_program_and_input(program: String, param: String) -> (Vec<u8>, SP1Stdin) {
    (get_program(&program), get_input(&program, &param))
}

pub fn get_program(program: &str) -> Vec<u8> {
    if let Some(local) = program.strip_prefix("local-") {
        return match local {
            "fibonacci" => (*FIBONACCI_ELF).to_vec(),
            "sha2" => (*SHA2_ELF).to_vec(),
            "keccak" => (*KECCAK256_ELF).to_vec(),
            other => panic!("invalid local program: {other}"),
        };
    }

    let output = std::process::Command::new("aws")
        .args(["s3", "cp", &format!("s3://sp1-testing-suite/{program}/program.bin"), "program.bin"])
        .output()
        .expect("failed to run aws cli");
    if !output.status.success() {
        panic!("failed to download program.bin: {}", String::from_utf8_lossy(&output.stderr));
    }
    let bytes = std::fs::read("program.bin").unwrap();
    std::fs::remove_file("program.bin").unwrap();
    bytes
}

pub fn get_input(program: &str, param: &str) -> SP1Stdin {
    if let Some(local) = program.strip_prefix("local-") {
        let mut stdin = SP1Stdin::new();
        match local {
            "fibonacci" => {
                let n = param.parse::<usize>().unwrap_or(1000);
                stdin.write(&n);
            }
            "sha2" | "keccak" => {
                stdin.write_vec(vec![0u8; param.parse::<usize>().unwrap_or(1000)]);
            }
            other => panic!("invalid local program: {other}"),
        }
        return stdin;
    }

    let output = if param.is_empty() {
        std::process::Command::new("aws")
            .args(["s3", "cp", &format!("s3://sp1-testing-suite/{program}/stdin.bin"), "stdin.bin"])
            .output()
            .expect("failed to run aws cli")
    } else {
        std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{program}/input/{param}.bin"),
                "stdin.bin",
            ])
            .output()
            .expect("failed to run aws cli")
    };
    if !output.status.success() {
        panic!("failed to download stdin.bin: {}", String::from_utf8_lossy(&output.stderr));
    }
    let bytes = std::fs::read("stdin.bin").unwrap();
    std::fs::remove_file("stdin.bin").unwrap();
    bincode::deserialize(&bytes).expect("failed to deserialize stdin")
}
