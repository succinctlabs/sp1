use sp1_core_machine::io::SP1Stdin;

pub use report::{write_measurements_to_csv, Measurement};

mod report;
pub mod telemetry;

pub const FIBONACCI_ELF: &[u8] =
    include_bytes!("../../prover_components/programs/fibonacci/riscv64im-succinct-zkvm-elf");
pub const KECCAK_ELF: &[u8] =
    include_bytes!("../../prover_components/programs/keccak/riscv64im-succinct-zkvm-elf");
pub const SHA2_ELF: &[u8] =
    include_bytes!("../../prover_components/programs/sha2/riscv64im-succinct-zkvm-elf");
pub const LOOP_ELF: &[u8] =
    include_bytes!("../../prover_components/programs/loop/riscv64im-succinct-zkvm-elf");
pub const POSEIDON2_ELF: &[u8] =
    include_bytes!("../../prover_components/programs/poseidon2/riscv64im-succinct-zkvm-elf");
pub const RSP_ELF: &[u8] = include_bytes!("../programs/rsp/elf/rsp-client");

pub fn get_program_and_input(program: String, param: String) -> (Vec<u8>, SP1Stdin) {
    // If the program elf is local, load it.
    if let Some(program_path) = program.strip_prefix("local-") {
        if program_path == "fibonacci" {
            let mut stdin = SP1Stdin::new();
            let n = param.parse::<usize>().unwrap_or(1000);
            stdin.write(&n);
            return (FIBONACCI_ELF.to_vec(), stdin);
        } else if program_path == "loop" {
            let mut stdin = SP1Stdin::new();
            let n = param.parse::<usize>().unwrap_or(1000);
            stdin.write(&n);
            return (LOOP_ELF.to_vec(), stdin);
        } else if program_path == "sha2" {
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(vec![0u8; param.parse::<usize>().unwrap_or(1000)]);
            return (SHA2_ELF.to_vec(), stdin);
        } else if program_path == "keccak" {
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(vec![0u8; param.parse::<usize>().unwrap_or(1000)]);
            return (KECCAK_ELF.to_vec(), stdin);
        } else if program_path == "poseidon2" {
            let mut stdin = SP1Stdin::new();
            let n = param.parse::<usize>().unwrap_or(1000);
            stdin.write(&n);
            return (POSEIDON2_ELF.to_vec(), stdin);
        } else if program_path == "rsp" {
            let mut stdin = SP1Stdin::new();
            let client_input_path = format!("sp1-gpu/crates/perf/programs/rsp/input/{param}.bin");
            let client_input = std::fs::read(client_input_path).unwrap();
            stdin.write_vec(client_input);
            return (RSP_ELF.to_vec(), stdin);
        } else {
            panic!("invalid program path provided: {program}");
        }
    }

    // Otherwise, assume it's a program from the s3 bucket.
    // Download files from S3
    let s3_path = program;
    let output = std::process::Command::new("aws")
        .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/program.bin"), "program.bin"])
        .output()
        .unwrap();
    if !output.status.success() {
        panic!("failed to download program.bin");
    }
    let output = if param.is_empty() {
        std::process::Command::new("aws")
            .args(["s3", "cp", &format!("s3://sp1-testing-suite/{s3_path}/stdin.bin"), "stdin.bin"])
            .output()
            .unwrap()
    } else {
        std::process::Command::new("aws")
            .args([
                "s3",
                "cp",
                &format!("s3://sp1-testing-suite/{s3_path}/input/{param}.bin"),
                "stdin.bin",
            ])
            .output()
            .unwrap()
    };
    if !output.status.success() {
        panic!("failed to download stdin.bin");
    }

    let program_path = "program.bin";
    let stdin_path = "stdin.bin";
    let program = std::fs::read(program_path).unwrap();
    let stdin = std::fs::read(stdin_path).unwrap();
    let stdin: SP1Stdin = bincode::deserialize(&stdin).unwrap();

    // remove the files
    std::fs::remove_file(program_path).unwrap();
    std::fs::remove_file(stdin_path).unwrap();

    (program, stdin)
}
