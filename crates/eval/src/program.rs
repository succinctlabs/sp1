use sp1_sdk::SP1Stdin;
use std::fs::File;
use std::io::Read;

#[derive(Clone)]
pub struct TesterProgram {
    pub name: &'static str,
    pub elf: &'static str,
    pub input: &'static str,
}

impl TesterProgram {
    const fn new(name: &'static str, elf: &'static str, input: &'static str) -> Self {
        Self { name, elf, input }
    }
}

pub const PROGRAMS: &[TesterProgram] = &[
    TesterProgram::new("fibonacci", "fibonacci/elf", "fibonacci/input.bin"),
    TesterProgram::new("ssz-withdrawals", "ssz-withdrawals/elf", "ssz-withdrawals/input.bin"),
    TesterProgram::new("tendermint", "tendermint/elf", "tendermint/input.bin"),
];

pub fn load_program(elf_path: &str, input_path: &str) -> (Vec<u8>, SP1Stdin) {
    let elf_path = format!("./programs/{}", elf_path);
    let input_path = format!("./programs/{}", input_path);

    let mut elf_file = File::open(elf_path).expect("failed to open elf");
    let mut elf = Vec::new();
    elf_file.read_to_end(&mut elf).expect("failed to read elf");

    let input_file = File::open(input_path).expect("failed to open input");
    let stdin: SP1Stdin =
        bincode::deserialize_from(input_file).expect("failed to deserialize input");

    (elf, stdin)
}
