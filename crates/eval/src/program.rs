// use sp1_sdk::SP1Stdin;
// use std::fs::File;
// use std::io::Read;

// #[derive(Clone)]
// pub struct TesterProgram {
//     pub name: &'static str,
//     pub elf: &'static str,
//     pub input: &'static str,
// }

// impl TesterProgram {
//     const fn new(name: &'static str, elf: &'static str, input: &'static str) -> Self {
//         Self { name, elf, input }
//     }
// }

// pub const PROGRAMS: &[TesterProgram] = &[
//     TesterProgram::new("fibonacci", "fibonacci/elf", "fibonacci/input.bin"),
//     TesterProgram::new("ssz-withdrawals", "ssz-withdrawals/elf", "ssz-withdrawals/input.bin"),
//     TesterProgram::new("rsa", "rsa/elf", "rsa/input.bin"),
//     TesterProgram::new("tendermint", "tendermint/elf", "tendermint/input.bin"),
//     TesterProgram::new("reth", "reth/elf", "reth/input.bin"),
//     TesterProgram::new("raiko", "raiko/elf", "raiko/input.bin"),
// ];

// pub fn load_program(elf_path: &str, input_path: &str) -> (Vec<u8>, SP1Stdin) {
//     let elf_path = format!("./programs/{}", elf_path);
//     let input_path = format!("./programs/{}", input_path);

//     let mut elf_file = File::open(elf_path).expect("failed to open elf");
//     let mut elf = Vec::new();
//     elf_file.read_to_end(&mut elf).expect("failed to read elf");

//     let input_file = File::open(input_path).expect("failed to open input");
//     let stdin: SP1Stdin =
//         bincode::deserialize_from(input_file).expect("failed to deserialize input");

//     (elf, stdin)
// }

use sp1_sdk::SP1Stdin;

#[derive(Clone)]
pub struct TesterProgram {
    pub name: &'static str,
    pub elf: &'static [u8],
    pub input: &'static [u8],
}

impl TesterProgram {
    const fn new(name: &'static str, elf: &'static [u8], input: &'static [u8]) -> Self {
        Self { name, elf, input }
    }
}

pub const PROGRAMS: &[TesterProgram] = &[
    TesterProgram::new(
        "fibonacci",
        include_bytes!("../programs/fibonacci/elf"),
        include_bytes!("../programs/fibonacci/input.bin"),
    ),
    TesterProgram::new(
        "ssz-withdrawals",
        include_bytes!("../programs/ssz-withdrawals/elf"),
        include_bytes!("../programs/ssz-withdrawals/input.bin"),
    ),
    TesterProgram::new(
        "tendermint",
        include_bytes!("../programs/tendermint/elf"),
        include_bytes!("../programs/tendermint/input.bin"),
    ),
    TesterProgram::new(
        "rsa",
        include_bytes!("../programs/rsa/elf"),
        include_bytes!("../programs/rsa/input.bin"),
    ),
    TesterProgram::new(
        "reth",
        include_bytes!("../programs/reth/elf"),
        include_bytes!("../programs/reth/input.bin"),
    ),
    TesterProgram::new(
        "raiko",
        include_bytes!("../programs/raiko/elf"),
        include_bytes!("../programs/raiko/input.bin"),
    ),
];

pub fn load_program(elf: &[u8], input: &[u8]) -> (Vec<u8>, SP1Stdin) {
    let stdin: SP1Stdin = bincode::deserialize(input).expect("failed to deserialize input");
    (elf.to_vec(), stdin)
}
