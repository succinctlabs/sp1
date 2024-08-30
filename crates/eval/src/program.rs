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
];

pub fn load_program(elf: &[u8], input: &[u8]) -> (Vec<u8>, SP1Stdin) {
    let stdin: SP1Stdin = bincode::deserialize(input).expect("failed to deserialize input");
    (elf.to_vec(), stdin)
}
