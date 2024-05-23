mod elf;
mod instruction;

pub use elf::*;
pub use instruction::*;

use std::{collections::BTreeMap, fs::File, io::Read};

use crate::runtime::{Instruction, Program};

impl Program {
    /// Create a new program.
    pub const fn new(instructions: Vec<Instruction>, pc_start: u32, pc_base: u32) -> Self {
        Self {
            instructions,
            pc_start,
            pc_base,
            memory_image: BTreeMap::new(),
        }
    }

    /// Disassemble a RV32IM ELF to a program that be executed by the VM.
    pub fn from(input: &[u8]) -> Self {
        // Decode the bytes as an ELF.
        let elf = Elf::decode(input);

        // Transpile the RV32IM instructions.
        let instructions = transpile(&elf.instructions);

        // Return the program.
        Program {
            instructions,
            pc_start: elf.pc_start,
            pc_base: elf.pc_base,
            memory_image: elf.memory_image,
        }
    }

    /// Disassemble a RV32IM ELF to a program that be executed by the VM from a file path.
    pub fn from_elf(path: &str) -> Self {
        let mut elf_code = Vec::new();
        File::open(path)
            .expect("failed to open input file")
            .read_to_end(&mut elf_code)
            .expect("failed to read from input file");
        Program::from(&elf_code)
    }
}
