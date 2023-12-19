mod instruction;
mod opcode;
mod parse;
mod transpile;

use std::{fs::File, io::Read};

pub use instruction::*;
pub use opcode::*;
pub use parse::*;
pub use transpile::*;

pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;
pub const WORD_SIZE: usize = 4;

/// Disassemble a RV32IM ELF to a list of instructions that be executed by the VM.
pub fn disassemble(input: &[u8]) -> (Vec<Instruction>, u32) {
    // Parse the ELF file.
    let (instructions_u32, pc) = parse_elf(input);

    // Decode the instructions.
    let mut instructions = decode_instructions(&instructions_u32);

    // Perform optimization passes.
    instructions = ecall_translation_pass(&instructions);

    // Return the instructions and the program counter.
    (instructions, pc)
}

/// Disassemble a RV32IM ELF to a list of instructions that be executed by the VM from a file path.
pub fn disassemble_from_elf(path: &str) -> (Vec<Instruction>, u32) {
    let mut elf_code = Vec::new();
    File::open(path)
        .expect("failed to open input file")
        .read_to_end(&mut elf_code)
        .expect("failed to read from input file");
    disassemble(&elf_code)
}

#[cfg(test)]
pub mod tests {
    use crate::disassembler::disassemble_from_elf;

    #[test]
    fn test_fibonacci() {
        let (instructions, pc) = disassemble_from_elf("../programs/fib.s");
        println!("{:?}, {}", instructions, pc);
    }
}
