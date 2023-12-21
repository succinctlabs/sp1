mod elf;
mod instruction;

mod transpile;

use std::{fs::File, io::Read};

pub use elf::*;
pub use instruction::*;

pub use transpile::*;

use crate::runtime::Instruction;

pub const MAXIMUM_MEMORY_SIZE: u32 = u32::MAX;
pub const WORD_SIZE: usize = 4;

/// Disassemble a RV32IM ELF to a list of instructions that be executed by the VM.
pub fn disassemble(input: &[u8]) -> (Vec<Instruction>, u32) {
    // Parse the ELF file.
    let (instructions_u32, pc) = parse_elf(input);

    // Transpile the instructions.
    let mut instructions = transpile(&instructions_u32);

    // Perform optimization passes.
    instructions = ecall_analysis_pass(&instructions);

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
    use crate::{disassembler::disassemble_from_elf, runtime::Runtime};

    #[test]
    fn test_fibonacci() {
        let (instructions, pc) = disassemble_from_elf("../programs/fib.s");
        let mut runtime = Runtime::new(instructions.clone(), pc);
        runtime.write_witness(&[1, 2]);
        runtime.run();
        println!("{:#?}, {}", instructions, pc);
    }

    #[test]
    fn test_malloc() {
        let (instructions, pc) = disassemble_from_elf("/Users/jtguibas/Succinct/risc0/examples/target/riscv-guest/riscv32im-risc0-zkvm-elf/release/search_json");
        let mut runtime = Runtime::new(instructions.clone(), pc);
        runtime.write_witness(&[1, 2]);
        runtime.run();
        println!("{:#?}, {}", instructions, pc);
    }
}
