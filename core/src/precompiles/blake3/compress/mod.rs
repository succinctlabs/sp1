mod columns;
mod compress_inner;
mod execute;
mod mix;
mod round;

/// The number of `Word`s in a Blake3 block.
pub(crate) const B3_BLOCK_SIZE: usize = 16;

pub struct Blake3CompressInnerChip {}

impl Blake3CompressInnerChip {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod compress_tests {
    use crate::runtime::Instruction;
    use crate::runtime::Opcode;
    use crate::runtime::Syscall;
    use crate::utils::prove;
    use crate::utils::setup_logger;
    use crate::Program;

    pub fn blake3_compress_internal_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![];
        let block_words_length = 16;
        let block_len_length = 1;
        let cv_words_length = 8;
        let counter_length = 2; // 2 u32's.
        let flag_length = 1; // 2 u32's.
        let total_length =
            block_words_length + block_len_length + cv_words_length + counter_length + flag_length;

        for i in 0..total_length {
            // Store 100 + i in memory for the i-th word of the state. 100 + i is an arbitrary
            // number that is easy to spot while debugging.
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 29, 0, 100 + i as u32, false, true),
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i as u32 * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                Syscall::BLAKE3_COMPRESS_INNER as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        setup_logger();
        let program = blake3_compress_internal_program();
        prove(program);
    }

    // TODO: Create something like this for blake3.
    // #[test]
    // fn test_poseidon2_external_1_simple() {
    //     setup_logger();
    //     let program = Program::from(POSEIDON2_EXTERNAL_1_ELF);
    //     prove(program);
    // }
}
