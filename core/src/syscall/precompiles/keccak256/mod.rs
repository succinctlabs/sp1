mod air;
pub mod columns;
mod execute;
mod trace;

use p3_keccak_air::KeccakAir;
use serde::{Deserialize, Serialize};

use crate::runtime::{MemoryReadRecord, MemoryWriteRecord};

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 32 bits, so it is 50 words.
const STATE_NUM_WORDS: usize = STATE_SIZE * 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeccakPermuteEvent {
    pub lookup_id: u128,
    pub shard: u32,
    pub channel: u8,
    pub clk: u32,
    pub pre_state: [u64; STATE_SIZE],
    pub post_state: [u64; STATE_SIZE],
    pub state_read_records: Vec<MemoryReadRecord>,
    pub state_write_records: Vec<MemoryWriteRecord>,
    pub state_addr: u32,
}

pub struct KeccakPermuteChip {
    p3_keccak: KeccakAir,
}

impl KeccakPermuteChip {
    pub const fn new() -> Self {
        Self {
            p3_keccak: KeccakAir {},
        }
    }
}

#[cfg(test)]
pub mod permute_tests {
    use crate::runtime::SyscallCode;
    use crate::stark::DefaultProver;
    use crate::utils::{run_test, SP1CoreOpts};
    use crate::{
        runtime::{Instruction, Opcode, Program, Runtime},
        utils::{self, tests::KECCAK_PERMUTE_ELF},
    };

    pub fn keccak_permute_program() -> Program {
        let digest_ptr = 100;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 1, false, true)];
        for i in 0..(25 * 8) {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, digest_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(
                Opcode::ADD,
                5,
                0,
                SyscallCode::KECCAK_PERMUTE as u32,
                false,
                true,
            ),
            Instruction::new(Opcode::ADD, 10, 0, digest_ptr, false, true),
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
        ]);

        Program::new(instructions, 0, 0)
    }

    #[test]
    pub fn test_keccak_permute_program_execute() {
        utils::setup_logger();
        let program = keccak_permute_program();
        let mut runtime = Runtime::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }

    #[test]
    fn test_keccak_permute_prove_babybear() {
        utils::setup_logger();

        let program = keccak_permute_program();
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }

    #[test]
    fn test_keccak_permute_program_prove() {
        utils::setup_logger();
        let program = Program::from(KECCAK_PERMUTE_ELF);
        run_test::<DefaultProver<_, _>>(program).unwrap();
    }
}
