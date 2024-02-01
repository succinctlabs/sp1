use std::ops::Range;

use crate::precompiles::{MemoryReadRecord, MemoryWriteRecord};

use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS as P3_NUM_KECCAK_COLS};

use self::columns::P3_KECCAK_COLS_OFFSET;

mod air;
pub mod columns;
mod execute;
mod trace;

const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 32 bits, so it is 50 words.
const STATE_NUM_WORDS: usize = 25 * 2;

#[derive(Debug, Clone, Copy)]
pub struct KeccakPermuteEvent {
    pub clk: u32,
    pub pre_state: [u64; STATE_SIZE],
    pub post_state: [u64; STATE_SIZE],
    pub state_read_records: [MemoryReadRecord; STATE_NUM_WORDS],
    pub state_write_records: [MemoryWriteRecord; STATE_NUM_WORDS],
    pub state_addr: u32,
}

pub struct KeccakPermuteChip {
    p3_keccak: KeccakAir,
    p3_keccak_col_range: Range<usize>,
}

impl KeccakPermuteChip {
    pub fn new() -> Self {
        // Get offset of p3_keccak_cols in KeccakCols
        let p3_keccak_air = KeccakAir {};
        Self {
            p3_keccak: p3_keccak_air,
            p3_keccak_col_range: P3_KECCAK_COLS_OFFSET
                ..(P3_KECCAK_COLS_OFFSET + P3_NUM_KECCAK_COLS),
        }
    }
}

#[cfg(test)]
pub mod permute_tests {
    use crate::{
        runtime::{Instruction, Opcode, Program, Runtime},
        utils::{self, tests::KECCAK_PERMUTE_ELF, BabyBearPoseidon2, StarkUtils},
        SuccinctProver,
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
            Instruction::new(Opcode::ADD, 5, 0, 106, false, true),
            Instruction::new(Opcode::ADD, 10, 0, digest_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);

        Program::new(instructions, 0, 0)
    }

    #[test]
    pub fn test_keccak_permute_program_execute() {
        let program = keccak_permute_program();
        let mut runtime = Runtime::new(program);
        runtime.write_stdin_slice(&[10]);
        runtime.run()
    }

    #[test]
    fn prove_babybear() {
        utils::setup_logger();
        let config = BabyBearPoseidon2::new(&mut rand::thread_rng());
        let mut challenger = config.challenger();

        let program = keccak_permute_program();
        let mut runtime = tracing::info_span!("runtime.run(...)").in_scope(|| {
            let mut runtime = Runtime::new(program);
            runtime.write_stdin_slice(&[10]);
            runtime.run();
            runtime
        });

        tracing::info_span!("runtime.prove(...)").in_scope(|| {
            runtime.prove::<_, _, BabyBearPoseidon2>(&config, &mut challenger);
        });
    }

    #[test]
    fn test_keccak_permute_program_prove() {
        utils::setup_logger();
        let prover = SuccinctProver::new();
        prover.prove(KECCAK_PERMUTE_ELF);
    }
}
