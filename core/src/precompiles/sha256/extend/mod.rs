mod air;
mod columns;
mod execute;
mod flags;
mod trace;

pub use columns::*;

use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};

#[derive(Debug, Clone, Copy)]
pub struct ShaExtendEvent {
    pub clk: u32,
    pub w_ptr: u32,
    pub w_i_minus_15_reads: [MemoryReadRecord; 48],
    pub w_i_minus_2_reads: [MemoryReadRecord; 48],
    pub w_i_minus_16_reads: [MemoryReadRecord; 48],
    pub w_i_minus_7_reads: [MemoryReadRecord; 48],
    pub w_i_writes: [MemoryWriteRecord; 48],
}

pub struct ShaExtendChip;

impl ShaExtendChip {
    pub fn new() -> Self {
        Self {}
    }
}

pub fn sha_extend(w: &mut [u32]) {
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

#[cfg(test)]
pub mod extend_tests {

    use p3_baby_bear::BabyBear;

    use p3_matrix::dense::RowMajorMatrix;

    use crate::{
        alu::AluEvent,
        runtime::{Instruction, Opcode, Program, Runtime, Segment},
        utils::{BabyBearPoseidon2, Chip, StarkUtils},
    };

    use super::ShaExtendChip;

    pub fn sha_extend_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..64 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 5, 0, 102, false, true),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn generate_trace() {
        let mut segment = Segment::default();
        segment.add_events = vec![AluEvent::new(0, Opcode::ADD, 14, 8, 6)];
        let chip = ShaExtendChip::new();
        let trace: RowMajorMatrix<BabyBear> = chip.generate_trace(&mut segment);
        println!("{:?}", trace.values)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new(&mut rand::thread_rng());
        let mut challenger = config.challenger();

        let program = sha_extend_program();
        let mut runtime = Runtime::new(program);
        runtime.write_stdin_slice(&[10]);
        runtime.run();

        runtime.prove::<_, _, BabyBearPoseidon2>(&config, &mut challenger);
    }
}
