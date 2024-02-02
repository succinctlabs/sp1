use crate::cpu::{MemoryReadRecord, MemoryWriteRecord};

// TODO: Eventually, I should have all these modules.
// mod air;
// mod columns;
// mod execute;
// mod trace;

// TODO: Make sure that I'm only adding columns that I need. I just copied and pasted these from SHA
// compress as a starting point, so these likely need to change quite a bit.
#[derive(Debug, Clone, Copy)]
pub struct Poseidon2ExternalEvent {
    pub clk: u32,
    pub w_and_h_ptr: u32,
    pub w: [u32; 64],
    pub h: [u32; 8],
    pub h_read_records: [MemoryReadRecord; 8],
    pub w_i_read_records: [MemoryReadRecord; 64],
    pub h_write_records: [MemoryWriteRecord; 8],
}

pub struct Poseidon2ExternalChip;

impl Poseidon2ExternalChip {
    pub fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod external_tests {

    use crate::{
        runtime::{Instruction, Opcode, Program, Runtime},
        utils::{BabyBearPoseidon2, StarkUtils},
    };

    // TODO: Make sure that I'm only adding columns that I need. I just copied and pasted these from SHA
    // compress as a starting point, so these likely need to change quite a bit.
    pub fn poseidon2_external_program() -> Program {
        let w_ptr = 100;
        let mut instructions = vec![Instruction::new(Opcode::ADD, 29, 0, 5, false, true)];
        for i in 0..64 {
            instructions.extend(vec![
                Instruction::new(Opcode::ADD, 30, 0, w_ptr + i * 4, false, true),
                Instruction::new(Opcode::SW, 29, 30, 0, false, true),
            ]);
        }
        instructions.extend(vec![
            Instruction::new(Opcode::ADD, 5, 0, 103, false, true),
            Instruction::new(Opcode::ADD, 10, 0, w_ptr, false, true),
            Instruction::new(Opcode::ECALL, 10, 5, 0, false, true),
        ]);
        Program::new(instructions, 0, 0)
    }

    #[test]
    fn prove_babybear() {
        let config = BabyBearPoseidon2::new(&mut rand::thread_rng());
        let mut challenger = config.challenger();

        let program = poseidon2_external_program();
        let mut runtime = Runtime::new(program);
        runtime.write_stdin_slice(&[10]);
        runtime.run();

        runtime.prove::<_, _, BabyBearPoseidon2>(&config, &mut challenger);
    }
}
