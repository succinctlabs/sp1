mod air;
mod columns;
mod trace;

pub use columns::*;
use p3_air::BaseAir;

#[derive(Default)]
pub struct BranchChip;

impl<F> BaseAir<F> for BranchChip {
    fn width(&self) -> usize {
        NUM_BRANCH_COLS
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_stark::{baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, MachineProver, Val};

    use crate::{io::SP1Stdin, riscv::RiscvAir, utils::run_test};

    #[test]
    fn test_malicious_beq() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 5, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the BEQ instruction branches incorrectly.
                let mut malicious_record = record.clone();
                malicious_record.cpu_events[2].next_pc = 12;
                malicious_record.branch_events[0].next_pc = 12;
                prover.generate_traces(&malicious_record)
            };

        let result = run_test::<P>(program, stdin, Some(Box::new(malicious_trace_generator)));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }
}
