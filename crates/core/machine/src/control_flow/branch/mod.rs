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
    use std::borrow::BorrowMut;

    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, MachineProver, Val,
    };

    use crate::{
        control_flow::{BranchChip, BranchColumns},
        io::SP1Stdin,
        riscv::RiscvAir,
        utils::run_malicious_test,
    };

    #[test]
    fn test_malicious_beq() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 5, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the BEQ instruction branches incorrectly.
                let mut malicious_record = record.clone();
                malicious_record.cpu_events[2].next_pc = 12;
                malicious_record.branch_events[0].next_pc = 12;
                prover.generate_traces(&malicious_record)
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }

    #[test]
    fn test_malicious_bne() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 4, false, true),
            Instruction::new(Opcode::BNE, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the BNE instruction branches incorrectly.
                let mut malicious_record = record.clone();
                malicious_record.cpu_events[2].next_pc = 12;
                malicious_record.branch_events[0].next_pc = 12;
                prover.generate_traces(&malicious_record)
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }

    #[test]
    fn test_malicious_blt() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 5, false, true),
            Instruction::new(Opcode::BLT, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the BLT instruction branches incorrectly.
                let mut malicious_record = record.clone();
                malicious_record.cpu_events[2].next_pc = 16;
                malicious_record.branch_events[0].next_pc = 16;
                prover.generate_traces(&malicious_record)
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }

    #[test]
    fn test_malicious_bge() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 3, false, true),
            Instruction::new(Opcode::BGE, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the BGE instruction branches incorrectly.
                let mut malicious_record = record.clone();
                malicious_record.cpu_events[2].next_pc = 12;
                malicious_record.branch_events[0].next_pc = 12;
                prover.generate_traces(&malicious_record)
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }

    #[test]
    fn test_malicious_multiple_opcode_flags() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 30, 0, 5, false, true),
            Instruction::new(Opcode::BEQ, 29, 30, 8, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Modify the branch chip to have a row that has multiple opcode flags set.
                let mut traces = prover.generate_traces(record);
                let branch_chip_name = <BranchChip as MachineAir<BabyBear>>::name(&BranchChip {});
                for (chip_name, trace) in traces.iter_mut() {
                    if *chip_name == branch_chip_name {
                        let first_row = trace.row_mut(0);
                        let first_row: &mut BranchColumns<BabyBear> = first_row.borrow_mut();
                        assert!(first_row.is_beq == BabyBear::one());
                        first_row.is_bne = BabyBear::one();
                    }
                }
                traces
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }
}
