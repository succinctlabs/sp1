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
    fn test_malicious_branches() {
        struct BranchTestCase {
            branch_opcode: Opcode,
            branch_operand_b_value: u32,
            branch_operand_c_value: u32,
            incorrect_next_pc: u32,
        }

        // The PC of the branch instruction is 8, and it will branch to 16 if the condition is true.
        let branch_test_cases = vec![
            BranchTestCase {
                branch_opcode: Opcode::BEQ,
                branch_operand_b_value: 5,
                branch_operand_c_value: 5,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BEQ,
                branch_operand_b_value: 5,
                branch_operand_c_value: 3,
                incorrect_next_pc: 16,
            },
            BranchTestCase {
                branch_opcode: Opcode::BNE,
                branch_operand_b_value: 5,
                branch_operand_c_value: 5,
                incorrect_next_pc: 16,
            },
            BranchTestCase {
                branch_opcode: Opcode::BNE,
                branch_operand_b_value: 5,
                branch_operand_c_value: 3,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BLTU,
                branch_operand_b_value: 5,
                branch_operand_c_value: 3,
                incorrect_next_pc: 16,
            },
            BranchTestCase {
                branch_opcode: Opcode::BLTU,
                branch_operand_b_value: 3,
                branch_operand_c_value: 5,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BLT,
                branch_operand_b_value: 0xFFFF_FFFF, // This is -1.
                branch_operand_c_value: 3,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BLT,
                branch_operand_b_value: 3,
                branch_operand_c_value: 0xFFFF_FFFF, // This is -1.
                incorrect_next_pc: 16,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGEU,
                branch_operand_b_value: 3,
                branch_operand_c_value: 5,
                incorrect_next_pc: 16,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGEU,
                branch_operand_b_value: 5,
                branch_operand_c_value: 5,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGEU,
                branch_operand_b_value: 5,
                branch_operand_c_value: 3,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGE,
                branch_operand_b_value: 0xFFFF_FFFF, // This is -1.
                branch_operand_c_value: 5,
                incorrect_next_pc: 16,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGE,
                branch_operand_b_value: 5,
                branch_operand_c_value: 5,
                incorrect_next_pc: 12,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGE,
                branch_operand_b_value: 3,
                branch_operand_c_value: 0xFFFF_FFFF, // This is -1.
                incorrect_next_pc: 12,
            },
        ];

        for test_case in branch_test_cases {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, test_case.branch_operand_b_value, false, true),
                Instruction::new(Opcode::ADD, 30, 0, test_case.branch_operand_c_value, false, true),
                Instruction::new(test_case.branch_opcode, 29, 30, 8, false, true),
                Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
                Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
            ];
            let program = Program::new(instructions, 0, 0);
            let stdin = SP1Stdin::new();

            type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

            let malicious_trace_pv_generator =
                move |prover: &P,
                      record: &mut ExecutionRecord|
                      -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                    // Create a malicious record where the BEQ instruction branches incorrectly.
                    let mut malicious_record = record.clone();
                    malicious_record.cpu_events[2].next_pc = test_case.incorrect_next_pc;
                    malicious_record.branch_events[0].next_pc = test_case.incorrect_next_pc;
                    prover.generate_traces(&malicious_record)
                };

            let result =
                run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
            assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
        }
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
             record: &mut ExecutionRecord|
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

        let result =
            run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }
}
