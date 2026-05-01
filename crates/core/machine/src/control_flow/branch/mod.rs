mod air;
mod columns;
mod trace;

pub use columns::*;
use slop_air::BaseAir;
use std::marker::PhantomData;

use crate::TrustMode;

#[derive(Default)]
pub struct BranchChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

impl<F, M: TrustMode> BaseAir<F> for BranchChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_BRANCH_COLS_SUPERVISOR
        } else {
            NUM_BRANCH_COLS_USER
        }
    }
}
/*
#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_hypercube::{
        air::MachineAir, koala_bear_poseidon2::SP1InnerPcs, chip_name, CpuProver,
        MachineProver, Val,
    };

//     use sp1_primitives::SP1Field;
//     use slop_algebra::AbstractField;
//     use slop_matrix::dense::RowMajorMatrix;
//     use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
//     use sp1_hypercube::{
//         air::MachineAir, koala_bear_poseidon2::SP1InnerPcs, chip_name, CpuProver,
//         MachineProver, Val,
//     };

    #[test]
    fn test_malicious_branches() {
        enum ErrorType {
            // TODO: Re-enable when we LOGUP-GKR working.
            // LocalCumulativeSumFailing,
            ConstraintsFailing,
        }

        struct BranchTestCase {
            branch_opcode: Opcode,
            branch_operand_b_value: u32,
            branch_operand_c_value: u32,
            incorrect_next_pc: u64,
            error_type: ErrorType,
        }

        // The PC of the branch instruction is 8, and it will branch to 16 if the condition is true.
        let branch_test_cases = vec![
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BEQ,
            //     branch_operand_b_value: 5,
            //     branch_operand_c_value: 5,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            BranchTestCase {
                branch_opcode: Opcode::BEQ,
                branch_operand_b_value: 5,
                branch_operand_c_value: 3,
                incorrect_next_pc: 16, // Correct next PC is 12.
                error_type: ErrorType::ConstraintsFailing,
            },
            BranchTestCase {
                branch_opcode: Opcode::BNE,
                branch_operand_b_value: 5,
                branch_operand_c_value: 5,
                incorrect_next_pc: 16, // Correct next PC is 12.
                error_type: ErrorType::ConstraintsFailing,
            },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BNE,
            //     branch_operand_b_value: 5,
            //     branch_operand_c_value: 3,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            BranchTestCase {
                branch_opcode: Opcode::BLTU,
                branch_operand_b_value: 5,
                branch_operand_c_value: 3,
                incorrect_next_pc: 16, // Correct next PC is 12.
                error_type: ErrorType::ConstraintsFailing,
            },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BLTU,
            //     branch_operand_b_value: 3,
            //     branch_operand_c_value: 5,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BLT,
            //     branch_operand_b_value: 0xFFFF_FFFF, // This is -1.
            //     branch_operand_c_value: 3,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            BranchTestCase {
                branch_opcode: Opcode::BLT,
                branch_operand_b_value: 3,
                branch_operand_c_value: 0xFFFF_FFFF, // This is -1.
                incorrect_next_pc: 16,               // Correct next PC is 12.
                error_type: ErrorType::ConstraintsFailing,
            },
            BranchTestCase {
                branch_opcode: Opcode::BGEU,
                branch_operand_b_value: 3,
                branch_operand_c_value: 5,
                incorrect_next_pc: 16, // Correct next PC is 12.
                error_type: ErrorType::ConstraintsFailing,
            },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BGEU,
            //     branch_operand_b_value: 5,
            //     branch_operand_c_value: 5,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BGEU,
            //     branch_operand_b_value: 5,
            //     branch_operand_c_value: 3,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            BranchTestCase {
                branch_opcode: Opcode::BGE,
                branch_operand_b_value: 0xFFFF_FFFF, // This is -1.
                branch_operand_c_value: 5,
                incorrect_next_pc: 16, // Correct next PC is 12.
                error_type: ErrorType::ConstraintsFailing,
            },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BGE,
            //     branch_operand_b_value: 5,
            //     branch_operand_c_value: 5,
            //     incorrect_next_pc: 12, // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
            // TODO: Re-enable when we LOGUP-GKR working.
            // BranchTestCase {
            //     branch_opcode: Opcode::BGE,
            //     branch_operand_b_value: 3,
            //     branch_operand_c_value: 0xFFFF_FFFF, // This is -1.
            //     incorrect_next_pc: 12,               // Correct next PC is 16.
            //     error_type: ErrorType::LocalCumulativeSumFailing,
            // },
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

            type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

            let malicious_trace_pv_generator =
                move |prover: &P,
                      record: &mut ExecutionRecord|
                      -> Vec<(String, RowMajorMatrix<Val<SP1InnerPcs>>)> {
                    // Create a malicious record where the BEQ instruction branches incorrectly.
                    let mut malicious_record = record.clone();
                    malicious_record.branch_events[0].next_pc = test_case.incorrect_next_pc;
                    prover.generate_traces(&malicious_record)
                };

            let result =
                run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));

            match test_case.error_type {
                // TODO: Re-enable when we LOGUP-GKR working.
                // ErrorType::LocalCumulativeSumFailing => {
                //     assert!(
                //         result.is_err() && result.unwrap_err().is_local_cumulative_sum_failing()
                //     );
                // }
                ErrorType::ConstraintsFailing => {
                    assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
                }
            }
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

        type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &mut ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<SP1InnerPcs>>)> {
                // Modify the branch chip to have a row that has multiple opcode flags set.
                let mut traces = prover.generate_traces(record);
                let branch_chip_name = chip_name!(BranchChip, SP1Field);
                for (chip_name, trace) in traces.iter_mut() {
                    if *chip_name == branch_chip_name {
                        let first_row = trace.row_mut(0);
                        let first_row: &mut BranchColumns<SP1Field> = first_row.borrow_mut();
                        assert!(first_row.is_beq == SP1Field::one());
                        first_row.is_bne = SP1Field::one();
                    }
                }
                traces
            };

        let result =
            run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }
}
 */
