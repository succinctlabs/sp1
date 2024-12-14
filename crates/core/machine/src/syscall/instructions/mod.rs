use columns::NUM_SYSCALL_INSTR_COLS;
use p3_air::BaseAir;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Default)]
pub struct SyscallInstrsChip;

impl<F> BaseAir<F> for SyscallInstrsChip {
    fn width(&self) -> usize {
        NUM_SYSCALL_INSTR_COLS
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
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, chip_name, CpuProver,
        MachineProver, Val,
    };
    use sp1_zkvm::syscalls::{COMMIT, COMMIT_DEFERRED_PROOFS, HALT, SHA_EXTEND};

    use crate::{
        cpu::{columns::CpuCols, CpuChip},
        io::SP1Stdin,
        riscv::RiscvAir,
        syscall::instructions::{columns::SyscallInstrColumns, SyscallInstrsChip},
        utils::run_malicious_test,
    };

    #[test]
    fn test_malicious_next_pc() {
        struct TestCase {
            program: Vec<Instruction>,
            incorrect_next_pc: u32,
        }

        let test_cases = vec![
            TestCase {
                program: vec![
                    Instruction::new(Opcode::ADD, 5, 0, HALT, false, true), // Set the syscall code in register x5.
                    Instruction::new(Opcode::ECALL, 5, 10, 11, false, false), // Call the syscall.
                    Instruction::new(Opcode::ADD, 30, 0, 100, false, true),
                ],
                incorrect_next_pc: 8, // The correct next_pc is 0.
            },
            TestCase {
                program: vec![
                    Instruction::new(Opcode::ADD, 5, 0, SHA_EXTEND, false, true), // Set the syscall code in register x5.
                    Instruction::new(Opcode::ADD, 10, 0, 40, false, true), // Set the syscall arg1 to 40.
                    Instruction::new(Opcode::ECALL, 5, 10, 11, false, false), // Call the syscall.
                    Instruction::new(Opcode::ADD, 30, 0, 100, false, true),
                ],
                incorrect_next_pc: 0, // The correct next_pc is 12.
            },
        ];

        for test_case in test_cases {
            let program = Program::new(test_case.program, 0, 0);
            let stdin = SP1Stdin::new();

            type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

            let malicious_trace_pv_generator =
                move |prover: &P,
                      record: &mut ExecutionRecord|
                      -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                    // Create a malicious record where the next pc is set to the incorrect value.
                    let mut malicious_record = record.clone();

                    // There can be multiple shards for programs with syscalls, so need to figure out which
                    // record is for a CPU shard.
                    if !malicious_record.cpu_events.is_empty() {
                        malicious_record.syscall_events[0].next_pc = test_case.incorrect_next_pc;
                    }

                    prover.generate_traces(&malicious_record)
                };

            let result =
                run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
            let syscall_chip_name = chip_name!(SyscallInstrsChip, BabyBear);
            assert!(
                result.is_err() && result.unwrap_err().is_constraints_failing(&syscall_chip_name)
            );
        }
    }

    #[test]
    fn test_malicious_extra_cycles() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, SHA_EXTEND, false, true), // Set the syscall code in register x5.
            Instruction::new(Opcode::ADD, 10, 0, 40, false, true), // Set the syscall arg1 to 40.
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false), // Call the syscall.
            Instruction::new(Opcode::ADD, 30, 20, 100, true, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &mut ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                let mut traces = prover.generate_traces(record);

                let cpu_chip_name = chip_name!(CpuChip, BabyBear);
                let syscall_chip_name = chip_name!(SyscallInstrsChip, BabyBear);

                for (chip_name, trace) in traces.iter_mut() {
                    if *chip_name == cpu_chip_name {
                        let third_row = trace.row_mut(2);
                        let third_row: &mut CpuCols<BabyBear> = third_row.borrow_mut();
                        assert!(third_row.is_syscall == BabyBear::one());
                        third_row.num_extra_cycles = BabyBear::from_canonical_usize(8);
                        // Correct value is 48.

                        let fourth_row = trace.row_mut(3);
                        let fourth_row: &mut CpuCols<BabyBear> = fourth_row.borrow_mut();
                        fourth_row.clk_16bit_limb = BabyBear::from_canonical_usize(20);
                        // Correct value is 60.
                    }

                    if *chip_name == syscall_chip_name {
                        let first_row = trace.row_mut(0);
                        let first_row: &mut SyscallInstrColumns<BabyBear> = first_row.borrow_mut();
                        first_row.num_extra_cycles = BabyBear::from_canonical_usize(4);
                        // Correct value is 48.
                    }
                }

                traces
            };

        let result =
            run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        let syscall_chip_name = chip_name!(SyscallInstrsChip, BabyBear);
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing(&syscall_chip_name));
    }

    #[test]
    fn test_malicious_commit() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, COMMIT, false, true), // Set the syscall code in register x5.
            Instruction::new(Opcode::ADD, 10, 0, 0, false, false), // Set the syscall code in register x5.
            Instruction::new(Opcode::ADD, 11, 0, 40, false, true), // Set the syscall arg1 to 40.
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false), // Call the syscall.
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &mut ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                record.public_values.committed_value_digest[0] = 10; // The correct value is 40.
                prover.generate_traces(record)
            };

        let result =
            run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        let syscall_chip_name = chip_name!(SyscallInstrsChip, BabyBear);
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing(&syscall_chip_name));
    }

    #[test]
    fn test_malicious_commit_deferred() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 5, 0, COMMIT_DEFERRED_PROOFS, false, true), // Set the syscall code in register x5.
            Instruction::new(Opcode::ADD, 10, 0, 0, false, false), // Set the syscall code in register x5.
            Instruction::new(Opcode::ADD, 11, 0, 40, false, true), // Set the syscall arg1 to 40.
            Instruction::new(Opcode::ECALL, 5, 10, 11, false, false), // Call the syscall.
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_pv_generator =
            |prover: &P,
             record: &mut ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                record.public_values.deferred_proofs_digest[0] = 10; // The correct value is 40.
                prover.generate_traces(record)
            };

        let result =
            run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
        let syscall_chip_name = chip_name!(SyscallInstrsChip, BabyBear);
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing(&syscall_chip_name));
    }
}
