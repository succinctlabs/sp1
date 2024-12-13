use columns::NUM_MEMORY_INSTRUCTIONS_COLUMNS;
use p3_air::BaseAir;

pub mod air;
pub mod columns;
pub mod trace;

#[derive(Default)]
pub struct MemoryInstructionsChip;

impl<F> BaseAir<F> for MemoryInstructionsChip {
    fn width(&self) -> usize {
        NUM_MEMORY_INSTRUCTIONS_COLUMNS
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::BorrowMut;

    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{
        events::MemoryRecordEnum, ExecutionRecord, Instruction, Opcode, Program,
    };
    use sp1_stark::{
        air::MachineAir, baby_bear_poseidon2::BabyBearPoseidon2, CpuProver, MachineProver, Val,
    };

    use crate::{
        io::SP1Stdin,
        memory::{columns::MemoryInstructionsColumns, MemoryInstructionsChip},
        riscv::RiscvAir,
        utils::run_malicious_test,
    };

    #[test]
    fn test_malicious_sw() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true), // Set the stored value to 5.
            Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the address to 100.
            Instruction::new(Opcode::SW, 29, 30, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the incorrect value is saved to memory.
                let mut malicious_record = record.clone();
                if let MemoryRecordEnum::Write(mem_write_record) =
                    &mut malicious_record.memory_instr_events[0].mem_access
                {
                    mem_write_record.value = 8;
                }
                prover.generate_traces(&malicious_record)
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }

    #[test]
    fn test_malicious_sh_sb() {
        for opcode in [Opcode::SH, Opcode::SB] {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 0xDEADBEEF, false, true), // Set the stored value to 0xDEADBEEF.
                Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the address to 100.
                Instruction::new(opcode, 29, 30, 0, false, true),
            ];
            let program = Program::new(instructions, 0, 0);
            let stdin = SP1Stdin::new();

            type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

            let malicious_trace_generator =
                |prover: &P,
                 record: &ExecutionRecord|
                 -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                    // Create a malicious record where the full word is saved to memory.
                    // The correct memory value is 0xBEEF for SH and 0xEF for SB.
                    let mut malicious_record = record.clone();
                    if let MemoryRecordEnum::Write(mem_write_record) =
                        &mut malicious_record.memory_instr_events[0].mem_access
                    {
                        mem_write_record.value = 0xDEADBEEF;
                    }
                    prover.generate_traces(&malicious_record)
                };

            let result =
                run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_generator));
            assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
        }
    }

    #[test]
    fn test_malicious_lw() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true), // Set the stored value to 5.
            Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the address to 100.
            Instruction::new(Opcode::SW, 29, 30, 0, false, true), // Store the value to memory.
            Instruction::new(Opcode::LW, 25, 30, 0, false, true), // Load the value from memory.
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Create a malicious record where the incorrect value is loaded from memory.
                let mut malicious_record = record.clone();
                malicious_record.cpu_events[3].a = 8;
                malicious_record.memory_instr_events[1].a = 8;
                prover.generate_traces(&malicious_record)
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }

    #[test]
    fn test_malicious_lh_lb_lhu_lbu() {
        for opcode in [Opcode::LH, Opcode::LB, Opcode::LHU, Opcode::LBU] {
            let instructions = vec![
                Instruction::new(Opcode::ADD, 29, 0, 0xDEADBEEF, false, true), // Set the stored value to 5.
                Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the address to 100.
                Instruction::new(Opcode::SW, 29, 30, 0, false, true), // Store the value to memory.
                Instruction::new(opcode, 25, 30, 0, false, true),     // Load the value from memory.
            ];
            let program = Program::new(instructions, 0, 0);
            let stdin = SP1Stdin::new();

            type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

            let malicious_trace_generator =
                |prover: &P,
                 record: &ExecutionRecord|
                 -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                    // Create a malicious record where the incorrect value is loaded from memory.
                    // The correct `a` value is 0xFFFFBEEF for LH, 0xFFFFFEF for LB, 0xBEEF for LHU, 0xEF for LBU.
                    let mut malicious_record = record.clone();
                    malicious_record.cpu_events[3].a = 0xDEADBEEF;
                    malicious_record.memory_instr_events[1].a = 0xDEADBEEF;
                    prover.generate_traces(&malicious_record)
                };

            let result =
                run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_generator));

            match opcode {
                Opcode::LH | Opcode::LB => assert!(
                    result.is_err() && result.unwrap_err().is_local_cumulative_sum_failing()
                ),
                Opcode::LHU | Opcode::LBU => {
                    assert!(result.is_err() && result.unwrap_err().is_constraints_failing())
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_malicious_multiple_opcode_flags() {
        let instructions = vec![
            Instruction::new(Opcode::ADD, 29, 0, 5, false, true), // Set the stored value to 5.
            Instruction::new(Opcode::ADD, 30, 0, 100, false, true), // Set the address to 100.
            Instruction::new(Opcode::SW, 29, 30, 0, false, true),
        ];
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();

        type P = CpuProver<BabyBearPoseidon2, RiscvAir<BabyBear>>;

        let malicious_trace_generator =
            |prover: &P,
             record: &ExecutionRecord|
             -> Vec<(String, RowMajorMatrix<Val<BabyBearPoseidon2>>)> {
                // Modify the branch chip to have a row that has multiple opcode flags set.
                let mut traces = prover.generate_traces(record);
                let memory_instr_chip_name = <MemoryInstructionsChip as MachineAir<BabyBear>>::name(
                    &MemoryInstructionsChip {},
                );
                for (chip_name, trace) in traces.iter_mut() {
                    if *chip_name == memory_instr_chip_name {
                        let first_row: &mut [BabyBear] = trace.row_mut(0);
                        let first_row: &mut MemoryInstructionsColumns<BabyBear> =
                            first_row.borrow_mut();
                        assert!(first_row.is_sw == BabyBear::one());
                        first_row.is_lw = BabyBear::one();
                    }
                }
                traces
            };

        let result = run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_generator));
        assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
    }
}
