mod air;
mod columns;
mod trace;

pub use columns::*;
use slop_air::BaseAir;
use std::marker::PhantomData;

use crate::TrustMode;

#[derive(Default)]
pub struct JalChip<M: TrustMode> {
    pub _phantom: PhantomData<M>,
}

impl<F, M: TrustMode> BaseAir<F> for JalChip<M> {
    fn width(&self) -> usize {
        if M::IS_TRUSTED {
            NUM_JAL_COLS_SUPERVISOR
        } else {
            NUM_JAL_COLS_USER
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use std::borrow::BorrowMut;

//     use sp1_primitives::SP1Field;
//     use slop_algebra::AbstractField;
//     use slop_matrix::dense::RowMajorMatrix;
//     use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
//     use sp1_hypercube::{
//         air::MachineAir, koala_bear_poseidon2::SP1InnerPcs, chip_name, CpuProver,
//         MachineProver, Val,
//     };

//     use crate::{
//         control_flow::{JumpChip, JumpColumns},
//         io::SP1Stdin,
//         riscv::RiscvAir,
//         utils::run_malicious_test,
//     };

//     // TODO: Re-enable when we LOGUP-GKR working.
//     // #[test]
//     // fn test_malicious_jumps() {
//     //     let mut jump_instructions = [
//     //         vec![Instruction::new(Opcode::JAL, 29, 8, 0, true, true)],
//     //         vec![
//     //             Instruction::new(Opcode::ADD, 28, 0, 8, false, true),
//     //             Instruction::new(Opcode::JALR, 29, 28, 0, false, true),
//     //         ],
//     //     ];

//     //     for instructions in jump_instructions.iter_mut() {
//     //         instructions.extend(vec![
//     //             Instruction::new(Opcode::ADD, 30, 0, 5, false, true),
//     //             Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
//     //             Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
//     //         ]);
//     //         let program = Program::new(instructions.to_vec(), 0, 0);
//     //         let stdin = SP1Stdin::new();

//     //         type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

//     //         let malicious_trace_pv_generator =
//     //             |prover: &P,
//     //              record: &mut ExecutionRecord|
//     //              -> Vec<(String, RowMajorMatrix<Val<SP1InnerPcs>>)> {
//     //                 let mut traces = prover.generate_traces(record);
//     //                 let jump_chip_name = chip_name!(JumpChip, SP1Field);
//     //                 for (chip_name, trace) in traces.iter_mut() {
//     //                     if *chip_name == jump_chip_name {
//     //                         let first_row = trace.row_mut(0);
//     //                         let first_row: &mut JumpColumns<SP1Field> =
// first_row.borrow_mut();     //                         first_row.next_pc = 4.into();
//     //                     }
//     //                 }

//     //                 traces
//     //             };

//     //         let result =
//     //             run_malicious_test::<P>(program, stdin,
// Box::new(malicious_trace_pv_generator));     //         assert!(result.is_err() &&
// result.unwrap_err().is_local_cumulative_sum_failing());     //     }
//     // }

//     #[test]
//     fn test_malicious_multiple_opcode_flags() {
//         let instructions = vec![
//             Instruction::new(Opcode::JAL, 29, 12, 0, true, true),
//             Instruction::new(Opcode::ADD, 30, 0, 5, false, true),
//             Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
//             Instruction::new(Opcode::ADD, 28, 0, 5, false, true),
//         ];
//         let program = Program::new(instructions, 0, 0);
//         let stdin = SP1Stdin::new();

//         type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

//         let malicious_trace_pv_generator =
//             |prover: &P,
//              record: &mut ExecutionRecord|
//              -> Vec<(String, RowMajorMatrix<Val<SP1InnerPcs>>)> {
//                 // Modify the branch chip to have a row that has multiple opcode flags set.
//                 let mut traces = prover.generate_traces(record);
//                 let jump_chip_name = chip_name!(JumpChip, SP1Field);
//                 for (chip_name, trace) in traces.iter_mut() {
//                     if *chip_name == jump_chip_name {
//                         let first_row = trace.row_mut(0);
//                         let first_row: &mut JumpColumns<SP1Field> = first_row.borrow_mut();
//                         assert!(first_row.is_jal == SP1Field::one());
//                         first_row.is_jalr = SP1Field::one();
//                     }
//                 }
//                 traces
//             };

//         let result =
//             run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
//         assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
//     }
// }
