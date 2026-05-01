use hashbrown::HashMap;
use itertools::Itertools;
use rayon::iter::{ParallelBridge, ParallelIterator};
use slop_air::{Air, AirBuilder, BaseAir};
use slop_algebra::{AbstractField, PrimeField32};
use slop_matrix::Matrix;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ExecutionRecord, Opcode, Program, CLK_INC, PC_INC,
};
use sp1_derive::AlignedBorrow;

use sp1_hypercube::{air::MachineAir, Word};
use sp1_primitives::consts::WORD_SIZE;
use std::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{
        register::j_type::{JTypeReader, JTypeReaderInput},
        state::{CPUState, CPUStateInput},
    },
    air::{SP1CoreAirBuilder, SP1Operation},
    operations::{AddOperation, AddOperationInput},
    utils::next_multiple_of_32,
};

#[derive(Default)]
pub struct UTypeChip;

pub const NUM_UTYPE_COLS: usize = size_of::<UTypeColumns<u8>>();

impl<F> BaseAir<F> for UTypeChip {
    fn width(&self) -> usize {
        NUM_UTYPE_COLS
    }
}

/// The column layout for UType instructions.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct UTypeColumns<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: JTypeReader<T>,

    /// The value to add to op_b.
    pub addend: [T; WORD_SIZE - 1],

    /// Computation of `addend + op_b`.
    pub add_operation: AddOperation<T>,

    /// Flag to specify if it is an AUIPC instruction.  If false, then it's a LUI instruction.
    pub is_auipc: T,

    /// Whether the row is real.
    pub is_real: T,
}

impl<AB> Air<AB> for UTypeChip
where
    AB: SP1CoreAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &UTypeColumns<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);
        builder.assert_bool(local.is_auipc);

        let opcode = local.is_auipc * AB::Expr::from_canonical_u32(Opcode::AUIPC as u32)
            + (AB::Expr::one() - local.is_auipc) * AB::Expr::from_canonical_u32(Opcode::LUI as u32);

        let funct3_auipc = AB::Expr::from_canonical_u8(Opcode::AUIPC.funct3().unwrap_or(0));
        let funct7_auipc = AB::Expr::from_canonical_u8(Opcode::AUIPC.funct7().unwrap_or(0));
        let base_opcode_auipc = AB::Expr::from_canonical_u32(Opcode::AUIPC.base_opcode().0);
        let instr_type_auipc =
            AB::Expr::from_canonical_u32(Opcode::AUIPC.instruction_type().0 as u32);

        let funct3_lui = AB::Expr::from_canonical_u8(Opcode::LUI.funct3().unwrap_or(0));
        let funct7_lui = AB::Expr::from_canonical_u8(Opcode::LUI.funct7().unwrap_or(0));
        let base_opcode_lui = AB::Expr::from_canonical_u32(Opcode::LUI.base_opcode().0);
        let instr_type_lui = AB::Expr::from_canonical_u32(Opcode::LUI.instruction_type().0 as u32);

        let is_lui = AB::Expr::one() - local.is_auipc;
        let funct3 = local.is_auipc * funct3_auipc + is_lui.clone() * funct3_lui;
        let funct7 = local.is_auipc * funct7_auipc + is_lui.clone() * funct7_lui;
        let base_opcode = local.is_auipc * base_opcode_auipc + is_lui.clone() * base_opcode_lui;
        let instr_type = local.is_auipc * instr_type_auipc + is_lui * instr_type_lui;

        // Constrain the state of the CPU.
        <CPUState<AB::F> as SP1Operation<AB>>::eval(
            builder,
            CPUStateInput::new(
                local.state,
                [
                    local.state.pc[0] + AB::F::from_canonical_u32(PC_INC),
                    local.state.pc[1].into(),
                    local.state.pc[2].into(),
                ],
                AB::Expr::from_canonical_u32(CLK_INC),
                local.is_real.into(),
            ),
        );

        let addend: Word<AB::Expr> = Word([
            local.addend[0].into(),
            local.addend[1].into(),
            local.addend[2].into(),
            AB::Expr::zero(),
        ]);

        let expected_addend = builder.select_word(
            local.is_auipc,
            Word([
                local.state.pc[0].into(),
                local.state.pc[1].into(),
                local.state.pc[2].into(),
                AB::Expr::zero(),
            ]),
            Word::zero::<AB>(),
        );

        builder.assert_word_eq(addend.clone(), expected_addend);

        builder.when_not(local.is_real).assert_zero(local.adapter.op_a_0);
        let op_input = AddOperationInput::<AB>::new(
            addend,
            local.adapter.b().map(|x| x.into()),
            local.add_operation,
            local.is_real.into() - local.adapter.op_a_0.into(),
        );
        <AddOperation<AB::F> as SP1Operation<AB>>::eval(builder, op_input);

        // Constrain the program and register reads.
        <JTypeReader<AB::F> as SP1Operation<AB>>::eval(
            builder,
            JTypeReaderInput::new(
                local.state.clk_high::<AB>(),
                local.state.clk_low::<AB>(),
                local.state.pc,
                opcode,
                [instr_type, base_opcode, funct3, funct7],
                local.add_operation.value.map(|x| x.into()),
                local.adapter,
                local.is_real.into(),
            ),
        );
    }
}

impl<F: PrimeField32> MachineAir<F> for UTypeChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "UType"
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows =
            next_multiple_of_32(input.utype_events.len(), input.fixed_log2_rows::<F, _>(self));
        Some(nb_rows)
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        let padded_nb_rows = <UTypeChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let chunk_size = std::cmp::max((input.utype_events.len()) / num_cpus::get(), 1);
        let num_event_rows = input.utype_events.len();

        unsafe {
            let padding_start = num_event_rows * NUM_UTYPE_COLS;
            let padding_size = (padded_nb_rows - num_event_rows) * NUM_UTYPE_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values =
            unsafe { core::slice::from_raw_parts_mut(buffer_ptr, num_event_rows * NUM_UTYPE_COLS) };

        let blu_events = values
            .chunks_mut(chunk_size * NUM_UTYPE_COLS)
            .enumerate()
            .par_bridge()
            .map(|(i, rows)| {
                let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
                rows.chunks_mut(NUM_UTYPE_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    let cols: &mut UTypeColumns<F> = row.borrow_mut();

                    if idx < input.utype_events.len() {
                        let (event, record) = &input.utype_events[idx];
                        cols.is_auipc = F::from_bool(event.opcode == Opcode::AUIPC);
                        cols.is_real = F::one();
                        let a = if event.opcode == Opcode::AUIPC { event.pc } else { 0 };
                        cols.addend[0] = F::from_canonical_u16((a & 0xFFFF) as u16);
                        cols.addend[1] = F::from_canonical_u16((a >> 16) as u16);
                        cols.addend[2] = F::from_canonical_u16((a >> 32) as u16);
                        if record.op_a != 0 {
                            cols.add_operation.populate(&mut blu, a, event.b);
                        } else {
                            cols.add_operation.value = Word::from(0u64);
                        }
                        cols.state.populate(&mut blu, event.clk, event.pc);
                        cols.adapter.populate(&mut blu, *record);
                    }
                });
                blu
            })
            .collect::<Vec<_>>();

        output.add_byte_lookup_events_from_maps(blu_events.iter().collect_vec());
    }

    fn included(&self, shard: &Self::Record) -> bool {
        if let Some(shape) = shard.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !shard.utype_events.is_empty()
        }
    }

    fn column_names(&self) -> Vec<String> {
        UTypeColumns::<F>::struct_reflection().unwrap()
    }
}

// #[cfg(test)]
// mod tests {
//     use std::borrow::BorrowMut;

//     use sp1_primitives::SP1Field;
//     use slop_algebra::AbstractField;
//     use slop_matrix::dense::RowMajorMatrix;
//     use sp1_core_executor::{
//         ExecutionError, ExecutionRecord, Executor, Instruction, Opcode, Program, Simple,
//     };
//     use sp1_hypercube::{
//         air::MachineAir, koala_bear_poseidon2::SP1InnerPcs, chip_name, CpuProver,
//         MachineProver, SP1CoreOpts, Val,
//     };

//     use crate::{
//         control_flow::{AuipcChip, AuipcColumns},
//         io::SP1Stdin,
//         riscv::RiscvAir,
//         utils::run_malicious_test,
//     };

//     // TODO: Re-enable when we LOGUP-GKR working.
//     // #[test]
//     // fn test_malicious_auipc() {
//     //     let instructions = vec![
//     //         Instruction::new(Opcode::AUIPC, 29, 12, 12, true, true),
//     //         Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
//     //     ];
//     //     let program = Program::new(instructions, 0, 0);
//     //     let stdin = SP1Stdin::new();

//     //     type P = CpuProver<SP1InnerPcs, RiscvAir<SP1Field>>;

//     //     let malicious_trace_pv_generator =
//     //         |prover: &P,
//     //          record: &mut ExecutionRecord|
//     //          -> Vec<(String, RowMajorMatrix<Val<SP1InnerPcs>>)> {
//     //             // Create a malicious record where the AUIPC instruction result is incorrect.
//     //             let mut malicious_record = record.clone();
//     //             malicious_record.auipc_events[0].a = 8;
//     //             prover.generate_traces(&malicious_record)
//     //         };

//     //     let result =
//     //         run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
//     //     assert!(result.is_err() && result.unwrap_err().is_local_cumulative_sum_failing());
//     // }

//     #[test]
//     fn test_malicious_multiple_opcode_flags() {
//         let instructions = vec![
//             Instruction::new(Opcode::AUIPC, 29, 12, 12, true, true),
//             Instruction::new(Opcode::ADD, 10, 0, 0, false, false),
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
//                 let auipc_chip_name = chip_name!(AuipcChip, SP1Field);
//                 for (chip_name, trace) in traces.iter_mut() {
//                     if *chip_name == auipc_chip_name {
//                         let first_row: &mut [SP1Field] = trace.row_mut(0);
//                         let first_row: &mut AuipcColumns<SP1Field> = first_row.borrow_mut();
//                         assert!(first_row.is_auipc == SP1Field::one());
//                         first_row.is_unimp = SP1Field::one();
//                     }
//                 }
//                 traces
//             };

//         let result =
//             run_malicious_test::<P>(program, stdin, Box::new(malicious_trace_pv_generator));
//         assert!(result.is_err() && result.unwrap_err().is_constraints_failing());
//     }

//     #[test]
//     fn test_unimpl() {
//         let instructions = vec![Instruction::new(Opcode::UNIMP, 29, 12, 0, true, true)];
//         let program = Program::new(instructions, 0, 0);
//         let stdin = SP1Stdin::new();

//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.maximal_shapes = None;
//         runtime.write_vecs(&stdin.buffer);
//         let result = runtime.execute::<Simple>();

//         assert!(result.is_err() && result.unwrap_err() == ExecutionError::Unimplemented());
//     }

//     #[test]
//     fn test_ebreak() {
//         let instructions = vec![Instruction::new(Opcode::EBREAK, 29, 12, 0, true, true)];
//         let program = Program::new(instructions, 0, 0);
//         let stdin = SP1Stdin::new();

//         let mut runtime = Executor::new(program, SP1CoreOpts::default());
//         runtime.maximal_shapes = None;
//         runtime.write_vecs(&stdin.buffer);
//         let result = runtime.execute::<Simple>();

//         assert!(result.is_err() && result.unwrap_err() == ExecutionError::Breakpoint());
//     }
// }
