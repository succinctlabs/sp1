use core::{
    borrow::{Borrow, BorrowMut},
    mem::{size_of, MaybeUninit},
};
use std::collections::HashMap;

use crate::{air::ProgramAirBuilder, program::InstructionCols, utils::next_multiple_of_32};
use slop_air::{Air, BaseAir, PairBuilder};
use slop_algebra::PrimeField32;
use slop_matrix::Matrix;
use slop_maybe_rayon::prelude::{ParallelBridge, ParallelIterator};
use sp1_core_executor::{ExecutionRecord, Program};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::{MachineAir, SP1AirBuilder};

/// The number of preprocessed program columns.
pub const NUM_PROGRAM_PREPROCESSED_COLS: usize = size_of::<ProgramPreprocessedCols<u8>>();

/// The number of columns for the program multiplicities.
pub const NUM_PROGRAM_MULT_COLS: usize = size_of::<ProgramMultiplicityCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramPreprocessedCols<T> {
    pub pc: [T; 3],
    pub instruction: InstructionCols<T>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct ProgramMultiplicityCols<T> {
    pub multiplicity: T,
}

/// A chip that implements addition for the opcodes ADD and ADDI.
#[derive(Default)]
pub struct ProgramChip;

impl ProgramChip {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<F: PrimeField32> MachineAir<F> for ProgramChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> &'static str {
        "Program"
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn num_rows(&self, input: &Self::Record) -> Option<usize> {
        let nb_rows = input.program.instructions.len();
        let size_log2 = input.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        Some(padded_nb_rows)
    }

    fn preprocessed_num_rows(&self, program: &Self::Program) -> Option<usize> {
        let instrs_len = program.instructions.len();
        Some(next_multiple_of_32(instrs_len, None))
    }

    fn preprocessed_num_rows_with_instrs_len(
        &self,
        _program: &Self::Program,
        instrs_len: usize,
    ) -> Option<usize> {
        Some(next_multiple_of_32(instrs_len, None))
    }

    fn generate_preprocessed_trace_into(
        &self,
        program: &Self::Program,
        buffer: &mut [MaybeUninit<F>],
    ) {
        debug_assert!(
            !program.instructions.is_empty() || program.preprocessed_shape.is_some(),
            "empty program"
        );
        // Generate the trace rows for each event.
        let nb_rows = program.instructions.len();
        let size_log2 = program.fixed_log2_rows::<F, _>(self);
        let padded_nb_rows = next_multiple_of_32(nb_rows, size_log2);
        assert!(matches!(
            padded_nb_rows.checked_mul(4),
            Some(last_idx) if last_idx < F::ORDER_U64 as usize,
        ));
        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(
                buffer_ptr,
                padded_nb_rows * NUM_PROGRAM_PREPROCESSED_COLS,
            )
        };
        let chunk_size = std::cmp::max((nb_rows + 1) / num_cpus::get(), 1);

        values
            .chunks_mut(chunk_size * NUM_PROGRAM_PREPROCESSED_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_PROGRAM_PREPROCESSED_COLS).enumerate().for_each(|(j, row)| {
                    let mut idx = i * chunk_size + j;
                    if idx >= nb_rows {
                        idx = 0;
                    }
                    let cols: &mut ProgramPreprocessedCols<F> = row.borrow_mut();
                    let pc = program.pc_base + idx as u64 * 4;
                    assert!(pc < (1 << 48));
                    cols.pc = [
                        F::from_canonical_u16((pc & 0xFFFF) as u16),
                        F::from_canonical_u16(((pc >> 16) & 0xFFFF) as u16),
                        F::from_canonical_u16(((pc >> 32) & 0xFFFF) as u16),
                    ];
                    let instruction = program.instructions[idx];
                    cols.instruction.populate(&instruction);
                });
            });
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {
        // Do nothing since this chip has no dependencies.
    }

    fn generate_trace_into(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
        buffer: &mut [MaybeUninit<F>],
    ) {
        // Generate the trace rows for each event.

        // Collect the number of times each instruction is called from the software cpu events.
        // Store it as a map of PC -> count.
        // Only count software events — APC-covered events are handled by the APC chip.
        let mut instruction_counts = HashMap::new();

        macro_rules! count_sw_events {
            ($events:expr, $fn_for:ident) => {{
                let spans = input.$fn_for(None);
                for &(start, end) in spans.spans() {
                    for event in &$events[start..end] {
                        let pc = event.0.pc;
                        instruction_counts.entry(pc).and_modify(|count| *count += 1).or_insert(1);
                    }
                }
            }};
        }

        count_sw_events!(input.add_events, add_events_for);
        count_sw_events!(input.addw_events, addw_events_for);
        count_sw_events!(input.addi_events, addi_events_for);
        count_sw_events!(input.sub_events, sub_events_for);
        count_sw_events!(input.subw_events, subw_events_for);
        count_sw_events!(input.bitwise_events, bitwise_events_for);
        count_sw_events!(input.mul_events, mul_events_for);
        count_sw_events!(input.divrem_events, divrem_events_for);
        count_sw_events!(input.lt_events, lt_events_for);
        count_sw_events!(input.shift_left_events, shift_left_events_for);
        count_sw_events!(input.shift_right_events, shift_right_events_for);
        count_sw_events!(input.branch_events, branch_events_for);
        count_sw_events!(input.memory_load_byte_events, memory_load_byte_events_for);
        count_sw_events!(input.memory_load_half_events, memory_load_half_events_for);
        count_sw_events!(input.memory_load_word_events, memory_load_word_events_for);
        count_sw_events!(input.memory_load_x0_events, memory_load_x0_events_for);
        count_sw_events!(input.memory_load_double_events, memory_load_double_events_for);
        count_sw_events!(input.memory_store_byte_events, memory_store_byte_events_for);
        count_sw_events!(input.memory_store_half_events, memory_store_half_events_for);
        count_sw_events!(input.memory_store_word_events, memory_store_word_events_for);
        count_sw_events!(input.memory_store_double_events, memory_store_double_events_for);
        count_sw_events!(input.jal_events, jal_events_for);
        count_sw_events!(input.jalr_events, jalr_events_for);
        count_sw_events!(input.utype_events, utype_events_for);
        count_sw_events!(input.syscall_events, syscall_events_for);

        // Note: The program table should only count trusted (i.e. not untrusted instructions.)
        // However, untrusted instructions are also included in the events vectors.
        // Intuitively this would cause a mismatch where the program table tries to receive
        // additional interactions due to thes untrusted instruction events. In reality, there is no
        // issue because rows are created over the program instructions which do not include
        // untrusted instructions, and the address space for program instructions are
        // protected and will never intersect with the address space for untrusted
        // instructions.

        let padded_nb_rows = <ProgramChip as MachineAir<F>>::num_rows(self, input).unwrap();
        let nb_instructions = input.program.instructions.len();

        unsafe {
            let padding_start = nb_instructions * NUM_PROGRAM_MULT_COLS;
            let padding_size = (padded_nb_rows - nb_instructions) * NUM_PROGRAM_MULT_COLS;
            if padding_size > 0 {
                core::ptr::write_bytes(buffer[padding_start..].as_mut_ptr(), 0, padding_size);
            }
        }

        let buffer_ptr = buffer.as_mut_ptr() as *mut F;
        let values = unsafe {
            core::slice::from_raw_parts_mut(buffer_ptr, nb_instructions * NUM_PROGRAM_MULT_COLS)
        };

        let chunk_size = std::cmp::max(nb_instructions / num_cpus::get(), 1);

        values.chunks_mut(chunk_size * NUM_PROGRAM_MULT_COLS).enumerate().par_bridge().for_each(
            |(i, rows)| {
                rows.chunks_mut(NUM_PROGRAM_MULT_COLS).enumerate().for_each(|(j, row)| {
                    let idx = i * chunk_size + j;
                    if idx < nb_instructions {
                        let pc = input.program.pc_base + idx as u64 * 4;
                        let cols: &mut ProgramMultiplicityCols<F> = row.borrow_mut();
                        cols.multiplicity =
                            F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                    }
                });
            },
        );
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F> BaseAir<F> for ProgramChip {
    fn width(&self) -> usize {
        NUM_PROGRAM_MULT_COLS
    }
}

impl<AB> Air<AB> for ProgramChip
where
    AB: SP1AirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &ProgramPreprocessedCols<AB::Var> = (*prep_local).borrow();
        let mult_local = main.row_slice(0);
        let mult_local: &ProgramMultiplicityCols<AB::Var> = (*mult_local).borrow();

        // Constrain the interaction with CPU table
        builder.receive_program(prep_local.pc, prep_local.instruction, mult_local.multiplicity);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use std::sync::Arc;

    use sp1_primitives::SP1Field;

    use slop_matrix::dense::RowMajorMatrix;
    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_hypercube::air::MachineAir;

    use crate::program::ProgramChip;

    #[test]
    fn generate_trace() {
        // main:
        //     addi x29, x0, 5
        //     addi x30, x0, 37
        //     add x31, x30, x29
        let instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 37, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        let shard = ExecutionRecord {
            program: Arc::new(Program::new(instructions, 0, 0)),
            ..Default::default()
        };
        let chip = ProgramChip::new();
        let trace: RowMajorMatrix<SP1Field> =
            chip.generate_trace(&shard, &mut ExecutionRecord::default());
        println!("{:?}", trace.values)
    }
}
