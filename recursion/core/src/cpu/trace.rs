use std::borrow::BorrowMut;

use crate::{
    air::BinomialExtensionUtils,
    memory::MemoryCols,
    runtime::{
        get_heap_size_range_check_events, instruction_is_heap_expand, ExecutionRecord, Opcode,
        RecursionProgram, D,
    },
};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSliceMut;
use sp1_core::{
    air::{BinomialExtension, MachineAir},
    utils::{next_power_of_two, par_for_each_row},
};
use tracing::instrument;

use super::{CpuChip, CpuCols, NUM_CPU_COLS};

impl<F: PrimeField32 + BinomiallyExtendable<D>, const L: usize> MachineAir<F> for CpuChip<F, L> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // There are no dependencies, since we do it all in the runtime. This is just a placeholder.
    }

    #[instrument(name = "generate cpu trace", level = "debug", skip_all, fields(rows = input.cpu_events.len()))]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let nb_events = input.cpu_events.len();
        let padded_nb_rows = next_power_of_two(nb_events, self.fixed_log2_rows);
        let mut values = vec![F::zero(); padded_nb_rows * NUM_CPU_COLS];

        par_for_each_row(&mut values, NUM_CPU_COLS, |i, row| {
            if i >= nb_events {
                return;
            }
            let event = &input.cpu_events[i];
            let cols: &mut CpuCols<F> = row.borrow_mut();

            cols.clk = event.clk;
            cols.pc = event.pc;
            cols.fp = event.fp;

            // Populate the instruction related columns.
            cols.selectors.populate(&event.instruction);
            cols.instruction.populate(&event.instruction);

            // Populate the register columns.
            if let Some(record) = &event.a_record {
                cols.a.populate(record);
            }
            if let Some(record) = &event.b_record {
                cols.b.populate(record);
            } else {
                *cols.b.value_mut() = event.instruction.op_b;
            }
            if let Some(record) = &event.c_record {
                cols.c.populate(record);
            } else {
                *cols.c.value_mut() = event.instruction.op_c;
            }
            if let Some(record) = &event.memory_record {
                let memory_cols = cols.opcode_specific.memory_mut();
                memory_cols.memory.populate(record);
                memory_cols.memory_addr = record.addr;
            }

            // Populate the heap columns.
            if instruction_is_heap_expand(&event.instruction) {
                let (u16_range_check, u12_range_check) =
                    get_heap_size_range_check_events(cols.a.value()[0]);

                let heap_cols = cols.opcode_specific.heap_expand_mut();
                heap_cols.diff_16bit_limb = F::from_canonical_u16(u16_range_check.val);
                heap_cols.diff_12bit_limb = F::from_canonical_u16(u12_range_check.val);
            }

            // Populate the branch columns.
            if matches!(
                event.instruction.opcode,
                Opcode::BEQ | Opcode::BNE | Opcode::BNEINC
            ) {
                let branch_cols = cols.opcode_specific.branch_mut();
                let a_ext: BinomialExtension<F> =
                    BinomialExtensionUtils::from_block(*cols.a.value());
                let b_ext: BinomialExtension<F> =
                    BinomialExtensionUtils::from_block(*cols.b.value());

                let (comparison_diff, do_branch) = match event.instruction.opcode {
                    Opcode::BEQ => (a_ext - b_ext, a_ext == b_ext),
                    Opcode::BNE | Opcode::BNEINC => (a_ext - b_ext, a_ext != b_ext),
                    _ => unreachable!(),
                };

                branch_cols
                    .comparison_diff
                    .populate((comparison_diff).as_block());
                branch_cols.comparison_diff_val = comparison_diff;
                branch_cols.do_branch = F::from_bool(do_branch);
                branch_cols.next_pc = if do_branch {
                    event.pc + event.instruction.op_c[0]
                } else {
                    event.pc + F::one()
                };
            }

            // Populate the public values columns.
            if event.instruction.opcode == Opcode::Commit {
                let public_values_cols = cols.opcode_specific.public_values_mut();
                let idx = cols.b.prev_value()[0].as_canonical_u32() as usize;
                public_values_cols.idx_bitmap[idx] = F::one();
            }

            cols.is_real = F::one();
        });

        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Fill in the dummy values for the padding rows.
        let padded_rows = trace
            .values
            .par_chunks_mut(NUM_CPU_COLS)
            .enumerate()
            .skip(input.cpu_events.len());
        padded_rows.for_each(|(i, row)| {
            let cols: &mut CpuCols<F> = row.borrow_mut();
            cols.selectors.is_noop = F::one();
            cols.instruction.imm_b = F::one();
            cols.instruction.imm_c = F::one();
            cols.clk = F::from_canonical_u32(4) * F::from_canonical_usize(i);
            cols.instruction.imm_b = F::from_canonical_u32(1);
            cols.instruction.imm_c = F::from_canonical_u32(1);
        });
        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}
