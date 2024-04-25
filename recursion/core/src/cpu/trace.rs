use p3_field::extension::BinomiallyExtendable;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use sp1_core::air::MachineAir;
use sp1_core::utils::pad_rows;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::cpu::CpuChip;
use crate::cpu::CpuCols;
use crate::cpu::CpuEvent;
use crate::cpu::CPU_COL_MAP;
use crate::cpu::NUM_CPU_COLS;
use crate::memory::MemoryCols;
use crate::range_check::RangeCheckEvent;
use crate::runtime::ExecutionRecord;
use crate::runtime::RecursionProgram;
use crate::runtime::D;

impl<F: PrimeField32 + BinomiallyExtendable<D>> MachineAir<F> for CpuChip<F> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    #[instrument(name = "generate cpu trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        output: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut new_range_check_events = Vec::new();

        let mut rows = input
            .cpu_events
            .iter()
            .map(|event| {
                let (row, row_range_check_events) = self.event_to_row(event);

                new_range_check_events.extend(row_range_check_events);

                row
            })
            .collect::<Vec<_>>();

        output.add_range_check_events(new_range_check_events);

        pad_rows(&mut rows, || {
            let mut row = [F::zero(); NUM_CPU_COLS];
            let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
            cols.selectors.is_noop = F::one();
            row
        });

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        for i in input.cpu_events.len()..trace.height() {
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.clk] =
                F::from_canonical_u32(4) * F::from_canonical_usize(i);
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.instruction.imm_b] =
                F::from_canonical_u32(1);
            trace.values[i * NUM_CPU_COLS + CPU_COL_MAP.instruction.imm_c] =
                F::from_canonical_u32(1);
        }
        trace
    }

    #[instrument(name = "generate cpu dependencies", level = "debug", skip_all)]
    fn generate_dependencies(&self, input: &ExecutionRecord<F>, output: &mut ExecutionRecord<F>) {
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let events = input
            .cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[CpuEvent<F>]| {
                let mut range_check_events: Vec<_> = Vec::default();
                ops.iter().for_each(|op| {
                    let (_, row_range_check_events) = self.event_to_row(op);
                    range_check_events.extend(row_range_check_events);
                });
                range_check_events
            })
            .collect::<Vec<_>>();

        events.into_iter().for_each(|range_check_events| {
            output.add_range_check_events(range_check_events);
        });

        println!(
            "cpu generate dependencies range check event len is {:?}",
            output.range_check_events.len()
        );
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<D>> CpuChip<F> {
    /// Create a row from an event.
    fn event_to_row(&self, event: &CpuEvent<F>) -> ([F; NUM_CPU_COLS], Vec<RangeCheckEvent>) {
        let mut new_range_check_events = Vec::new();

        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();

        cols.clk = event.clk;
        cols.pc = event.pc;
        cols.fp = event.fp;

        cols.selectors.populate(&event.instruction);

        cols.instruction.opcode = F::from_canonical_u32(event.instruction.opcode as u32);
        cols.instruction.op_a = event.instruction.op_a;
        cols.instruction.op_b = event.instruction.op_b;
        cols.instruction.op_c = event.instruction.op_c;
        cols.instruction.imm_b = F::from_canonical_u32(event.instruction.imm_b as u32);
        cols.instruction.imm_c = F::from_canonical_u32(event.instruction.imm_c as u32);

        if let Some(record) = &event.a_record {
            cols.a.populate(record, &mut new_range_check_events);
        }
        if let Some(record) = &event.b_record {
            cols.b.populate(record, &mut new_range_check_events);
        } else {
            *cols.b.value_mut() = event.instruction.op_b;
        }
        if let Some(record) = &event.c_record {
            cols.c.populate(record, &mut new_range_check_events);
        } else {
            *cols.c.value_mut() = event.instruction.op_c;
        }

        // cols.a_eq_b
        //     .populate((cols.a.value()[0] - cols.b.value()[0]).as_canonical_u32());

        // let is_last_row = F::from_bool(i == input.cpu_events.len() - 1);
        // cols.beq = cols.is_beq * cols.a_eq_b.result * (F::one() - is_last_row);
        // cols.bne = cols.is_bne * (F::one() - cols.a_eq_b.result) * (F::one() - is_last_row);

        cols.is_real = F::one();
        (row, new_range_check_events)
    }
}
