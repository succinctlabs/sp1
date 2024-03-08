use crate::cpu::CpuChip;
use core::mem::size_of;
use p3_air::Air;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_core::stark::SP1AirBuilder;
use sp1_core::{air::MachineAir, utils::pad_to_power_of_two};
use std::borrow::Borrow;
use std::borrow::BorrowMut;

use super::columns::CpuCols;
use crate::runtime::ExecutionRecord;

pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

impl<F: PrimeField32> MachineAir<F> for CpuChip<F> {
    type Record = ExecutionRecord<F>;

    fn name(&self) -> String {
        "CPU".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let rows = input
            .cpu_events
            .iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_CPU_COLS];
                let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                cols.clk = event.clk;
                cols.pc = event.pc;
                cols.fp = event.fp;
                cols.instruction.opcode = F::from_canonical_u32(event.instruction.opcode as u32);
                cols.instruction.op_a = event.instruction.op_a;
                cols.instruction.op_b = event.instruction.op_b;
                cols.instruction.op_c = event.instruction.op_c;
                cols.instruction.imm_b = F::from_canonical_u32(event.instruction.imm_b as u32);
                cols.instruction.imm_c = F::from_canonical_u32(event.instruction.imm_c as u32);
                row
            })
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_CPU_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F: Send + Sync> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip<AB::F>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let _: &CpuCols<AB::Var> = main.row_slice(0).borrow();
        let _: &CpuCols<AB::Var> = main.row_slice(1).borrow();
    }
}
