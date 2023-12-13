use super::air::{CpuCols, NUM_CPU_COLS};
use super::CpuEvent;
use core::mem::{size_of, transmute};

use crate::lookup::Interaction;
use crate::runtime::chip::Chip;
use crate::runtime::Runtime;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

pub struct CpuChip<F: PrimeField> {
    _field: F,
}

impl<F: PrimeField> Chip<F> for CpuChip<F> {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F> {
        let mut rows = runtime
            .cpu_events
            .iter() // TODO make this a par_iter
            .enumerate()
            .map(|(n, op)| self.event_to_row(*op))
            .collect::<Vec<_>>();

        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), NUM_CPU_COLS);

        // TODO: pad to a power of 2.
        // Self::pad_to_power_of_two(&mut trace.values);

        trace
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        todo!()
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        todo!()
    }
}

impl<F: PrimeField> CpuChip<F> {
    fn event_to_row(&self, event: CpuEvent) -> [F; NUM_CPU_COLS] {
        let mut row = [F::zero(); NUM_CPU_COLS];
        let cols: &mut CpuCols<F> = unsafe { transmute(&mut row) };
        cols.pc = F::from_canonical_u32(event.clk);
        cols.pc = F::from_canonical_u32(event.pc);
        row
    }
}
