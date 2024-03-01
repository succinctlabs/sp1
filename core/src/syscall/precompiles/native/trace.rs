use std::borrow::BorrowMut;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;

use crate::{
    air::MachineAir,
    field::event::FieldEvent,
    runtime::ExecutionRecord,
    syscall::precompiles::native::{NativeCols, NUM_NATIVE_COLS},
    utils::pad_simd_rows,
};

use super::{NativeChip, NativeEvent};

impl<F: PrimeField32> NativeCols<F> {
    fn populate(&mut self, event: &NativeEvent, new_field_events: &mut Vec<FieldEvent>) {
        self.is_real = F::one();
        self.shard = F::from_canonical_u32(event.shard);
        self.clk = F::from_canonical_u32(event.clk);
        self.a_access.populate(event.a_record, new_field_events);
        self.b_access.populate(event.b_record, new_field_events);
    }
}

impl<F: PrimeField32, const LANES: usize> MachineAir<F> for NativeChip<LANES> {
    fn name(&self) -> String {
        format!("native_{}", self.op)
    }

    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        for event in self.op.events(input) {
            let mut row = [F::zero(); NUM_NATIVE_COLS];
            let cols: &mut NativeCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate(event, &mut output.field_events);
        }
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = self
            .op
            .events(input)
            .par_iter()
            .map(|event| {
                let mut row = [F::zero(); NUM_NATIVE_COLS];
                let cols: &mut NativeCols<F> = row.as_mut_slice().borrow_mut();
                cols.populate(event, &mut vec![]);

                row
            })
            .collect::<Vec<_>>();

        pad_simd_rows::<_, NUM_NATIVE_COLS, LANES>(&mut rows, || [F::zero(); NUM_NATIVE_COLS]);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_NATIVE_COLS * LANES,
        )
    }
}
