use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::utils::pad_to_power_of_two;
use std::borrow::BorrowMut;
use tracing::instrument;

use crate::fri_fold::{column::FriFoldCols, column::NUM_FRI_FOLD_COLS, FriFoldChip};
use crate::runtime::{ExecutionRecord, RecursionProgram};

impl<F: PrimeField32> MachineAir<F> for FriFoldChip {
    type Record = ExecutionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    #[instrument(name = "generate fri fold trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord<F>,
        _: &mut ExecutionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut rows = Vec::new();

        for event in &input.fri_fold_events {
            let mut row = [F::zero(); NUM_FRI_FOLD_COLS];

            let cols: &mut FriFoldCols<F> = row.as_mut_slice().borrow_mut();

            cols.m.populate(&event.m);
            cols.input_ptr.populate(&event.input_ptr);

            cols.z.populate(&event.z);
            cols.alpha.populate(&event.alpha);
            cols.x.populate(&event.x);
            cols.log_height.populate(&event.log_height);
            cols.mat_opening_ptr.populate(&event.mat_opening_ptr);
            cols.ps_at_z_ptr.populate(&event.ps_at_z_ptr);
            cols.alpha_pow_ptr.populate(&event.alpha_pow_ptr);
            cols.ro_ptr.populate(&event.ro_ptr);

            cols.p_at_x.populate(&event.p_at_x);
            cols.p_at_z.populate(&event.p_at_z);

            cols.alpha_pow_at_log_height
                .populate(&event.alpha_pow_at_log_height);
            cols.ro_at_log_height.populate(&event.ro_at_log_height);

            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FRI_FOLD_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FRI_FOLD_COLS, F>(&mut trace.values);

        #[cfg(debug_assertions)]
        println!(
            "fri fold trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn included(&self, record: &Self::Record) -> bool {
        !record.fri_fold_events.is_empty()
    }
}
