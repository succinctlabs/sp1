pub mod event;

use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::IntoParallelRefIterator;
use p3_maybe_rayon::prelude::ParallelIterator;
use sp1_derive::AlignedBorrow;

use crate::air::FieldAirBuilder;
use crate::air::MachineAir;
use crate::air::SP1AirBuilder;
use crate::runtime::ExecutionRecord;
use crate::utils::pad_to_power_of_two;

use tracing::instrument;

/// The number of main trace columns for `FieldLTUChip`.
pub const NUM_FIELD_COLS: usize = size_of::<FieldLtuCols<u8>>();

/// A chip that implements less than within the field.
#[derive(Default)]
pub struct FieldLtuChip;

/// The column layout for the chip.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct FieldLtuCols<T> {
    /// The result of the `LT` operation on `b` and `c`
    pub lt: T,

    /// The first field operand.
    pub b: T,

    /// The second field operand.
    pub c: T,

    /// The difference between `b` and `c` in little-endian order.
    pub diff_bits: [T; LTU_NB_BITS + 1],

    // TODO:  Support multiplicities > 1.  Right now there can be duplicate rows.
    // pub multiplicities: T,
    pub is_real: T,
}

impl<F: PrimeField> MachineAir<F> for FieldLtuChip {
    type Record = ExecutionRecord;

    fn name(&self) -> String {
        "FieldLTU".to_string()
    }

    fn generate_dependencies(&self, _input: &ExecutionRecord, _output: &mut ExecutionRecord) {}

    #[instrument(name = "generate field ltu trace", level = "debug", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        // Generate the trace rows for each event.
        let cols = input
            .field_events
            .par_iter()
            .flat_map_iter(|event| {
                let mut row = [F::zero(); NUM_FIELD_COLS];
                let cols: &mut FieldLtuCols<F> = row.as_mut_slice().borrow_mut();
                let diff = event.b.wrapping_sub(event.c).wrapping_add(1 << LTU_NB_BITS);
                cols.b = F::from_canonical_u32(event.b);
                cols.c = F::from_canonical_u32(event.c);
                for i in 0..cols.diff_bits.len() {
                    cols.diff_bits[i] = F::from_canonical_u32((diff >> i) & 1);
                }
                let max = 1 << LTU_NB_BITS;
                if diff >= max {
                    panic!("diff overflow");
                }
                cols.lt = F::from_bool(event.ltu);
                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(cols, NUM_FIELD_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FIELD_COLS, F>(&mut trace.values);

        trace
    }

    fn included(&self, shard: &Self::Record) -> bool {
        !shard.field_events.is_empty()
    }
}

pub const LTU_NB_BITS: usize = 29;

impl<F: Field> BaseAir<F> for FieldLtuChip {
    fn width(&self) -> usize {
        NUM_FIELD_COLS
    }
}

impl<AB: SP1AirBuilder> Air<AB> for FieldLtuChip {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &FieldLtuCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint for normalizing to degree 3.
        builder.assert_eq(local.b * local.b * local.b, local.b * local.b * local.b);

        // Verify that lt is a boolean.
        builder.assert_bool(local.lt);

        // Verify that the diff bits are boolean.
        for i in 0..local.diff_bits.len() {
            builder.assert_bool(local.diff_bits[i]);
        }

        // Verify the decomposition of b - c.
        let mut diff = AB::Expr::zero();
        for i in 0..local.diff_bits.len() {
            diff += local.diff_bits[i] * AB::F::from_canonical_u32(1 << i);
        }
        builder.when(local.is_real).assert_eq(
            local.b - local.c + AB::F::from_canonical_u32(1 << LTU_NB_BITS),
            diff,
        );

        // Assert that the output is correct.
        builder
            .when(local.is_real)
            .assert_eq(local.lt, AB::Expr::one() - local.diff_bits[LTU_NB_BITS]);

        // Receive the field operation.
        builder.receive_field_op(local.lt, local.b, local.c, local.is_real);
    }
}
