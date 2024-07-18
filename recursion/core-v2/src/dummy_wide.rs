use p3_air::PairBuilder;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_derive::AlignedBorrow;

use crate::{builder::SP1RecursionAirBuilder, *};

#[derive(Default)]
pub struct DummyWideChip<const COL_PADDING: usize, const NUM_CONSTRAINTS: usize> {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DummyWideCols<F: Copy, const COL_PADDING: usize> {
    pub vals: [F; COL_PADDING],
}

impl<F: Field, const COL_PADDING: usize, const NUM_CONSTRAINTS: usize> BaseAir<F>
    for DummyWideChip<COL_PADDING, NUM_CONSTRAINTS>
{
    fn width(&self) -> usize {
        COL_PADDING
    }
}

impl<F: PrimeField32, const COL_PADDING: usize, const NUM_CONSTRAINTS: usize> MachineAir<F>
    for DummyWideChip<COL_PADDING, NUM_CONSTRAINTS>
{
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "Dummy wide".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, _: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        RowMajorMatrix::new(vec![F::zero(); COL_PADDING * (1 << 16)], COL_PADDING)
    }

    fn included(&self, _record: &Self::Record) -> bool {
        COL_PADDING != 0
    }
}

impl<AB, const COL_PADDING: usize, const NUM_CONSTRAINTS: usize> Air<AB>
    for DummyWideChip<COL_PADDING, NUM_CONSTRAINTS>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        for _ in 0..NUM_CONSTRAINTS {
            builder.assert_zero(local[0]);
        }
    }
}
