use p3_air::PairBuilder;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use sp1_core::air::MachineAir;
use sp1_derive::AlignedBorrow;

use crate::{builder::SP1RecursionAirBuilder, *};

#[derive(Default)]
pub struct DummyWideChip<const COL_PADDING: usize> {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DummyWideCols<F: Copy, const COL_PADDING: usize> {
    pub vals: [F; COL_PADDING],
}

impl<F: Field, const COL_PADDING: usize> BaseAir<F> for DummyWideChip<COL_PADDING> {
    fn width(&self) -> usize {
        COL_PADDING
    }
}

impl<F: PrimeField32, const COL_PADDING: usize> MachineAir<F> for DummyWideChip<COL_PADDING> {
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
        true
    }
}

impl<AB, const COL_PADDING: usize> Air<AB> for DummyWideChip<COL_PADDING>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, _builder: &mut AB) {}
}
