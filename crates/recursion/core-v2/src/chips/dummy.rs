use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use sp1_derive::AlignedBorrow;
use sp1_stark::air::MachineAir;

use crate::{builder::SP1RecursionAirBuilder, *};

/// A dummy chip with 1<< `log_height` rows, `COL_PADDING` main columns, `COL_PADDING` preprocessed
/// columns, and no constraints.
pub struct DummyChip<const COL_PADDING: usize> {
    log_height: usize,
}

impl<const COL_PADDING: usize> Default for DummyChip<COL_PADDING> {
    fn default() -> Self {
        Self { log_height: 1 }
    }
}

impl<const COL_PADDING: usize> DummyChip<COL_PADDING> {
    pub fn new(log_height: usize) -> Self {
        Self { log_height }
    }
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct DummyCols<F: Copy, const COL_PADDING: usize> {
    pub vals: [F; COL_PADDING],
}

impl<F: Field, const COL_PADDING: usize> BaseAir<F> for DummyChip<COL_PADDING> {
    fn width(&self) -> usize {
        COL_PADDING
    }
}

impl<F: PrimeField32, const COL_PADDING: usize> MachineAir<F> for DummyChip<COL_PADDING> {
    type Record = ExecutionRecord<F>;

    type Program = crate::RecursionProgram<F>;

    fn name(&self) -> String {
        "DummyWide".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(&self, _: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        RowMajorMatrix::new(vec![F::zero(); COL_PADDING * (1 << self.log_height)], COL_PADDING)
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(vec![F::zero(); 1 << self.log_height], 1))
    }

    fn preprocessed_width(&self) -> usize {
        1
    }

    fn included(&self, _record: &Self::Record) -> bool {
        COL_PADDING != 0
    }
}

impl<AB, const COL_PADDING: usize> Air<AB> for DummyChip<COL_PADDING>
where
    AB: SP1RecursionAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        builder.assert_zero(local[0]);
    }
}
