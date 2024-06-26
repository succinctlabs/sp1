use core::borrow::Borrow;
use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use sp1_core::air::MachineAir;
use sp1_core::air::SP1AirBuilder;
use sp1_core::runtime::ExecutionRecord;
use sp1_core::runtime::Program;
use sp1_core::utils::pad_rows_fixed;
use sp1_derive::AlignedBorrow;
use std::borrow::BorrowMut;
use tracing::instrument;

pub const NUM_ADD_COLS: usize = core::mem::size_of::<AddCols<u8>>();

#[derive(Default)]
pub struct AddChip<const DEGREE: usize> {}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddCols<T: Copy> {
    pub a: T,
    pub b: T,
    pub c: T,
    pub is_real: T,
}

impl<F, const DEGREE: usize> BaseAir<F> for AddChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_ADD_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for AddChip<DEGREE> {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Add".to_string()
    }

    fn generate_dependencies(&self, _: &Self::Record, _: &mut Self::Record) {
        // This is a no-op.
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let mut rows = vec![F::zero(); NUM_ADD_COLS * 4];

        RowMajorMatrix::new(rows, NUM_ADD_COLS)
    }

    fn included(&self, record: &Self::Record) -> bool {
        true
    }
}

impl<AB, const DEGREE: usize> Air<AB> for AddChip<DEGREE>
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddCols<AB::Var> = (*local).borrow();
        builder
            .when(local.is_real)
            .assert_eq(local.a, local.b + local.c);
    }
}

/*

1) make a dummy program for loop 100: x' = x*x + x
2) make add chip and mul chip with 3 columns each that prove a = b + c and a = b * c respectively.
and then also fill in generate_trace and eval and write test (look at add_sub in core for test example).
you will also need to write your own execution record struct but look at recursion-core for how we did that

*/
