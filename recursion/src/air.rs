use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use p3_maybe_rayon::prelude::ParallelIterator;
use p3_maybe_rayon::prelude::ParallelSlice;
use sp1_derive::AlignedBorrow;
use tracing::instrument;

use sp1_core::air::MachineAir;
use sp1_core::air::{SP1AirBuilder, Word};
use sp1_core::operations::AddOperation;
use sp1_core::runtime::{ExecutionRecord, Opcode};
use sp1_core::utils::pad_to_power_of_two;

/// The number of main trace columns for `CpuChip`.
pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct CpuChip;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T> {
    pub pc: T,
    pub fp: T,

    pub a: T,
    pub b: T,
    pub c: T,

    pub op_a: T,
    pub op_b: T,
    pub op_c: T,
    pub is_add: T,
    pub is_sub: T,
    pub is_mul: T,
    pub is_div: T,
    pub is_lw: T,
    pub is_sw: T,
    pub is_beq: T,
    pub is_bne: T,
    pub is_jal: T,
    pub is_jalr: T,
}

impl<F: PrimeField> MachineAir<F> for CpuChip {
    fn name(&self) -> String {
        "CPU".to_string()
    }

    #[instrument(name = "generate add trace", skip_all)]
    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        output: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        todo!()
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}

impl<AB> Air<AB> for CpuChip
where
    AB: SP1AirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &CpuCols<AB::Var> = main.row_slice(0).borrow();
    }
}
