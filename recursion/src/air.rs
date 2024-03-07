use core::borrow::Borrow;
use core::mem::size_of;
use p3_air::{Air, BaseAir};
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRowSlices;
use sp1_derive::AlignedBorrow;
use tracing::instrument;

use sp1_core::air::MachineAir;
use sp1_core::air::SP1AirBuilder;
use sp1_core::operations::{AddOperation, IsZeroOperation};
use sp1_core::runtime::{ExecutionRecord, Opcode};
use sp1_core::utils::pad_to_power_of_two;

/// The number of main trace columns for `CpuChip`.
pub const NUM_CPU_COLS: usize = size_of::<CpuCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Word<T>(pub [T; 4]);

/// A chip that implements addition for the opcode ADD.
#[derive(Default)]
pub struct CpuChip;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct MemoryReadCols<T> {
    pub value: Word<T>,
    pub prev_timestamp: T,
    pub curr_timestamp: T,
}

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct MemoryWriteCols<T> {
    pub prev_value: Word<T>,
    pub curr_value: Word<T>,
    pub prev_timestamp: T,
    pub curr_timestamp: T,
}

// #[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
// pub struct ExtensionCols<T> {
//     pub a: [T; 4],
//     pub b: [T; 4],
//     pub c: [T; 4],
//     pub add: [T; 4],
//     pub sub: [T; 4],
//     pub mul: [T; 4],
//     pub div: [T; 4],
// }

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
pub struct HashCols<T> {
    pub i1: MemoryReadCols<T>,
    pub i2: MemoryReadCols<T>,
    pub o1: MemoryWriteCols<T>,
    pub o2: MemoryWriteCols<T>,
}

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct CpuCols<T> {
    pub clk: T,
    pub pc: T,
    pub fp: T,

    pub a: MemoryWriteCols<T>,
    pub b: MemoryReadCols<T>,
    pub c: MemoryReadCols<T>,

    pub opcode: T,
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

    // Prove c = a + b;
    pub add_scratch: T,

    // Prove c = a - b;
    pub sub_scratch: T,

    // Prove c = a * b;
    pub mul_scratch: T,

    // Prove c = a / b;
    pub div_scratch: T,

    // Prove ext(c) = ext(a) + ext(b);
    pub add_ext_scratch: [T; 4],

    // Prove ext(c) = ext(a) - ext(b);
    pub sub_ext_scratch: [T; 4],

    // Prove ext(c) = ext(a) * ext(b);
    pub mul_ext_scratch: [T; 4],

    // Prove ext(c) = ext(a) / ext(b);
    pub div_ext_scratch: [T; 4],

    // Prove c = a == b;
    pub a_eq_b: IsZeroOperation<T>,
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
        let next: &CpuCols<AB::Var> = main.row_slice(1).borrow();
    }
}
