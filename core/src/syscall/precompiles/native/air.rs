use crate::memory::MemoryCols;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::runtime::Register;
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;
use p3_air::Air;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_field::PrimeField32;
use p3_matrix::MatrixRowSlices;
use sp1_derive::AlignedBorrow;

use crate::air::SP1AirBuilder;

use super::BinaryOpcode;

const DEFAULT_WIDTH: usize = 1;

pub const NUM_NATIVE_COLS: usize = size_of::<NativeCols<u8>>();

/// A chip for a native field operation
///
/// The chip is configured to process `LANES` number of operations in parallel
pub struct NativeChip<const LANES: usize = DEFAULT_WIDTH> {
    pub(super) op: BinaryOpcode,
}

impl<const LANES: usize> NativeChip<LANES> {
    pub const fn new(op: BinaryOpcode) -> Self {
        Self { op }
    }

    pub const fn add() -> Self {
        Self::new(BinaryOpcode::Add)
    }

    pub const fn mul() -> Self {
        Self::new(BinaryOpcode::Mul)
    }

    pub const fn sub() -> Self {
        Self::new(BinaryOpcode::Sub)
    }

    pub const fn div() -> Self {
        Self::new(BinaryOpcode::Div)
    }
}

/// A set of columns to compute a native field binary operation.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct NativeCols<T> {
    pub shard: T,
    pub clk: T,

    pub a_access: MemoryWriteCols<T>,
    pub b_access: MemoryReadCols<T>,
    pub is_real: T,
}

impl<F: PrimeField32, const LANES: usize> BaseAir<F> for NativeChip<LANES> {
    fn width(&self) -> usize {
        NUM_NATIVE_COLS * LANES
    }
}

impl<AB: SP1AirBuilder, const LANES: usize> Air<AB> for NativeChip<LANES>
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        for chunk in main.row_slice(0).chunks_exact(NUM_NATIVE_COLS) {
            let local: &NativeCols<AB::Var> = chunk.borrow();

            // Read the value of `a`, `b`, and the result.
            let a = local.a_access.prev_value().reduce::<AB>();
            let b = local.b_access.value().reduce::<AB>();
            let result = local.a_access.value().reduce::<AB>();

            // Constrain the correct arithmetic equations.
            match self.op {
                BinaryOpcode::Add => {
                    builder.assert_eq(result, a + b);
                }
                BinaryOpcode::Mul => {
                    builder.assert_eq(result, a * b);
                }
                BinaryOpcode::Sub => {
                    builder.assert_eq(result, a - b);
                }
                BinaryOpcode::Div => {
                    builder.assert_eq(result * b, a);
                }
            };

            // constrain memory accesses.
            let a0 = AB::F::from_canonical_u32(Register::X10 as u32);
            let a1 = AB::F::from_canonical_u32(Register::X11 as u32);
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                a0,
                &local.a_access,
                local.is_real,
            );
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                a1,
                &local.b_access,
                local.is_real,
            );
        }
    }
}
