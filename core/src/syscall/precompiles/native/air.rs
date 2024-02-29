use crate::memory::MemoryCols;
use crate::memory::MemoryReadCols;
use crate::memory::MemoryWriteCols;
use crate::runtime::Register;
use core::borrow::Borrow;
use core::borrow::BorrowMut;
use core::mem::size_of;
use p3_air::Air;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::MatrixRowSlices;
use sp1_derive::AlignedBorrow;

use crate::air::SP1AirBuilder;

use super::BinaryOpcode;

const DEFAULT_WIDTH: usize = 10;

const NUM_NATIVE_COLS: usize = size_of::<NativeCols<u8>>();

/// A chip for a native field operation
pub struct NativeChip {
    op: BinaryOpcode,
    width: usize,
}

impl NativeChip {
    pub const fn new(op: BinaryOpcode) -> Self {
        Self {
            op,
            width: DEFAULT_WIDTH,
        }
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

    a_access: MemoryWriteCols<T>,
    b_access: MemoryReadCols<T>,
    is_real: T,
}

impl<F: PrimeField32> BaseAir<F> for NativeChip {
    fn width(&self) -> usize {
        NUM_NATIVE_COLS * self.width
    }
}

impl<AB: SP1AirBuilder> Air<AB> for NativeChip
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        for chunk in main.row_slice(0).chunks_exact(self.width) {
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
            builder.constraint_memory_access(
                local.shard,
                local.clk,
                Register::A0,
                &local.a_access,
                local.is_real,
            )
        }
    }
}
