use serde::{Deserialize, Serialize};
use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_BYTE_SIZE, WORD_SIZE};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::air::{SP1Operation, WordAirBuilder};
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

/// A set of columns for a u16 to u8 adapter to convert a `Word` to u8 limbs.
#[derive(
    AlignedBorrow, StructReflection, Default, Debug, Clone, Copy, Serialize, Deserialize, IntoShape,
)]
#[repr(C)]
pub struct U16toU8Operation<T> {
    low_bytes: [T; WORD_SIZE],
}

impl<F: Field> U16toU8Operation<F> {
    pub fn populate_u16_to_u8_unsafe(&mut self, a_u64: u64) {
        let a_limbs = u64_to_u16_limbs(a_u64);
        for i in 0..WORD_SIZE {
            self.low_bytes[i] = F::from_canonical_u8((a_limbs[i] & 0xFF) as u8);
        }
    }

    pub fn populate_u16_to_u8_safe(&mut self, record: &mut impl ByteRecord, a_u64: u64) {
        let a_limbs = u64_to_u16_limbs(a_u64);
        for i in 0..WORD_SIZE {
            let low_byte = (a_limbs[i] & 0xFF) as u8;
            let high_byte = ((a_limbs[i] >> 8) & 0xFF) as u8;
            self.low_bytes[i] = F::from_canonical_u8((a_limbs[i] & 0xFF) as u8);
            record.add_u8_range_check(low_byte, high_byte);
        }
    }

    /// Converts four u16 limbs into eight u8 limbs.
    /// This function assumes that the u8 limbs will be range checked.
    pub fn eval_u16_to_u8_unsafe<AB: SP1AirBuilder>(
        _: &mut AB,
        u16_values: [AB::Expr; WORD_SIZE],
        cols: U16toU8Operation<AB::Var>,
    ) -> [AB::Expr; WORD_BYTE_SIZE] {
        let mut ret = core::array::from_fn(|_| AB::Expr::zero());
        let divisor = AB::F::from_canonical_u32(1 << 8).inverse();

        for i in 0..WORD_SIZE {
            ret[i * 2] = cols.low_bytes[i].into();
            ret[i * 2 + 1] = (u16_values[i].clone() - ret[i * 2].clone()) * divisor;
        }

        ret
    }

    /// Converts four u16 limbs into eight u8 limbs.
    /// This function range checks the eight u8 limbs.
    fn eval_u16_to_u8_safe<AB: SP1AirBuilder>(
        builder: &mut AB,
        u16_values: [AB::Expr; WORD_SIZE],
        cols: U16toU8Operation<AB::Var>,
        is_real: AB::Expr,
    ) -> [AB::Expr; WORD_BYTE_SIZE] {
        let ret = U16toU8Operation::<AB::F>::eval_u16_to_u8_unsafe(builder, u16_values, cols);
        builder.slice_range_check_u8(&ret, is_real);
        ret
    }
}

#[derive(Debug, Clone, SP1OperationBuilder)]
pub struct U16toU8OperationSafe;

#[derive(Debug, Clone, InputParams, InputExpr)]
pub struct U16toU8OperationSafeInput<AB: SP1AirBuilder> {
    pub u16_values: [AB::Expr; WORD_SIZE],
    pub cols: U16toU8Operation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for U16toU8OperationSafe {
    type Input = U16toU8OperationSafeInput<AB>;
    type Output = [AB::Expr; WORD_BYTE_SIZE];

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        U16toU8Operation::<AB::F>::eval_u16_to_u8_safe(
            builder,
            input.u16_values,
            input.cols,
            input.is_real,
        )
    }
}

#[derive(Debug, Clone, SP1OperationBuilder)]
pub struct U16toU8OperationUnsafe;

#[derive(Debug, Clone, InputParams, InputExpr)]
pub struct U16toU8OperationUnsafeInput<AB: SP1AirBuilder> {
    pub u16_values: [AB::Expr; WORD_SIZE],
    pub cols: U16toU8Operation<AB::Var>,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for U16toU8OperationUnsafe {
    type Input = U16toU8OperationUnsafeInput<AB>;
    type Output = [AB::Expr; WORD_BYTE_SIZE];

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        U16toU8Operation::<AB::F>::eval_u16_to_u8_unsafe(builder, input.u16_values, input.cols)
    }
}
