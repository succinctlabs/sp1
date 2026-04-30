use super::{BitwiseOperation, BitwiseOperationInput, U16toU8Operation};
use crate::{
    air::{SP1Operation, SP1OperationBuilder},
    operations::{U16toU8OperationUnsafe, U16toU8OperationUnsafeInput},
};
use serde::{Deserialize, Serialize};
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_core_executor::{events::ByteRecord, Opcode};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_hypercube::{air::SP1AirBuilder, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

/// A set of columns needed to compute the bitwise operation over `Word` of u16 limbs.
#[derive(
    AlignedBorrow,
    StructReflection,
    Default,
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    IntoShape,
    SP1OperationBuilder,
)]
#[repr(C)]
pub struct BitwiseU16Operation<T> {
    /// Lower byte of the limbs of `b`.
    pub b_low_bytes: U16toU8Operation<T>,

    /// Lower byte of the limbs of `c`.
    pub c_low_bytes: U16toU8Operation<T>,

    /// The bitwise operation over bytes.
    pub bitwise_operation: BitwiseOperation<T>,
}

impl<F: Field> BitwiseU16Operation<F> {
    pub fn populate_bitwise(
        &mut self,
        record: &mut impl ByteRecord,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
        opcode: Opcode,
    ) {
        self.b_low_bytes.populate_u16_to_u8_unsafe(b_u64);
        self.c_low_bytes.populate_u16_to_u8_unsafe(c_u64);
        self.bitwise_operation.populate_bitwise(record, a_u64, b_u64, c_u64, opcode);
    }

    /// Evaluate the bitwise operation over two `Word`s of u16 limbs.
    /// Assumes that the two words are valid `Word`s of u16 limbs.
    /// Assumes that `opcode` is a valid byte opcode.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the return value is constrained to be correct.
    fn eval_bitwise_u16<AB>(
        builder: &mut AB,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        cols: BitwiseU16Operation<AB::Var>,
        opcode: AB::Expr,
        is_real: AB::Expr,
    ) -> Word<AB::Expr>
    where
        AB: SP1AirBuilder
            + SP1OperationBuilder<U16toU8OperationUnsafe>
            + SP1OperationBuilder<BitwiseOperation<<AB as AirBuilder>::F>>,
    {
        // Constrain that `is_real` is boolean.
        builder.assert_bool(is_real.clone());

        // Convert the two words to bytes using the unsafe API.
        // SAFETY: This is safe because the `BitwiseOperation` will range check the bytes.
        let b_input = U16toU8OperationUnsafeInput::new(b.0, cols.b_low_bytes);
        let b_bytes = U16toU8OperationUnsafe::eval(builder, b_input);
        let c_input = U16toU8OperationUnsafeInput::new(c.0, cols.c_low_bytes);
        let c_bytes = U16toU8OperationUnsafe::eval(builder, c_input);

        // SAFETY: This is safe because `is_real` is constrained to be boolean.
        BitwiseOperation::<AB::F>::eval(
            builder,
            BitwiseOperationInput::<AB>::new(
                b_bytes,
                c_bytes,
                cols.bitwise_operation,
                opcode,
                is_real,
            ),
        );

        // Combine the byte results into u16 limbs.
        let result_limb0 = cols.bitwise_operation.result[0]
            + cols.bitwise_operation.result[1] * AB::F::from_canonical_u32(1 << 8);
        let result_limb1 = cols.bitwise_operation.result[2]
            + cols.bitwise_operation.result[3] * AB::F::from_canonical_u32(1 << 8);
        let result_limb2 = cols.bitwise_operation.result[4]
            + cols.bitwise_operation.result[5] * AB::F::from_canonical_u32(1 << 8);
        let result_limb3 = cols.bitwise_operation.result[6]
            + cols.bitwise_operation.result[7] * AB::F::from_canonical_u32(1 << 8);
        Word([result_limb0, result_limb1, result_limb2, result_limb3])
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct BitwiseU16OperationInput<AB: SP1AirBuilder> {
    pub b: Word<AB::Expr>,
    pub c: Word<AB::Expr>,
    pub cols: BitwiseU16Operation<AB::Var>,
    pub opcode: AB::Expr,
    pub is_real: AB::Expr,
}

impl<AB> SP1Operation<AB> for BitwiseU16Operation<AB::F>
where
    AB: SP1AirBuilder
        + SP1OperationBuilder<U16toU8OperationUnsafe>
        + SP1OperationBuilder<BitwiseOperation<<AB as AirBuilder>::F>>,
{
    type Input = BitwiseU16OperationInput<AB>;
    type Output = Word<AB::Expr>;

    fn lower(builder: &mut AB, input: Self::Input) -> Word<AB::Expr> {
        Self::eval_bitwise_u16(builder, input.b, input.c, input.cols, input.opcode, input.is_real)
    }
}
