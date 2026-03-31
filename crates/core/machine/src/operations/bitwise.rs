use crate::air::SP1Operation;
use serde::{Deserialize, Serialize};
use slop_algebra::Field;
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode, Opcode,
};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_hypercube::air::SP1AirBuilder;
use sp1_primitives::consts::WORD_BYTE_SIZE;
use struct_reflection::{StructReflection, StructReflectionHelper};

/// A set of columns needed to compute the bitwise operation over u64s in byte form.
#[derive(
    AlignedBorrow,
    Default,
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    IntoShape,
    SP1OperationBuilder,
    StructReflection,
)]
#[repr(C)]
pub struct BitwiseOperation<T> {
    /// The result of the bitwise operation in bytes.
    pub result: [T; WORD_BYTE_SIZE],
}

impl<F: Field> BitwiseOperation<F> {
    pub fn populate_bitwise(
        &mut self,
        record: &mut impl ByteRecord,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
        opcode: Opcode,
    ) {
        let a = a_u64.to_le_bytes();
        let b = b_u64.to_le_bytes();
        let c = c_u64.to_le_bytes();

        self.result = a.map(|x| F::from_canonical_u8(x));

        for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
            let byte_event =
                ByteLookupEvent { opcode: ByteOpcode::from(opcode), a: b_a as u16, b: b_b, c: b_c };
            record.add_byte_lookup_event(byte_event);
        }
    }

    /// Evaluate the bitwise operation over two u64s in byte form.
    /// Assumes that `is_real` is boolean.
    /// If `is_real` is true, constrains that the inputs are valid bytes.
    /// If `is_real` is true, constrains that the `result` is the correct result.
    fn eval_bitwise<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: [AB::Expr; WORD_BYTE_SIZE],
        b: [AB::Expr; WORD_BYTE_SIZE],
        cols: BitwiseOperation<AB::Var>,
        opcode: AB::Expr,
        is_real: AB::Expr,
    ) {
        // The byte table will constrain that, if `is_real` is true,
        //  - `a[i], b[i]` are bytes.
        //  - `result[i] = op(a[i], b[i])`.
        for i in 0..WORD_BYTE_SIZE {
            builder.send_byte(
                opcode.clone(),
                cols.result[i],
                a[i].clone(),
                b[i].clone(),
                is_real.clone(),
            );
        }
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct BitwiseOperationInput<AB: SP1AirBuilder> {
    pub a: [AB::Expr; WORD_BYTE_SIZE],
    pub b: [AB::Expr; WORD_BYTE_SIZE],
    pub cols: BitwiseOperation<AB::Var>,
    pub opcode: AB::Expr,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for BitwiseOperation<AB::F> {
    type Input = BitwiseOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) {
        BitwiseOperation::<AB::F>::eval_bitwise(
            builder,
            input.a,
            input.b,
            input.cols,
            input.opcode,
            input.is_real,
        );
    }
}
