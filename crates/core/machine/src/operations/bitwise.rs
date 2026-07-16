use crate::air::{HostWitnessBuilder, SP1Operation, WitnessBuilder};
use serde::{Deserialize, Serialize};
use slop_algebra::Field;
use sp1_core_executor::{events::ByteRecord, ByteOpcode, Opcode};
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

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> BitwiseOperation<T> {
    /// Backend-agnostic witgen dual of [`Self::eval`]: the result bytes (`a`) plus a
    /// byte-table lookup `{byte_opcode, a_byte, b_byte, c_byte}` per byte. `byte_opcode`
    /// is a `ByteOpcode` discriminant (AND/OR/XOR), a per-row wire.
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut BitwiseOperation<WB::Field>,
        a: WB::Nat,
        b: WB::Nat,
        c: WB::Nat,
        byte_opcode: WB::Nat,
    ) {
        for i in 0..WORD_BYTE_SIZE {
            let a_byte = wb.bits(a, (i as u32) * 8, 8);
            cols.result[i] = wb.nat_to_field(a_byte);
            let b_byte = wb.bits(b, (i as u32) * 8, 8);
            let c_byte = wb.bits(c, (i as u32) * 8, 8);
            wb.add_byte_lookup(byte_opcode, a_byte, b_byte, c_byte);
        }
    }
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
        let mut wb = HostWitnessBuilder::<F, _>::new(record);
        Self::witgen(&mut wb, self, a_u64, b_u64, c_u64, ByteOpcode::from(opcode) as u64);
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
