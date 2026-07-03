use crate::operations::U32toU8Operation;
use slop_algebra::{AbstractField, Field};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use sp1_derive::AlignedBorrow;
use sp1_hypercube::air::SP1AirBuilder;

/// A set of columns needed to compute the AND operation over two u16 limbs.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AndU32Operation<T> {
    /// Lower byte of two limbs of `b`.
    pub b_low_bytes: U32toU8Operation<T>,

    /// Lower byte of two limbs of `c`.
    pub c_low_bytes: U32toU8Operation<T>,

    /// The result of the AND operation.
    pub value: [T; 4],
}

// Witgen in an unconstrained `impl` (column type is the builder's `Field`).
impl<T: Copy> AndU32Operation<T> {
    /// Backend-agnostic witgen dual of `populate_and_u32`. Returns `b & c`.
    pub fn witgen_and_u32<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut AndU32Operation<WB::Field>,
        b: WB::Nat,
        c: WB::Nat,
    ) -> WB::Nat {
        use sp1_core_executor::ByteOpcode;
        let expected = wb.and(b, c);
        super::U32toU8Operation::<WB::Field>::witgen_u32_to_u8_unsafe(
            wb,
            &mut cols.b_low_bytes,
            b,
        );
        super::U32toU8Operation::<WB::Field>::witgen_u32_to_u8_unsafe(
            wb,
            &mut cols.c_low_bytes,
            c,
        );
        let opcode = wb.const_nat(ByteOpcode::AND as u64);
        for i in 0..4u32 {
            let b_byte = wb.bits(b, 8 * i, 8);
            let c_byte = wb.bits(c, 8 * i, 8);
            let a_byte = wb.bits(expected, 8 * i, 8);
            cols.value[i as usize] = wb.nat_to_field(a_byte);
            wb.add_byte_lookup(opcode, a_byte, b_byte, c_byte);
        }
        expected
    }
}

impl<F: Field> AndU32Operation<F> {
    pub fn populate_and_u32(
        &mut self,
        record: &mut impl ByteRecord,
        b_u32: u32,
        c_u32: u32,
    ) -> u32 {
        let expected = b_u32 & c_u32;
        self.b_low_bytes.populate_u32_to_u8_unsafe(b_u32);
        self.c_low_bytes.populate_u32_to_u8_unsafe(c_u32);

        let b_bytes = b_u32.to_le_bytes();
        let c_bytes = c_u32.to_le_bytes();
        for i in 0..4 {
            let and = b_bytes[i] & c_bytes[i];
            self.value[i] = F::from_canonical_u8(and);

            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::AND,
                a: and as u16,
                b: b_bytes[i],
                c: c_bytes[i],
            };
            record.add_byte_lookup_event(byte_event);
        }
        expected
    }

    /// Evaluate the AND operation over two u32s of two u16 limbs.
    /// Assumes that the two words are valid u32s of two u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the return value is constrained to be correct.
    pub fn eval_and_u32<AB: SP1AirBuilder>(
        builder: &mut AB,
        b: [AB::Expr; 2],
        c: [AB::Expr; 2],
        cols: AndU32Operation<AB::Var>,
        is_real: AB::Var,
    ) -> [AB::Expr; 2] {
        // Constrain that `is_real` is boolean.
        builder.assert_bool(is_real);

        // Convert the two words to bytes using the unsafe API.
        // SAFETY: This is safe because the byte lookup will range check the bytes.
        let b_bytes =
            U32toU8Operation::<AB::F>::eval_u32_to_u8_unsafe(builder, b, cols.b_low_bytes);
        let c_bytes =
            U32toU8Operation::<AB::F>::eval_u32_to_u8_unsafe(builder, c, cols.c_low_bytes);

        // Constrain the `AND` operation over bytes via a byte lookup.
        for i in 0..4 {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::AND as u32),
                cols.value[i],
                b_bytes[i].clone(),
                c_bytes[i].clone(),
                is_real,
            );
        }

        // Combine the byte results into two u16 limbs.
        let result_limb0 = cols.value[0] + cols.value[1] * AB::F::from_canonical_u32(1 << 8);
        let result_limb1 = cols.value[2] + cols.value[3] * AB::F::from_canonical_u32(1 << 8);

        [result_limb0, result_limb1]
    }
}
