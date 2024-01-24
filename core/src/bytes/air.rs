use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;
use core::mem::transmute;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_field::{AbstractField, ExtensionField};
use p3_matrix::MatrixRowSlices;
use p3_util::indices_arr;
use valida_derive::AlignedBorrow;

use crate::air::CurtaAirBuilder;

use super::NUM_BYTE_OPS;
use super::{ByteChip, ByteOpcode};

pub const NUM_BYTE_COLS: usize = size_of::<ByteCols<u8>>();
pub(crate) const BYTE_COL_MAP: ByteCols<usize> = make_col_map();
pub(crate) const BYTE_MULT_INDICES: [usize; NUM_BYTE_OPS] = BYTE_COL_MAP.multiplicities;

const fn make_col_map() -> ByteCols<usize> {
    let indices_arr = indices_arr::<NUM_BYTE_COLS>();
    unsafe { transmute::<[usize; NUM_BYTE_COLS], ByteCols<usize>>(indices_arr) }
}

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct ByteCols<T> {
    /// The first byte operand.
    pub b: T,

    /// The second byte operand.
    pub c: T,

    /// The result of the `AND` operation on `a` and `b`
    pub and: T,

    /// The result of the `OR` operation on `a` and `b`
    pub or: T,

    /// The result of the `XOR` operation on `a` and `b`
    pub xor: T,

    /// The result of the `SLL` operation on `a` and `b`
    pub sll: T,

    /// The result of the `ShrCarry` operation on `a` and `b`.
    pub shr: T,
    pub shr_carry: T,

    /// The result of the `LTU` operation on `a` and `b`.
    pub ltu: T,

    /// The most significant bit of `b`.
    pub msb: T,

    pub multiplicities: [T; NUM_BYTE_OPS],
}

impl<EF: ExtensionField<F>, F: Field> BaseAir<EF> for ByteChip<F> {
    fn width(&self) -> usize {
        NUM_BYTE_COLS
    }
}

impl<AB: CurtaAirBuilder, F: Field> Air<AB> for ByteChip<F>
where
    AB::F: ExtensionField<F>,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &ByteCols<AB::Var> = main.row_slice(0).borrow();

        // Dummy constraint for normalizing to degree 3.
        #[allow(clippy::eq_op)]
        builder.assert_zero(local.b * local.b * local.b - local.b * local.b * local.b);

        // Send all the lookups for each operation.
        for (i, opcode) in ByteOpcode::get_all().iter().enumerate() {
            let field_op = opcode.to_field::<AB::F>();
            let mult = local.multiplicities[i];
            match opcode {
                ByteOpcode::AND => {
                    builder.receive_byte(field_op, local.and, local.b, local.c, mult)
                }
                ByteOpcode::OR => builder.receive_byte(field_op, local.or, local.b, local.c, mult),
                ByteOpcode::XOR => {
                    builder.receive_byte(field_op, local.xor, local.b, local.c, mult)
                }
                ByteOpcode::SLL => {
                    builder.receive_byte(field_op, local.sll, local.b, local.c, mult)
                }
                ByteOpcode::Range => {
                    builder.receive_byte(field_op, AB::F::zero(), local.b, local.c, mult)
                }
                ByteOpcode::ShrCarry => builder.receive_byte_pair(
                    field_op,
                    local.shr,
                    local.shr_carry,
                    local.b,
                    local.c,
                    mult,
                ),
                ByteOpcode::LTU => {
                    builder.receive_byte(field_op, local.ltu, local.b, local.c, mult)
                }
                ByteOpcode::MSB => {
                    builder.receive_byte(field_op, local.msb, local.b, AB::F::zero(), mult)
                }
            }
        }
    }
}
