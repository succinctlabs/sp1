use core::borrow::Borrow;

use p3_air::{Air, BaseAir, PairBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use sp1_core_executor::ByteOpcode;
use sp1_stark::air::SP1AirBuilder;

use super::{
    columns::{ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS},
    ByteChip,
};

impl<F: Field> BaseAir<F> for ByteChip<F> {
    fn width(&self) -> usize {
        NUM_BYTE_MULT_COLS
    }
}

impl<AB: SP1AirBuilder + PairBuilder> Air<AB> for ByteChip<AB::F> {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_mult = main.row_slice(0);
        let local_mult: &ByteMultCols<AB::Var> = (*local_mult).borrow();

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        let local: &BytePreprocessedCols<AB::Var> = (*prep).borrow();

        // Send all the lookups for each operation.
        for (i, opcode) in ByteOpcode::all().iter().enumerate() {
            let field_op = opcode.as_field::<AB::F>();
            let mult = local_mult.multiplicities[i];
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
                ByteOpcode::U8Range => {
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
                ByteOpcode::U16Range => builder.receive_byte(
                    field_op,
                    local.value_u16,
                    AB::F::zero(),
                    AB::F::zero(),
                    mult,
                ),
            }
        }
    }
}
