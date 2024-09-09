use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};
use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_derive::AlignedBorrow;
use sp1_primitives::consts::WORD_SIZE;
use sp1_stark::{air::SP1AirBuilder, Word};

/// A set of columns needed to compute the not of a word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotOperation<T> {
    /// The result of `!x`.
    pub value: Word<T>,
}

impl<F: Field> NotOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, shard: u32, x: u32) -> u32 {
        let expected = !x;
        let x_bytes = x.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(!x_bytes[i]);
        }
        record.add_u8_range_checks(shard, &x_bytes);
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        cols: NotOperation<AB::Var>,
        is_real: impl Into<AB::Expr> + Copy,
    ) {
        for i in (0..WORD_SIZE).step_by(2) {
            builder.send_byte_pair(
                AB::F::from_canonical_u32(ByteOpcode::U8Range as u32),
                AB::F::zero(),
                AB::F::zero(),
                a[i],
                a[i + 1],
                is_real,
            );
        }

        // For any byte b, b + !b = 0xFF.
        for i in 0..WORD_SIZE {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i], AB::F::from_canonical_u8(u8::MAX));
        }
    }
}
