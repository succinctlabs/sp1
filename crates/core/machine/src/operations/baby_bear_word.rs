use p3_air::AirBuilder;
use p3_field::{AbstractField, Field, PrimeField32};
use sp1_core_executor::{
    events::{ByteLookupEvent, ByteRecord},
    ByteOpcode,
};
use sp1_derive::AlignedBorrow;
use sp1_stark::{
    air::{BaseAirBuilder, SP1AirBuilder},
    Word,
};

/// A set of columns needed to range check a BabyBear word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BabyBearWordRangeChecker<T> {
    /// Most sig byte is less than 120.
    pub most_sig_byte_lt_120: T,
}

impl<F: PrimeField32> BabyBearWordRangeChecker<F> {
    pub fn populate(&mut self, value: Word<F>, record: &mut impl ByteRecord) {
        let ms_byte_u8 = value[3].as_canonical_u32() as u8;
        self.most_sig_byte_lt_120 = F::from_bool(ms_byte_u8 < 120);

        // Add the byte lookup for the range check bit.
        record.add_byte_lookup_event(ByteLookupEvent {
            opcode: ByteOpcode::LTU,
            a1: if ms_byte_u8 < 120 { 1 } else { 0 },
            a2: 0,
            b: ms_byte_u8,
            c: 120,
        });
    }
}

impl<F: Field> BabyBearWordRangeChecker<F> {
    pub fn range_check<AB: SP1AirBuilder>(
        builder: &mut AB,
        value: Word<AB::Var>,
        cols: BabyBearWordRangeChecker<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Range check that value is less than baby bear modulus.  To do this, it is sufficient
        // to just do comparisons for the most significant byte. BabyBear's modulus is (in big
        // endian binary) 01111000_00000000_00000000_00000001.  So we need to check the
        // following conditions:
        // 1) if most_sig_byte > 01111000 (or 120 in decimal), then fail.
        // 2) if most_sig_byte == 01111000, then value's lower sig bytes must all be 0.
        // 3) if most_sig_byte < 01111000, then pass.

        let ms_byte = value[3];

        // The range check bit is on if and only if the most significant byte of the word is < 120.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::LTU as u32),
            cols.most_sig_byte_lt_120,
            ms_byte,
            AB::Expr::from_canonical_u8(120),
            is_real.clone(),
        );

        let mut is_real_builder = builder.when(is_real.clone());

        // If the range check bit is off, the most significant byte is >=120, so to be a valid BabyBear
        // word we need the most significant byte to be =120.
        is_real_builder
            .when_not(cols.most_sig_byte_lt_120)
            .assert_eq(ms_byte, AB::Expr::from_canonical_u8(120));

        // Moreover, if the most significant byte =120, then the 3 other bytes must all be zero.s
        let mut assert_zero_builder = is_real_builder.when_not(cols.most_sig_byte_lt_120);
        assert_zero_builder.assert_zero(value[0]);
        assert_zero_builder.assert_zero(value[1]);
        assert_zero_builder.assert_zero(value[2]);
    }
}
