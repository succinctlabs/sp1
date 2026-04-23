use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_core_executor::events::ByteRecord;
use sp1_derive::AlignedBorrow;
use sp1_hypercube::{
    air::{BaseAirBuilder, SP1AirBuilder},
    Word,
};
use sp1_primitives::SP1Field;
use struct_reflection::{StructReflection, StructReflectionHelper};

const_assert!((SP1Field::ORDER_U32 - 1).is_multiple_of(1 << 16));

const TOP_LIMB: u16 = ((SP1Field::ORDER_U32 - 1) >> 16) as u16;

use crate::{
    air::{SP1Operation, SP1OperationBuilder},
    operations::U16CompareOperationInput,
};

use super::U16CompareOperation;

/// A set of columns needed to range check a SP1Field word.
#[derive(AlignedBorrow, StructReflection, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct SP1FieldWordRangeChecker<T> {
    /// Most significant limb is less than 127 * 2^8 = 32512.
    pub most_sig_limb_lt_top_limb: U16CompareOperation<T>,
}

impl<F: PrimeField32> SP1FieldWordRangeChecker<F> {
    pub fn populate(&mut self, value: Word<F>, record: &mut impl ByteRecord) {
        let ms_limb = value[1].as_canonical_u32() as u16;
        self.most_sig_limb_lt_top_limb.populate(
            record,
            (ms_limb < TOP_LIMB) as u16,
            ms_limb,
            TOP_LIMB,
        );
    }
}

impl<F: Field> SP1FieldWordRangeChecker<F> {
    /// Constrains that `value` represents a value less than the SP1Field modulus.
    /// Assumes that `value` is a valid `Word` of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, constrains that `value` is a valid SP1Field word.
    pub fn range_check<AB>(
        builder: &mut AB,
        value: Word<AB::Expr>,
        cols: SP1FieldWordRangeChecker<AB::Var>,
        is_real: AB::Expr,
    ) where
        AB: SP1AirBuilder + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>,
    {
        builder.assert_bool(is_real.clone());
        builder.when(is_real.clone()).assert_zero(value[2].clone());
        builder.when(is_real.clone()).assert_zero(value[3].clone());

        // Note that SP1Field modulus is 2^31 - 2^24 + 1 = 127 * 2^24 + 1.
        // First, check if the most significant limb is less than 127 * 2^8 = 32512.
        <U16CompareOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16CompareOperationInput::<AB>::new(
                value[1].clone(),
                AB::Expr::from_canonical_u16(TOP_LIMB),
                cols.most_sig_limb_lt_top_limb,
                is_real.clone(),
            ),
        );

        // If the range check bit is off, the most significant limb is >= 127 * 2^8 = 32512.
        // To be a valid SP1Field word, the most significant limb must be 127 * 2^8 = 32512.
        builder
            .when(is_real.clone())
            .when_not(cols.most_sig_limb_lt_top_limb.bit)
            .assert_eq(value[1].clone(), AB::Expr::from_canonical_u16(TOP_LIMB));

        // Moreover, if the most significant limb = 15 * 2^11, then the other limb must be zero.
        builder
            .when(is_real.clone())
            .when_not(cols.most_sig_limb_lt_top_limb.bit)
            .assert_zero(value[0].clone());
    }
}
