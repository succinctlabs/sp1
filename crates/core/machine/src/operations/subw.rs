use std::num::Wrapping;

use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_SIZE};
use struct_reflection::{StructReflection, StructReflectionHelper};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use crate::{
    air::{SP1Operation, SP1OperationBuilder, WordAirBuilder},
    operations::{U16MSBOperation, U16MSBOperationInput},
};

/// A set of columns needed to compute the sub of two words.
#[derive(
    AlignedBorrow, Default, Debug, Clone, Copy, IntoShape, SP1OperationBuilder, StructReflection,
)]
#[repr(C)]
pub struct SubwOperation<T> {
    /// The result of `a - b`.
    pub value: [T; WORD_SIZE / 2],
    /// The msb of the result.
    pub msb: U16MSBOperation<T>,
}

impl<F: Field> SubwOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u64: u64, b_u64: u64) {
        let value = (Wrapping(a_u64 as i32) - Wrapping(b_u64 as i32)).0 as i64 as u64;
        let limbs = u64_to_u16_limbs(value);
        self.value = [F::from_canonical_u16(limbs[0]), F::from_canonical_u16(limbs[1])];

        // Range check
        record.add_u16_range_checks(&limbs[..WORD_SIZE / 2]);
        self.msb.populate_msb(record, limbs[1]);
    }

    /// Evaluate the sub operation.
    /// Assumes that `a`, `b` are valid `Word`s of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the `value` is constrained to be the lower u32 of the SUBW result.
    /// Also, the `msb` will be constrained to equal the most significant bit of the `value`.
    pub fn eval<AB>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: SubwOperation<AB::Var>,
        is_real: AB::Expr,
    ) where
        AB: SP1AirBuilder + SP1OperationBuilder<U16MSBOperation<<AB as AirBuilder>::F>>,
    {
        builder.assert_bool(is_real.clone());

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry = AB::Expr::one();
        let one = AB::Expr::one();

        // Use the same logic as addition, for (a + (2^32 - b)).
        // This by using `2^16 - 1 - b[i]` as the added limb, and initializing the carry to 1.
        for i in 0..WORD_SIZE / 2 {
            carry = (a[i] + base - one.clone() - b[i] - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real.clone());

        U16MSBOperation::<AB::F>::eval(
            builder,
            U16MSBOperationInput::new(cols.value[1].into(), cols.msb, is_real.clone()),
        );
    }
}

#[derive(Debug, Clone, InputExpr, InputParams)]
pub struct SubwOperationInput<AB: SP1AirBuilder> {
    pub a: Word<AB::Var>,
    pub b: Word<AB::Var>,
    pub cols: SubwOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB> SP1Operation<AB> for SubwOperation<<AB as AirBuilder>::F>
where
    AB: SP1AirBuilder + SP1OperationBuilder<U16MSBOperation<<AB as AirBuilder>::F>>,
{
    type Input = SubwOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(builder, input.a, input.b, input.cols, input.is_real);
    }
}
