use serde::{Deserialize, Serialize};
use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_SIZE};
use struct_reflection::{StructReflection, StructReflectionHelper};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use crate::air::{SP1Operation, WordAirBuilder};

/// A set of columns needed to compute the sub of two words.
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
pub struct SubOperation<T> {
    /// The result of `a - b`.
    pub value: Word<T>,
}

impl<F: Field> SubOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u64: u64, b_u64: u64) -> u64 {
        let expected = a_u64.wrapping_sub(b_u64);
        self.value = Word::from(expected);
        // Range check
        record.add_u16_range_checks(&u64_to_u16_limbs(expected));
        expected
    }

    /// Evaluate the sub operation.
    /// Assumes that `a`, `b` are valid `Word`s of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the `value` is constrained to a valid `Word` representing `a - b`.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: SubOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry = AB::Expr::one();
        let one = AB::Expr::one();

        // Use the same logic as addition, for (a + (2^64 - b)).
        // This by using `2^16 - 1 - b[i]` as the added limb, and initializing the carry to 1.
        for i in 0..WORD_SIZE {
            carry = (a[i] + base - one.clone() - b[i] - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value.0, is_real);
    }
}

#[derive(Clone, InputExpr, InputParams)]
pub struct SubOperationInput<AB: SP1AirBuilder> {
    pub a: Word<AB::Var>,
    pub b: Word<AB::Var>,
    pub cols: SubOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for SubOperation<AB::F> {
    type Input = SubOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(builder, input.a, input.b, input.cols, input.is_real);
    }
}
