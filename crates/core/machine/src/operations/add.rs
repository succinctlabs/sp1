use serde::{Deserialize, Serialize};
use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_SIZE};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use crate::air::{SP1Operation, WordAirBuilder};
use struct_reflection::{StructReflection, StructReflectionHelper};

/// A set of columns needed to compute the add of two `Words`.
#[derive(
    AlignedBorrow,
    StructReflection,
    Default,
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    IntoShape,
    SP1OperationBuilder,
)]
#[repr(C)]
pub struct AddOperation<T> {
    /// The result of `a + b`.
    pub value: Word<T>,
}

impl<F: Field> AddOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u64: u64, b_u64: u64) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        self.value = Word::from(expected);
        // Range check
        record.add_u16_range_checks(&u64_to_u16_limbs(expected));
        expected
    }

    /// Evaluate the add operation.
    /// Assumes that `a`, `b` are valid `Word`s of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the `value` is constrained to a valid `Word` representing `a + b`.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        cols: AddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry = AB::Expr::zero();

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = a[i] + b[i] + carry
        //  - carry is boolean
        //  - 0 <= value[i] < 2^16
        for i in 0..WORD_SIZE {
            carry = (a[i].clone() + b[i].clone() - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value.0, is_real);
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct AddOperationInput<AB: SP1AirBuilder> {
    #[picus(input)]
    pub a: Word<AB::Expr>,
    #[picus(input)]
    pub b: Word<AB::Expr>,
    #[picus(output)]
    pub cols: AddOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for AddOperation<AB::F> {
    type Input = AddOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(builder, input.a, input.b, input.cols, input.is_real);
    }
}
