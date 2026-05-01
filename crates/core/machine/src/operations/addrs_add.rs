use serde::{Deserialize, Serialize};
use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_SIZE};
use struct_reflection::{StructReflection, StructReflectionHelper};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use crate::air::{SP1Operation, WordAirBuilder};

/// A set of columns needed to compute the addition of two Words as an u48 address.
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
pub struct AddrAddOperation<T> {
    /// The result of `a + b` in u48 (three u16 limbs).
    pub value: [T; 3],
}

impl<F: Field> AddrAddOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u64: u64, b_u64: u64) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        assert!(expected >> 48 == 0);
        self.value = [
            F::from_canonical_u16((expected & 0xFFFF) as u16),
            F::from_canonical_u16((expected >> 16) as u16),
            F::from_canonical_u16((expected >> 32) as u16),
        ];
        // Range check
        record.add_u16_range_checks(&u64_to_u16_limbs(expected)[..3]);
        expected
    }

    /// Evaluate the add operation.
    /// Assumes that `a`, `b` are valid `Word`s.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, `value` is constrained to a valid u48 address `a + b`.
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        cols: AddrAddOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Constrain that `is_real` is boolean.
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
            let value = if i < WORD_SIZE - 1 { cols.value[i].into() } else { AB::Expr::zero() };
            carry = (a[i].clone() + b[i].clone() - value + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real);
    }
}

#[derive(Debug, Clone, InputParams, InputExpr)]
pub struct AddrAddOperationInput<AB: SP1AirBuilder> {
    pub a: Word<AB::Expr>,
    pub b: Word<AB::Expr>,
    pub cols: AddrAddOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for AddrAddOperation<AB::F> {
    type Input = AddrAddOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(builder, input.a, input.b, input.cols, input.is_real);
    }
}
