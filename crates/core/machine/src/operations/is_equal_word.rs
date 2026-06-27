use serde::{Deserialize, Serialize};
use slop_air::AirBuilder;
use slop_algebra::Field;
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::{u64_to_u16_limbs, WORD_SIZE};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    air::{SP1Operation, SP1OperationBuilder},
    operations::IsZeroOperation,
};

use super::{IsZeroWordOperation, IsZeroWordOperationInput};

/// A set of columns needed to compute the equality of two words.
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
pub struct IsEqualWordOperation<T> {
    /// An operation to check whether the differences in limbs are all 0.
    /// The result of `IsEqualWordOperation` is `is_diff_zero.result`.
    pub is_diff_zero: IsZeroWordOperation<T>,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> IsEqualWordOperation<T> {
    /// Backend-agnostic witgen dual of [`Self::populate`]: the inner
    /// `IsZeroWordOperation` over the per-limb differences `a[i] − b[i]`. Since
    /// `a[i]`, `b[i]` are u16, `diff == 0 ⟺ a[i] == b[i]`, so the result is `eq` in
    /// nat-space and the inverse is the field inverse of the (possibly-large) diff.
    /// Returns the 0/1 `result` as a nat.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut IsEqualWordOperation<WB::Field>,
        a: WB::Nat,
        b: WB::Nat,
    ) -> WB::Nat {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        let one_f = wb.nat_to_field(one);
        let zero_f = wb.nat_to_field(zero);
        let izw = &mut cols.is_diff_zero;
        let mut eqs = [zero; WORD_SIZE];
        for i in 0..WORD_SIZE {
            let a_i = wb.bits(a, (i as u32) * 16, 16);
            let b_i = wb.bits(b, (i as u32) * 16, 16);
            let eq_i = wb.eq(a_i, b_i);
            izw.is_zero_limb[i].result = wb.nat_to_field(eq_i);
            let a_f = wb.nat_to_field(a_i);
            let b_f = wb.nat_to_field(b_i);
            let diff = wb.field_sub(a_f, b_f);
            let safe = wb.field_select(eq_i, one_f, diff);
            let inv = wb.field_inverse(safe);
            izw.is_zero_limb[i].inverse = wb.field_select(eq_i, zero_f, inv);
            eqs[i] = eq_i;
        }
        let fh = wb.select(eqs[0], eqs[1], zero);
        izw.is_zero_first_half = wb.nat_to_field(fh);
        let sh = wb.select(eqs[2], eqs[3], zero);
        izw.is_zero_second_half = wb.nat_to_field(sh);
        let res = wb.select(fh, sh, zero);
        izw.result = wb.nat_to_field(res);
        res
    }
}

impl<F: Field> IsEqualWordOperation<F> {
    pub fn populate(&mut self, a_u64: u64, b_u64: u64) -> u64 {
        let a = u64_to_u16_limbs(a_u64);
        let b = u64_to_u16_limbs(b_u64);
        let diff = [
            F::from_canonical_u16(a[0]) - F::from_canonical_u16(b[0]),
            F::from_canonical_u16(a[1]) - F::from_canonical_u16(b[1]),
            F::from_canonical_u16(a[2]) - F::from_canonical_u16(b[2]),
            F::from_canonical_u16(a[3]) - F::from_canonical_u16(b[3]),
        ];
        self.is_diff_zero.populate_from_field_element(Word(diff));
        (a_u64 == b_u64) as u64
    }

    /// Evaluate the `IsEqualWordOperation` on the given inputs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, it constrains that the result is `a == b`.
    fn eval_is_equal_word<
        AB: SP1AirBuilder
            + SP1OperationBuilder<IsZeroOperation<<AB as AirBuilder>::F>>
            + SP1OperationBuilder<IsZeroWordOperation<<AB as AirBuilder>::F>>,
    >(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        cols: IsEqualWordOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        // Calculate differences in limbs.
        let diff = Word([
            a[0].clone() - b[0].clone(),
            a[1].clone() - b[1].clone(),
            a[2].clone() - b[2].clone(),
            a[3].clone() - b[3].clone(),
        ]);

        // Check if the difference is 0.
        <IsZeroWordOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            IsZeroWordOperationInput::new(diff, cols.is_diff_zero, is_real.clone()),
        );
    }
}

#[derive(Clone, InputExpr, InputParams)]
pub struct IsEqualWordOperationInput<AB: SP1AirBuilder> {
    pub a: Word<AB::Expr>,
    pub b: Word<AB::Expr>,
    pub cols: IsEqualWordOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<
        AB: SP1AirBuilder
            + SP1OperationBuilder<IsZeroOperation<<AB as AirBuilder>::F>>
            + SP1OperationBuilder<IsZeroWordOperation<<AB as AirBuilder>::F>>,
    > SP1Operation<AB> for IsEqualWordOperation<AB::F>
{
    type Input = IsEqualWordOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) {
        Self::eval_is_equal_word(builder, input.a, input.b, input.cols, input.is_real);
    }
}
