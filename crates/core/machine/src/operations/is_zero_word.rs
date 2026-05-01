//! An operation to check if the input word is 0.
//!
//! This is bijective (i.e., returns 1 if and only if the input is 0). It is also worth noting that
//! this operation doesn't do a range check.
use serde::{Deserialize, Serialize};
use slop_air::AirBuilder;
use slop_algebra::Field;
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::WORD_SIZE;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::air::{SP1Operation, SP1OperationBuilder};

use super::{IsZeroOperation, IsZeroOperationInput};

/// A set of columns needed to compute whether the given `Word` is 0.
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
pub struct IsZeroWordOperation<T> {
    /// `IsZeroOperation` to check if each limb in the input `Word` is zero.
    pub is_zero_limb: [IsZeroOperation<T>; WORD_SIZE],

    /// If the first two limbs of the `Word` is zero.
    pub is_zero_first_half: T,

    /// If the last two limbs of the `Word` is zero.
    pub is_zero_second_half: T,

    /// A boolean flag indicating whether the input `Word` is zero.
    pub result: T,
}

impl<F: Field> IsZeroWordOperation<F> {
    pub fn populate(&mut self, a_u64: u64) -> u64 {
        self.populate_from_field_element(Word::from(a_u64))
    }

    pub fn populate_from_field_element(&mut self, a: Word<F>) -> u64 {
        let mut is_zero = true;
        for i in 0..WORD_SIZE {
            is_zero &= self.is_zero_limb[i].populate_from_field_element(a[i]) == 1;
        }
        self.result = F::from_bool(is_zero);
        self.is_zero_first_half = self.is_zero_limb[0].result * self.is_zero_limb[1].result;
        self.is_zero_second_half = self.is_zero_limb[2].result * self.is_zero_limb[3].result;
        is_zero as u64
    }

    /// Evaluate the `IsZeroWordOperation` on the given inputs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, it constrains that the result is `a == 0`.
    fn eval_zero_word<
        AB: SP1AirBuilder + SP1OperationBuilder<IsZeroOperation<<AB as AirBuilder>::F>>,
    >(
        builder: &mut AB,
        a: Word<AB::Expr>,
        cols: IsZeroWordOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        // Calculate whether each limb is 0.
        for i in 0..WORD_SIZE {
            IsZeroOperation::<AB::F>::eval(
                builder,
                IsZeroOperationInput::new(a[i].clone(), cols.is_zero_limb[i], is_real.clone()),
            )
        }

        // Check that `is_real` is boolean.
        builder.assert_bool(is_real.clone());
        // Check that `result` is boolean.
        builder.assert_bool(cols.result);

        // The first half is zero if and only if the first two limbs are both zero.
        builder.assert_eq(
            cols.is_zero_first_half,
            cols.is_zero_limb[0].result * cols.is_zero_limb[1].result,
        );
        // The second half is zero if and only if the last two limbs are both zero.
        builder.assert_eq(
            cols.is_zero_second_half,
            cols.is_zero_limb[2].result * cols.is_zero_limb[3].result,
        );

        // The `Word` is zero if and only if both halves are zero.
        builder
            .when(is_real.clone())
            .assert_eq(cols.result, cols.is_zero_first_half * cols.is_zero_second_half);
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct IsZeroWordOperationInput<AB: SP1AirBuilder> {
    pub a: Word<AB::Expr>,
    pub cols: IsZeroWordOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder + SP1OperationBuilder<IsZeroOperation<<AB as AirBuilder>::F>>>
    SP1Operation<AB> for IsZeroWordOperation<AB::F>
{
    type Input = IsZeroWordOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) {
        Self::eval_zero_word(builder, input.a, input.cols, input.is_real);
    }
}
