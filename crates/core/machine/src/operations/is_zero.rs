//! An operation to check if the input is 0.
//!
//! This is guaranteed to return 1 if and only if the input is 0.
//!
//! The idea is that 1 - input * inverse is exactly the boolean value indicating whether the input
//! is 0.
use serde::{Deserialize, Serialize};
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use sp1_hypercube::air::SP1AirBuilder;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::air::SP1Operation;

/// A set of columns needed to compute whether the given input is 0.
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
pub struct IsZeroOperation<T> {
    /// The inverse of the input.
    pub inverse: T,

    /// Result indicating whether the input is 0. This equals `inverse * input == 0`.
    pub result: T,
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> IsZeroOperation<T> {
    /// Backend-agnostic witgen dual of [`Self::populate`] for a small (≤u16) nat
    /// input: `result = (a == 0)` and `inverse = a^{-1}` (0 when `a == 0`). Returns
    /// the 0/1 `result` as a nat.
    pub fn witgen<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut IsZeroOperation<WB::Field>,
        a: WB::Nat,
    ) -> WB::Nat {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        let is_z = wb.eq(a, zero);
        cols.result = wb.nat_to_field(is_z);
        let a_f = wb.nat_to_field(a);
        let one_f = wb.nat_to_field(one);
        let zero_f = wb.nat_to_field(zero);
        let safe = wb.field_select(is_z, one_f, a_f);
        let inv = wb.field_inverse(safe);
        cols.inverse = wb.field_select(is_z, zero_f, inv);
        is_z
    }

    /// Witgen dual of `populate_from_field_element(a_f - b_f)` where `a` and `b` are
    /// small nats embedded in the field (both < p, so `a_f == b_f` iff `a == b`):
    /// `result = (a == b)` and `inverse = (a_f - b_f)^{-1}` (0 when equal). Used by
    /// the syscall-id discriminators (`syscall_id_byte` vs a `SyscallCode`
    /// constant). Returns the 0/1 `result` as a nat.
    pub fn witgen_nat_diff<WB: crate::air::WitnessBuilder>(
        wb: &mut WB,
        cols: &mut IsZeroOperation<WB::Field>,
        a: WB::Nat,
        b: WB::Nat,
    ) -> WB::Nat {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        let is_z = wb.eq(a, b);
        cols.result = wb.nat_to_field(is_z);
        let a_f = wb.nat_to_field(a);
        let b_f = wb.nat_to_field(b);
        let diff_f = wb.field_sub(a_f, b_f);
        let one_f = wb.nat_to_field(one);
        let zero_f = wb.nat_to_field(zero);
        let safe = wb.field_select(is_z, one_f, diff_f);
        let inv = wb.field_inverse(safe);
        cols.inverse = wb.field_select(is_z, zero_f, inv);
        is_z
    }
}

impl<F: Field> IsZeroOperation<F> {
    pub fn populate(&mut self, a: u64) -> u64 {
        self.populate_from_field_element(F::from_canonical_u64(a))
    }

    pub fn populate_from_field_element(&mut self, a: F) -> u64 {
        if a == F::zero() {
            self.inverse = F::zero();
            self.result = F::one();
        } else {
            self.inverse = a.inverse();
            self.result = F::zero();
        }
        let prod = self.inverse * a;
        debug_assert!(prod == F::one() || prod == F::zero());
        (a == F::zero()) as u64
    }

    /// Evaluate the `IsZeroOperation` on the given inputs.
    /// If `is_real` is non-zero, it constrains that the result is `a == 0`.
    fn eval_is_zero<AB: SP1AirBuilder>(
        builder: &mut AB,
        a: AB::Expr,
        cols: IsZeroOperation<AB::Var>,
        is_real: AB::Expr,
    ) {
        let one: AB::Expr = AB::Expr::one();

        // 1. Input == 0 => is_zero = 1 regardless of the inverse.
        // 2. Input != 0
        //   2.1. inverse is correctly set => is_zero = 0.
        //   2.2. inverse is incorrect
        //     2.2.1 inverse is nonzero => is_zero isn't bool, it fails.
        //     2.2.2 inverse is 0 => is_zero is 1. But then we would assert that a = 0. And that
        //                           assert fails.

        // If the input is 0, then any product involving it is 0. If it is nonzero and its inverse
        // is correctly set, then the product is 1.
        let is_zero = one.clone() - cols.inverse * a.clone();
        builder.when(is_real.clone()).assert_eq(is_zero, cols.result);
        builder.when(is_real.clone()).assert_bool(cols.result);

        // If the result is 1, then the input is 0.
        builder.when(is_real.clone()).when(cols.result).assert_zero(a.clone());
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct IsZeroOperationInput<AB: SP1AirBuilder> {
    pub a: AB::Expr,
    pub cols: IsZeroOperation<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for IsZeroOperation<AB::F> {
    type Input = IsZeroOperationInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) {
        Self::eval_is_zero(builder, input.a, input.cols, input.is_real);
    }
}
