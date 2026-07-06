use itertools::izip;
use serde::{Deserialize, Serialize};
use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::{air::SP1AirBuilder, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_primitives::consts::WORD_SIZE;

use crate::air::{HostWitnessBuilder, SP1Operation, SP1OperationBuilder, WitnessBuilder};

use super::{U16CompareOperation, U16CompareOperationInput, U16MSBOperation, U16MSBOperationInput};

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
pub struct LtOperationUnsigned<T> {
    /// Instance of the U16CompareOperation.
    pub u16_compare_operation: U16CompareOperation<T>,
    /// Boolean flag to indicate which limb pair differs if the operands are not equal.
    pub u16_flags: [T; WORD_SIZE],
    /// An inverse of differing limb if b_comp != c_comp.
    pub not_eq_inv: T,
    /// The comparison limbs to be looked up.
    pub comparison_limbs: [T; 2],
}

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
pub struct LtOperationSigned<T> {
    /// The result of the SLTU operation.
    pub result: LtOperationUnsigned<T>,
    /// The most significant bit of operand b if `is_signed` is true.
    pub b_msb: U16MSBOperation<T>,
    /// The most significant bit of operand c if `is_signed` is true.
    pub c_msb: U16MSBOperation<T>,
}

/// `x ^ (1 << 63)` (toggle the top bit) using only DSL ops: `low_63 + (msb ? 0 :
/// 1<<63)`. Used to map signed comparison to unsigned by flipping the sign bit.
fn flip_top_bit<WB: WitnessBuilder>(wb: &mut WB, x: WB::Nat) -> WB::Nat {
    let zero = wb.const_nat(0);
    let low = wb.bits(x, 0, 63);
    let msb = wb.bits(x, 63, 1);
    let big = wb.const_nat(1u64 << 63);
    let add = wb.select(msb, zero, big);
    wb.wrapping_add(low, add)
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> LtOperationSigned<T> {
    /// Backend-agnostic witgen dual of [`Self::eval_lt_signed`]: per-row signed vs
    /// unsigned (`is_signed`). The MSB gadgets of `b`/`c` are computed always but
    /// their lookups are guarded by `is_signed` and their `msb` column is 0 when
    /// unsigned (field_select); the signed comparison flips the sign bit of `b`/`c`.
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut LtOperationSigned<WB::Field>,
        a: WB::Nat,
        b: WB::Nat,
        c: WB::Nat,
        is_signed: WB::Nat,
    ) {
        let zero = wb.const_nat(0);
        let zero_f = wb.nat_to_field(zero);
        let b3 = wb.bits(b, 48, 16);
        let c3 = wb.bits(c, 48, 16);
        wb.push_guard(is_signed);
        U16MSBOperation::<WB::Field>::witgen(wb, &mut cols.b_msb, b3);
        U16MSBOperation::<WB::Field>::witgen(wb, &mut cols.c_msb, c3);
        wb.pop_guard();
        cols.b_msb.msb = wb.field_select(is_signed, cols.b_msb.msb, zero_f);
        cols.c_msb.msb = wb.field_select(is_signed, cols.c_msb.msb, zero_f);
        // Map signed → unsigned by flipping the sign bit when signed.
        let b_flip = flip_top_bit(wb, b);
        let c_flip = flip_top_bit(wb, c);
        let b_cmp = wb.select(is_signed, b_flip, b);
        let c_cmp = wb.select(is_signed, c_flip, c);
        LtOperationUnsigned::<WB::Field>::witgen(wb, &mut cols.result, a, b_cmp, c_cmp);
    }
}

impl<F: Field> LtOperationSigned<F> {
    pub fn populate_signed(
        &mut self,
        record: &mut impl ByteRecord,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
        is_signed: bool,
    ) {
        let mut wb = HostWitnessBuilder::<F, _>::new(record);
        Self::witgen(&mut wb, self, a_u64, b_u64, c_u64, is_signed as u64);
    }

    /// Evaluate the signed LT operation.
    /// Assumes that `b`, `c` are valid `Word`s of u16 limbs.
    /// Constrains that `is_signed` is boolean.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, constrains that the result is the signed LT of `b` and `c`.
    pub fn eval_lt_signed<AB>(
        builder: &mut AB,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        cols: LtOperationSigned<AB::Var>,
        is_signed: AB::Expr,
        is_real: AB::Expr,
    ) where
        AB: SP1AirBuilder
            + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>
            + SP1OperationBuilder<U16MSBOperation<<AB as AirBuilder>::F>>
            + SP1OperationBuilder<LtOperationUnsigned<<AB as AirBuilder>::F>>,
    {
        builder.assert_bool(is_signed.clone());
        builder.assert_bool(is_real.clone());
        // If `is_real` is false, assert that `is_signed` is zero.
        builder.when_not(is_real.clone()).assert_zero(is_signed.clone());

        // Constrain the MSB of `b` and `c` if `is_signed` is true.
        // This will be used to determine the sign of `b` and `c`.
        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::<AB>::new(
                b.0[WORD_SIZE - 1].clone(),
                cols.b_msb,
                is_signed.clone(),
            ),
        );
        <U16MSBOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16MSBOperationInput::<AB>::new(
                c.0[WORD_SIZE - 1].clone(),
                cols.c_msb,
                is_signed.clone(),
            ),
        );

        // Constrain `b` and `c` to be considered positive if `is_signed` is false.
        builder.when_not(is_signed.clone()).assert_zero(cols.b_msb.msb);
        builder.when_not(is_signed.clone()).assert_zero(cols.c_msb.msb);

        let mut b_compare = b;
        let mut c_compare = c;

        let base = AB::Expr::from_canonical_u32(1 << 16);

        // XOR `1 << 63` to `b` and `c` if `is_signed` is true.
        // If `is_signed` is false, the `msb` values are constrained to be zero.
        // If `is_signed` is true, the `msb` values are constrained by `U16MSBOperation`.
        // In both cases, `b_compare` and `c_compare` are correct.
        b_compare[WORD_SIZE - 1] = b_compare[WORD_SIZE - 1].clone()
            + is_signed.clone() * AB::Expr::from_canonical_u32(1 << 15)
            - base.clone() * cols.b_msb.msb;
        c_compare[WORD_SIZE - 1] = c_compare[WORD_SIZE - 1].clone()
            + is_signed.clone() * AB::Expr::from_canonical_u32(1 << 15)
            - base.clone() * cols.c_msb.msb;

        // Now apply the unsigned LT operation.
        <LtOperationUnsigned<AB::F> as SP1Operation<AB>>::eval(
            builder,
            LtOperationUnsignedInput::<AB>::new(b_compare, c_compare, cols.result, is_real.clone()),
        );
    }
}

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> LtOperationUnsigned<T> {
    /// Backend-agnostic witgen dual of [`Self::eval_lt_unsigned`]. The data-dependent
    /// "first differing limb (from the MSB)" search is expressed branch-free over the
    /// 4 limbs with `select`/`eq` chains; `not_eq_inv = (cb − cc)^{-1}` is guarded
    /// against the all-equal case (inverse of 0) via `field_select`.
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut LtOperationUnsigned<WB::Field>,
        a: WB::Nat,
        b: WB::Nat,
        c: WB::Nat,
    ) {
        let zero = wb.const_nat(0);
        let one = wb.const_nat(1);
        // u16 limbs of b and c.
        let b0 = wb.bits(b, 0, 16);
        let b1 = wb.bits(b, 16, 16);
        let b2 = wb.bits(b, 32, 16);
        let b3 = wb.bits(b, 48, 16);
        let c0 = wb.bits(c, 0, 16);
        let c1 = wb.bits(c, 16, 16);
        let c2 = wb.bits(c, 32, 16);
        let c3 = wb.bits(c, 48, 16);
        // Per-limb equality and "differs" flags.
        let eq0 = wb.eq(b0, c0);
        let eq1 = wb.eq(b1, c1);
        let eq2 = wb.eq(b2, c2);
        let eq3 = wb.eq(b3, c3);
        let ne0 = wb.eq(eq0, zero);
        let ne1 = wb.eq(eq1, zero);
        let ne2 = wb.eq(eq2, zero);
        let ne3 = wb.eq(eq3, zero);
        // First difference from the MSB: flag_i = differs_i AND (all higher equal).
        let first3 = ne3;
        let first2 = wb.select(eq3, ne2, zero);
        let he1 = wb.select(eq3, eq2, zero); // eq3 && eq2
        let first1 = wb.select(he1, ne1, zero);
        let he0 = wb.select(he1, eq1, zero); // eq3 && eq2 && eq1
        let first0 = wb.select(he0, ne0, zero);
        cols.u16_flags[3] = wb.nat_to_field(first3);
        cols.u16_flags[2] = wb.nat_to_field(first2);
        cols.u16_flags[1] = wb.nat_to_field(first1);
        cols.u16_flags[0] = wb.nat_to_field(first0);
        // Comparison limbs = (b, c) at the first differing limb, else 0.
        let cb_a = wb.select(first0, b0, zero);
        let cb_b = wb.select(first1, b1, cb_a);
        let cb_c = wb.select(first2, b2, cb_b);
        let cb = wb.select(first3, b3, cb_c);
        let cc_a = wb.select(first0, c0, zero);
        let cc_b = wb.select(first1, c1, cc_a);
        let cc_c = wb.select(first2, c2, cc_b);
        let cc = wb.select(first3, c3, cc_c);
        cols.comparison_limbs[0] = wb.nat_to_field(cb);
        cols.comparison_limbs[1] = wb.nat_to_field(cc);
        // not_eq_inv = (cb − cc)^{-1} when they differ, else 0 (avoid inverse(0)).
        let all_eq = wb.eq(cb, cc);
        let diff_f = wb.field_sub(cols.comparison_limbs[0], cols.comparison_limbs[1]);
        let one_f = wb.nat_to_field(one);
        let safe = wb.field_select(all_eq, one_f, diff_f);
        let inv = wb.field_inverse(safe);
        let zero_f = wb.nat_to_field(zero);
        cols.not_eq_inv = wb.field_select(all_eq, zero_f, inv);
        // The u16 compare over the low result limb and the comparison limbs.
        let a_u16 = wb.bits(a, 0, 16);
        U16CompareOperation::<WB::Field>::witgen(
            wb,
            &mut cols.u16_compare_operation,
            a_u16,
            cb,
            cc,
        );
    }
}

impl<F: Field> LtOperationUnsigned<F> {
    pub fn populate_unsigned(
        &mut self,
        record: &mut impl ByteRecord,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
    ) {
        let mut wb = HostWitnessBuilder::<F, _>::new(record);
        Self::witgen(&mut wb, self, a_u64, b_u64, c_u64);
    }

    /// Evaluate that LT operation.
    /// Assumes that `b`, `c` are either valid `Word`s of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, constrains that the result is the LT of `b` and `c`.
    pub fn eval_lt_unsigned<AB>(
        builder: &mut AB,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        cols: LtOperationUnsigned<AB::Var>,
        is_real: AB::Expr,
    ) where
        AB: SP1AirBuilder + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>,
    {
        builder.assert_bool(is_real.clone());

        // Verify that the limb equality flags are set correctly, i.e. all are boolean and only
        // at most a single flag is set to one.
        let sum_flags =
            cols.u16_flags[0] + cols.u16_flags[1] + cols.u16_flags[2] + cols.u16_flags[3];
        builder.assert_bool(cols.u16_flags[0]);
        builder.assert_bool(cols.u16_flags[1]);
        builder.assert_bool(cols.u16_flags[2]);
        builder.assert_bool(cols.u16_flags[3]);
        builder.assert_bool(sum_flags.clone());

        let is_comp_eq = AB::Expr::one() - sum_flags;

        // A flag to indicate whether an equality check is necessary.
        // This is for all limbs from most significant until the first inequality.
        let mut is_inequality_visited = AB::Expr::zero();

        // Iterate over the limbs in reverse order and select the differing limbs using the limb
        // flag columns values.
        let mut b_comparison_limb = AB::Expr::zero();
        let mut c_comparison_limb = AB::Expr::zero();
        for (b_limb, c_limb, &flag) in
            izip!(b.0.iter().rev(), c.0.iter().rev(), cols.u16_flags.iter().rev())
        {
            // Once the byte flag was set to one, we turn off the equality check flag.
            // We can do this by calculating the sum of the flags since only one is set to `1`.
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            // If inequality is not visited, assert that the limbs are equal.
            builder
                .when(is_real.clone() - is_inequality_visited.clone())
                .assert_eq(b_limb.clone(), c_limb.clone());

            b_comparison_limb = b_comparison_limb.clone() + b_limb.clone() * flag.into();
            c_comparison_limb = c_comparison_limb.clone() + c_limb.clone() * flag.into();
        }

        let (b_comp_limb, c_comp_limb) = (cols.comparison_limbs[0], cols.comparison_limbs[1]);
        builder.assert_eq(b_comparison_limb, b_comp_limb);
        builder.assert_eq(c_comparison_limb, c_comp_limb);

        // Using the values above, we can constrain the `is_comp_eq` flag. We already asserted
        // in the loop that when `is_comp_eq == 1` then all limbs are equal. It is left to
        // verify that when `is_comp_eq == 0` the comparison limbs are indeed not equal.
        // This is done using the inverse hint `not_eq_inv`, when `is_real` is true.
        builder
            .when_not(is_comp_eq)
            .assert_eq(cols.not_eq_inv * (b_comp_limb - c_comp_limb), is_real.clone());

        // Compare the two comparison limbs.
        <U16CompareOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            U16CompareOperationInput::<AB>::new(
                b_comp_limb.into(),
                c_comp_limb.into(),
                cols.u16_compare_operation,
                is_real.clone(),
            ),
        );
    }
}

#[derive(Clone, InputExpr, InputParams)]
pub struct LtOperationUnsignedInput<AB: SP1AirBuilder> {
    pub b: Word<AB::Expr>,
    pub c: Word<AB::Expr>,
    pub cols: LtOperationUnsigned<AB::Var>,
    pub is_real: AB::Expr,
}

impl<AB> SP1Operation<AB> for LtOperationUnsigned<AB::F>
where
    AB: SP1AirBuilder + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>,
{
    type Input = LtOperationUnsignedInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval_lt_unsigned(builder, input.b, input.c, input.cols, input.is_real);
    }
}

#[derive(Clone, InputExpr, InputParams)]
pub struct LtOperationSignedInput<AB: SP1AirBuilder> {
    pub b: Word<AB::Expr>,
    pub c: Word<AB::Expr>,
    pub cols: LtOperationSigned<AB::Var>,
    pub is_signed: AB::Expr,
    pub is_real: AB::Expr,
}

impl<AB> SP1Operation<AB> for LtOperationSigned<AB::F>
where
    AB: SP1AirBuilder
        + SP1OperationBuilder<U16CompareOperation<<AB as AirBuilder>::F>>
        + SP1OperationBuilder<U16MSBOperation<<AB as AirBuilder>::F>>
        + SP1OperationBuilder<LtOperationUnsigned<<AB as AirBuilder>::F>>,
{
    type Input = LtOperationSignedInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval_lt_signed(builder, input.b, input.c, input.cols, input.is_signed, input.is_real);
    }
}
