use sp1_core_executor::events::ByteRecord;
use sp1_hypercube::{air::SP1AirBuilder, Word};
use sp1_primitives::consts::WORD_SIZE;
use struct_reflection::{StructReflection, StructReflectionHelper};

use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use crate::{
    air::{HostWitnessBuilder, SP1Operation, SP1OperationBuilder, WitnessBuilder, WordAirBuilder},
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

// Witgen in an unconstrained `impl<T>` (column type is the builder's `Field`).
impl<T> SubwOperation<T> {
    /// Backend-agnostic witgen dual of [`Self::eval`]: the two low u16 limbs of the
    /// 32-bit `a - b` into `value` (with range checks) plus the msb of the high limb.
    /// The sign-extension of the full SUBW result only affects the unused high
    /// limbs, so only the low 32 bits of `wrapping_sub(a, b)` matter here.
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut SubwOperation<WB::Field>,
        a: WB::Nat,
        b: WB::Nat,
    ) {
        let sub = wb.wrapping_sub(a, b);
        let limb0 = wb.bits(sub, 0, 16);
        cols.value[0] = wb.nat_to_field(limb0);
        wb.add_u16_range_check(limb0);
        let limb1 = wb.bits(sub, 16, 16);
        cols.value[1] = wb.nat_to_field(limb1);
        wb.add_u16_range_check(limb1);
        U16MSBOperation::<WB::Field>::witgen(wb, &mut cols.msb, limb1);
    }
}

impl<F: Field> SubwOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, a_u64: u64, b_u64: u64) {
        let mut wb = HostWitnessBuilder::<F, _>::new(record);
        Self::witgen(&mut wb, self, a_u64, b_u64);
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

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use sp1_core_executor::{events::ByteLookupEvent, ByteOpcode};
    use sp1_primitives::{consts::u64_to_u16_limbs, SP1Field};

    type F = SP1Field;

    /// `SubwOperation::witgen` (via the delegating `populate`) must reproduce the
    /// original SUBW reference: low two u16 limbs of the 32-bit `a - b`, the msb of
    /// the high limb, and the three `{Range, ., 16}` lookups.
    #[test]
    fn subw_witgen_matches_reference() {
        let cases: [(u64, u64); 8] = [
            (0, 0),
            (5, 3),
            (3, 5),
            (0, 1),
            (0xFFFF_FFFF, 1),
            (0x8000_0000, 1),
            (0x1234_5678, 0x8765_4321),
            (0xDEAD_BEEF_0000, 0x1),
        ];
        for (a, b) in cases {
            let mut cols = SubwOperation::<F>::default();
            let mut blu: HashMap<ByteLookupEvent, usize> = HashMap::new();
            cols.populate(&mut blu, a, b);

            let value =
                (std::num::Wrapping(a as i32) - std::num::Wrapping(b as i32)).0 as i64 as u64;
            let limbs = u64_to_u16_limbs(value);
            assert_eq!(cols.value[0], F::from_canonical_u16(limbs[0]), "value0 ({a:#x},{b:#x})");
            assert_eq!(cols.value[1], F::from_canonical_u16(limbs[1]), "value1 ({a:#x},{b:#x})");
            assert_eq!(
                cols.msb.msb,
                F::from_canonical_u16((limbs[1] >> 15) & 1),
                "msb ({a:#x},{b:#x})"
            );

            let mut refblu: HashMap<ByteLookupEvent, usize> = HashMap::new();
            for e in [
                ByteLookupEvent { opcode: ByteOpcode::Range, a: limbs[0], b: 16, c: 0 },
                ByteLookupEvent { opcode: ByteOpcode::Range, a: limbs[1], b: 16, c: 0 },
                ByteLookupEvent {
                    opcode: ByteOpcode::Range,
                    a: limbs[1].wrapping_mul(2),
                    b: 16,
                    c: 0,
                },
            ] {
                *refblu.entry(e).or_insert(0) += 1;
            }
            assert_eq!(blu, refblu, "byte lookups mismatch for ({a:#x},{b:#x})");
        }
    }
}
