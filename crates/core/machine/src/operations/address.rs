use serde::{Deserialize, Serialize};
use slop_air::AirBuilder;
use slop_algebra::{AbstractField, Field, PrimeField32};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};

use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_hypercube::{air::SP1AirBuilder, Word};
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::air::{HostWitnessBuilder, SP1Operation, SP1OperationBuilder, WitnessBuilder};

use super::{AddrAddOperation, AddrAddOperationInput};

/// A set of columns needed to validate the address and return the aligned address.
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
pub struct AddressOperation<T> {
    /// Instance of `AddOperation` for addr.
    pub addr_operation: AddrAddOperation<T>,

    /// This is used to check if the top two limbs of the address is not both zero.
    pub top_two_limb_inv: T,
}

impl<F: PrimeField32> AddressOperation<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecord, b: u64, c: u64) -> u64 {
        let memory_addr = b.wrapping_add(c);
        assert!(memory_addr >> 48 == 0);
        let mut wb = HostWitnessBuilder::<F, _>::new(record);
        Self::witgen(&mut wb, self, b, c)
    }
}

// Witgen lives in an unconstrained `impl<T>` (see `AddrAddOperation::witgen`): the
// column type is the builder's `Field`, a wire id under the recording backend.
impl<T> AddressOperation<T> {
    /// Backend-agnostic witness generation: derives the aligned u48 memory address
    /// `b + c`, fills `addr_operation` (composing [`AddrAddOperation::witgen`]),
    /// computes `top_two_limb_inv`, and emits the alignment bit-range check. The
    /// witgen dual of [`Self::eval`].
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut AddressOperation<WB::Field>,
        b: WB::Nat,
        c: WB::Nat,
    ) -> WB::Nat {
        let memory_addr = wb.wrapping_add(b, c);
        // u48 limbs.
        AddrAddOperation::<WB::Field>::witgen(wb, &mut cols.addr_operation, b, c);
        let limb1 = wb.bits(memory_addr, 16, 16);
        let limb2 = wb.bits(memory_addr, 32, 16);
        let limb1_f = wb.nat_to_field(limb1);
        let limb2_f = wb.nat_to_field(limb2);
        let sum_top_two_limb = wb.field_add(limb1_f, limb2_f);
        cols.top_two_limb_inv = wb.field_inverse(sum_top_two_limb);
        // `addr_limbs[0] / 8` == bits 3..16 of the address.
        let limb0_div8 = wb.bits(memory_addr, 3, 13);
        wb.add_bit_range_check(limb0_div8, 13);
        memory_addr
    }
}

impl<F: Field> AddressOperation<F> {
    /// Given `op_b` and `op_c` in a memory opcode, derive the memory address.
    /// The memory address is constrained to be `>= 2^16` and less than 2^48.
    /// Both `is_real` and offset bits are constrained to be boolean and correct.
    /// The returned value is the aligned memory address used for memory access.
    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB>(
        builder: &mut AB,
        b: Word<AB::Expr>,
        c: Word<AB::Expr>,
        offset_bit0: AB::Expr,
        offset_bit1: AB::Expr,
        offset_bit2: AB::Expr,
        is_real: AB::Expr,
        cols: AddressOperation<AB::Var>,
    ) -> [AB::Expr; 3]
    where
        AB: SP1AirBuilder + SP1OperationBuilder<AddrAddOperation<<AB as AirBuilder>::F>>,
    {
        // Check that `is_real` and offset bits are boolean.
        builder.assert_bool(is_real.clone());
        builder.assert_bool(offset_bit0.clone());
        builder.assert_bool(offset_bit1.clone());
        builder.assert_bool(offset_bit2.clone());

        // `addr` is computed as `op_b + op_c`, and is range checked to be three u16 limbs.
        <AddrAddOperation<AB::F> as SP1Operation<AB>>::eval(
            builder,
            AddrAddOperationInput::new(b, c, cols.addr_operation, is_real.clone()),
        );
        let addr = cols.addr_operation.value;

        let sum_top_two_limb = addr[1] + addr[2];

        // Check that `addr >= 2^16`, so it doesn't touch registers.
        // This implements a stack guard of size 2^16 bytes = 64KB.
        // If `is_real = 1`, then `addr[1] + addr[2] != 0`, so `addr >= 2^16`.
        builder.assert_eq(cols.top_two_limb_inv * sum_top_two_limb.clone(), is_real.clone());

        // Check `0 <= (addr[0] - 4 * bit2 - 2 * bit1 - bit0) / 8 < 2^13`.
        // This shows `addr[0] - 4 * bit2 - 2 * bit1 - bit0` is a multiple of `8` within `u16`.
        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (addr[0]
                - AB::Expr::from_canonical_u32(4) * offset_bit2.clone()
                - AB::Expr::from_canonical_u32(2) * offset_bit1.clone()
                - offset_bit0.clone())
                * AB::F::from_canonical_u32(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            is_real.clone(),
        );

        [
            addr[0].into()
                - AB::Expr::from_canonical_u32(4) * offset_bit2
                - AB::Expr::from_canonical_u32(2) * offset_bit1
                - offset_bit0,
            addr[1].into(),
            addr[2].into(),
        ]
    }
}

#[derive(Debug, Clone, InputExpr, InputParams)]
pub struct AddressOperationInput<AB: SP1AirBuilder> {
    pub b: Word<AB::Expr>,
    pub c: Word<AB::Expr>,
    pub offset_bit0: AB::Expr,
    pub offset_bit1: AB::Expr,
    pub offset_bit2: AB::Expr,
    pub is_real: AB::Expr,
    pub cols: AddressOperation<AB::Var>,
}

impl<AB> SP1Operation<AB> for AddressOperation<AB::F>
where
    AB: SP1AirBuilder + SP1OperationBuilder<AddrAddOperation<<AB as AirBuilder>::F>>,
{
    type Input = AddressOperationInput<AB>;
    type Output = [AB::Expr; 3];

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(
            builder,
            input.b,
            input.c,
            input.offset_bit0,
            input.offset_bit1,
            input.offset_bit2,
            input.is_real,
            input.cols,
        )
    }
}
