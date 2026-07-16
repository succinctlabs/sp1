use crate::air::{HostWitnessBuilder, WitnessBuilder, WordAirBuilder};
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, Field};
use sp1_core_executor::{events::ByteRecord, ByteOpcode};
use sp1_derive::{AlignedBorrow, InputExpr, InputParams, IntoShape, SP1OperationBuilder};
use sp1_hypercube::air::SP1AirBuilder;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::air::SP1Operation;

/// A set of columns to describe the state of the CPU.
/// The state is composed of the shard, clock, and the program counter.
/// The clock is split into 24 bits, 8 bits, 16 bits limbs.
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
pub struct CPUState<T> {
    pub clk_high: T,
    pub clk_16_24: T,
    pub clk_0_16: T,
    pub pc: [T; 3],
}

impl<T: Copy> CPUState<T> {
    pub fn clk_high<AB>(&self) -> AB::Expr
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        self.clk_high.into()
    }
    pub fn clk_low<AB>(&self) -> AB::Expr
    where
        AB: SP1AirBuilder<Var = T>,
        T: Into<AB::Expr>,
    {
        self.clk_0_16.into() + self.clk_16_24.into() * AB::Expr::from_canonical_u32(1 << 16)
    }
}

// Witgen lives in an unconstrained `impl<T>` (the column type is the builder's
// `Field`, a wire id under the recording backend). See `AddrAddOperation::witgen`.
impl<T> CPUState<T> {
    /// Backend-agnostic witness generation: the clk (high/8-bit/16-bit) and pc
    /// (three u16 limbs) column decomposition, plus the clk range checks. Witgen
    /// dual of [`Self::eval`].
    pub fn witgen<WB: WitnessBuilder>(
        wb: &mut WB,
        cols: &mut CPUState<WB::Field>,
        clk: WB::Nat,
        pc: WB::Nat,
    ) {
        let clk_high = wb.bits(clk, 24, 32);
        cols.clk_high = wb.nat_to_field(clk_high);
        let clk_16_24 = wb.bits(clk, 16, 8);
        cols.clk_16_24 = wb.nat_to_field(clk_16_24);
        let clk_0_16 = wb.bits(clk, 0, 16);
        cols.clk_0_16 = wb.nat_to_field(clk_0_16);
        let pc0 = wb.bits(pc, 0, 16);
        let pc1 = wb.bits(pc, 16, 16);
        let pc2 = wb.bits(pc, 32, 16);
        cols.pc[0] = wb.nat_to_field(pc0);
        cols.pc[1] = wb.nat_to_field(pc1);
        cols.pc[2] = wb.nat_to_field(pc2);

        // 0 <= (clk_0_16 - 1) / 8 < 2^13 shows clk == 1 (mod 8) and clk_0_16 is 16 bits.
        let one = wb.const_nat(1);
        let cm1 = wb.wrapping_sub(clk_0_16, one);
        let cm1_div8 = wb.bits(cm1, 3, 13);
        wb.add_bit_range_check(cm1_div8, 13);
        let zero = wb.const_nat(0);
        wb.add_u8_range_check(clk_16_24, zero);
    }
}

impl<F: Field> CPUState<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(&mut self, blu_events: &mut impl ByteRecord, clk: u64, pc: u64) {
        let mut wb = HostWitnessBuilder::<F, _>::new(blu_events);
        Self::witgen(&mut wb, self, clk, pc);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval<AB: SP1AirBuilder>(
        builder: &mut AB,
        cols: CPUState<AB::Var>,
        next_pc: [AB::Expr; 3],
        clk_increment: AB::Expr,
        is_real: AB::Expr,
    ) {
        let clk_high = cols.clk_high::<AB>();
        let clk_low = cols.clk_low::<AB>();
        builder.assert_bool(is_real.clone());
        builder.receive_state(clk_high.clone(), clk_low.clone(), cols.pc, is_real.clone());
        builder.send_state(
            clk_high.clone(),
            clk_low.clone() + clk_increment,
            next_pc,
            is_real.clone(),
        );

        builder.send_byte(
            AB::Expr::from_canonical_u32(ByteOpcode::Range as u32),
            (cols.clk_0_16 - AB::Expr::one()) * AB::F::from_canonical_u8(8).inverse(),
            AB::Expr::from_canonical_u32(13),
            AB::Expr::zero(),
            is_real.clone(),
        );

        builder.slice_range_check_u8(&[cols.clk_16_24.into(), AB::Expr::zero()], is_real.clone());
    }
}

#[derive(Clone, InputParams, InputExpr)]
pub struct CPUStateInput<AB: SP1AirBuilder> {
    pub cols: CPUState<AB::Var>,
    pub next_pc: [AB::Expr; 3],
    pub clk_increment: AB::Expr,
    pub is_real: AB::Expr,
}

impl<AB: SP1AirBuilder> SP1Operation<AB> for CPUState<AB::F> {
    type Input = CPUStateInput<AB>;
    type Output = ();

    fn lower(builder: &mut AB, input: Self::Input) -> Self::Output {
        Self::eval(builder, input.cols, input.next_pc, input.clk_increment, input.is_real);
    }
}
