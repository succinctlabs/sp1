use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_uni_stark::{
    ProverConstraintFolder, StarkConfig, SymbolicAirBuilder, VerifierConstraintFolder,
};

use super::bool::Bool;
use super::interaction::AirInteraction;
use super::word::Word;
use crate::cpu::columns::instruction::InstructionCols;
use crate::cpu::columns::opcode::OpcodeSelectorCols;
use crate::lookup::InteractionKind;
use crate::{bytes::ByteOpcode, memory::MemoryCols};
use p3_field::{AbstractField, Field};
use p3_uni_stark::check_constraints::DebugConstraintBuilder;
use std::iter::once;

/// A Builder with the ability to encode the existance of interactions with other AIRs by sending
/// and receiving messages.
pub trait MessageBuilder<M> {
    fn send(&mut self, message: M);

    fn receive(&mut self, message: M);
}

impl<AB: EmptyMessageBuilder, M> MessageBuilder<M> for AB {
    fn send(&mut self, _message: M) {}

    fn receive(&mut self, _message: M) {}
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyMessageBuilder: AirBuilder {}

/// A trait which contains basic methods for building an AIR.
pub trait BaseAirBuilder: AirBuilder + MessageBuilder<AirInteraction<Self::Expr>> {
    /// Returns a sub-builder whose constraints are enforced only when condition is one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when(Self::Expr::from(Self::F::one()) - condition.into())
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<
        I1: Into<Self::Expr>,
        I2: Into<Self::Expr>,
        I1I: IntoIterator<Item = I1> + Copy,
        I2I: IntoIterator<Item = I2> + Copy,
    >(
        &mut self,
        left: I1I,
        right: I2I,
    ) {
        debug_assert_eq!(left.into_iter().count(), right.into_iter().count());
        for (left, right) in left.into_iter().zip(right) {
            self.assert_eq(left, right);
        }
    }
}

/// A trait which contains methods related to boolean methods in an AIR.
pub trait BoolAirBuilder: BaseAirBuilder {
    fn assert_is_bool<I: Into<Self::Expr>>(&mut self, value: Bool<I>) {
        self.assert_bool(value.0);
    }
}

/// A trait which contains methods for byte interactions in an AIR.
pub trait ByteAirBuilder: BaseAirBuilder {
    /// Sends a byte operation to be processed.
    fn send_byte<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Ea,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.send_byte_pair(opcode, a, Self::Expr::zero(), b, c, multiplicity)
    }

    /// Sends a byte operation with two outputs to be processed.
    fn send_byte_pair<EOp, Ea1, Ea2, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a1: Ea1,
        a2: Ea2,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea1: Into<Self::Expr>,
        Ea2: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.send(AirInteraction::new(
            vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }

    /// Receives a byte operation to be processed.
    fn receive_byte<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Ea,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.receive_byte_pair(opcode, a, Self::Expr::zero(), b, c, multiplicity)
    }

    /// Receives a byte operation with two outputs to be processed.
    fn receive_byte_pair<EOp, Ea1, Ea2, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a1: Ea1,
        a2: Ea2,
        b: Eb,
        c: Ec,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea1: Into<Self::Expr>,
        Ea2: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.receive(AirInteraction::new(
            vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }
}

/// A trait which contains methods for field interactions in an AIR.
pub trait FieldAirBuilder: BaseAirBuilder {
    /// Sends a field operation to be processed.
    fn send_field_op<Ea, Eb, Ec, EMult>(&mut self, a: Ea, b: Eb, c: Ec, multiplicity: EMult)
    where
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.send(AirInteraction::new(
            vec![a.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Field,
        ));
    }

    /// Receives a field operation to be processed.
    fn receive_field_op<Ea, Eb, Ec, EMult>(&mut self, a: Ea, b: Eb, c: Ec, multiplicity: EMult)
    where
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        self.receive(AirInteraction::new(
            vec![a.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Field,
        ));
    }
}

/// A trait which contains methods related to words in an AIR.
pub trait WordAirBuilder: ByteAirBuilder {
    /// Asserts that the two words are equal.
    fn assert_word_eq<I: Into<Self::Expr>>(&mut self, left: Word<I>, right: Word<I>) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8<EWord: Into<Self::Expr> + Copy, EMult: Into<Self::Expr> + Clone>(
        &mut self,
        input: &[EWord],
        mult: EMult,
    ) {
        let mut index = 0;
        while index + 1 < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index],
                input[index + 1],
                mult.clone(),
            );
            index += 2;
        }
        if index < input.len() {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index],
                Self::Expr::zero(),
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16<EWord: Into<Self::Expr> + Copy, EMult: Into<Self::Expr> + Clone>(
        &mut self,
        input: &[EWord],
        mult: EMult,
    ) {
        input.iter().for_each(|limb| {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                *limb,
                Self::Expr::zero(),
                Self::Expr::zero(),
                mult.clone(),
            );
        });
    }
}

/// A trait which contains methods related to ALU interactions in an AIR.
pub trait AluAirBuilder: BaseAirBuilder {
    /// Sends an ALU operation to be processed.
    fn send_alu<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Word<Ea>,
        b: Word<Eb>,
        c: Word<Ec>,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Alu,
        ));
    }

    /// Receives an ALU operation to be processed.
    fn receive_alu<EOp, Ea, Eb, Ec, EMult>(
        &mut self,
        opcode: EOp,
        a: Word<Ea>,
        b: Word<Eb>,
        c: Word<Ec>,
        multiplicity: EMult,
    ) where
        EOp: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Alu,
        ));
    }
}

/// A trait which contains methods related to memory interactions in an AIR.
pub trait MemoryAirBuilder: BaseAirBuilder {
    /// Constraints a memory read or write.
    fn constraint_memory_access<EClk, ESegment, Ea, Eb, EVerify, M>(
        &mut self,
        segment: ESegment,
        clk: EClk,
        addr: Ea,
        memory_access: &M,
        verify_memory_access: EVerify,
    ) where
        ESegment: Into<Self::Expr>,
        EClk: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr> + Clone,
        EVerify: Into<Self::Expr>,
        M: MemoryCols<Eb>,
    {
        let verify_memory_access_expr: Self::Expr = verify_memory_access.into();
        self.assert_bool(verify_memory_access_expr.clone());

        let access = memory_access.access();

        //// Check that this memory access occurs after the previous one.
        // First check if we need to compare between the segment or the clk.
        let use_clk_comparison_expr: Self::Expr = access.use_clk_comparison.clone().into();
        let current_segment_expr: Self::Expr = segment.into();
        let prev_segment_expr: Self::Expr = access.prev_segment.clone().into();
        let current_clk_expr: Self::Expr = clk.into();
        let prev_clk_expr: Self::Expr = access.prev_clk.clone().into();

        self.when(verify_memory_access_expr.clone())
            .assert_bool(use_clk_comparison_expr.clone());
        self.when(verify_memory_access_expr.clone())
            .when(use_clk_comparison_expr.clone())
            .assert_eq(current_segment_expr.clone(), prev_segment_expr.clone());

        // Verify the previous and current time value that should be used for comparison.
        let one = Self::Expr::one();
        let calculated_prev_time_value = use_clk_comparison_expr.clone() * prev_clk_expr.clone()
            + (one.clone() - use_clk_comparison_expr.clone()) * prev_segment_expr.clone();
        let calculated_current_time_value = use_clk_comparison_expr.clone()
            * current_clk_expr.clone()
            + (one.clone() - use_clk_comparison_expr.clone()) * current_segment_expr.clone();

        let prev_time_value_expr: Self::Expr = access.prev_time_value.clone().into();
        let current_time_value_expr: Self::Expr = access.current_time_value.clone().into();
        self.when(verify_memory_access_expr.clone())
            .assert_eq(prev_time_value_expr.clone(), calculated_prev_time_value);

        self.when(verify_memory_access_expr.clone()).assert_eq(
            current_time_value_expr.clone(),
            calculated_current_time_value,
        );

        // Do the actual comparison via a lookup to the field op table.
        self.send_field_op(
            one,
            prev_time_value_expr,
            current_time_value_expr,
            verify_memory_access_expr.clone(),
        );

        //// Check the previous and current memory access via a lookup to the memory table.
        let addr_expr = addr.into();
        let prev_values = once(prev_segment_expr)
            .chain(once(prev_clk_expr))
            .chain(once(addr_expr.clone()))
            .chain(memory_access.prev_value().clone().map(Into::into))
            .collect();
        let current_values = once(current_segment_expr)
            .chain(once(current_clk_expr))
            .chain(once(addr_expr.clone()))
            .chain(memory_access.value().clone().map(Into::into))
            .collect();

        // The previous values get sent with multiplicity * 1, for "read".
        self.send(AirInteraction::new(
            prev_values,
            verify_memory_access_expr.clone(),
            InteractionKind::Memory,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.receive(AirInteraction::new(
            current_values,
            verify_memory_access_expr.clone(),
            InteractionKind::Memory,
        ));
    }

    /// Constraints a memory read or write to a slice of `MemoryAccessCols`.
    fn constraint_memory_access_slice<ESegment, Ea, Eb, EVerify, M>(
        &mut self,
        segment: ESegment,
        clk: Self::Expr,
        initial_addr: Ea,
        memory_access_slice: &[M],
        verify_memory_access: EVerify,
    ) where
        ESegment: Into<Self::Expr> + std::marker::Copy,
        Ea: Into<Self::Expr> + std::marker::Copy,
        Eb: Into<Self::Expr> + std::marker::Copy,
        EVerify: Into<Self::Expr> + std::marker::Copy,
        M: MemoryCols<Eb>,
    {
        for i in 0..memory_access_slice.len() {
            self.constraint_memory_access(
                segment,
                clk.clone(),
                initial_addr.into() + Self::Expr::from_canonical_usize(i * 4),
                &memory_access_slice[i],
                verify_memory_access,
            );
        }
    }
}

/// A trait which contains methods related to program interactions in an AIR.
pub trait ProgramAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectorCols<ESel>,
        multiplicity: EMult,
    ) where
        EPc: Into<Self::Expr>,
        EInst: Into<Self::Expr> + Copy,
        ESel: Into<Self::Expr> + Copy,
        EMult: Into<Self::Expr>,
    {
        let values = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }

    /// Receives an instruction.
    fn receive_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectorCols<ESel>,
        multiplicity: EMult,
    ) where
        EPc: Into<Self::Expr>,
        EInst: Into<Self::Expr> + Copy,
        ESel: Into<Self::Expr> + Copy,
        EMult: Into<Self::Expr>,
    {
        let values: Vec<<Self as AirBuilder>::Expr> = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }
}

/// A trait which contains all helper methods for building an AIR.
pub trait CurtaAirBuilder:
    BaseAirBuilder
    + BoolAirBuilder
    + ByteAirBuilder
    + WordAirBuilder
    + AluAirBuilder
    + MemoryAirBuilder
    + ProgramAirBuilder
{
}

impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> BaseAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> BoolAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> ByteAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> FieldAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> WordAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> AluAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> MemoryAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> ProgramAirBuilder for AB {}
impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> CurtaAirBuilder for AB {}

impl<'a, AB: AirBuilder + MessageBuilder<M>, M> MessageBuilder<M> for FilteredAirBuilder<'a, AB> {
    fn send(&mut self, message: M) {
        self.inner.send(message);
    }

    fn receive(&mut self, message: M) {
        self.inner.receive(message);
    }
}

impl<'a, SC: StarkConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}

impl<'a, Challenge: Field> EmptyMessageBuilder for VerifierConstraintFolder<'a, Challenge> {}

impl<F: Field> EmptyMessageBuilder for SymbolicAirBuilder<F> {}

impl<'a, F: Field> EmptyMessageBuilder for DebugConstraintBuilder<'a, F> {}
