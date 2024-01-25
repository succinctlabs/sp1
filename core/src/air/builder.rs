use p3_air::{AirBuilder, FilteredAirBuilder, MessageBuilder};

use super::bool::Bool;
use super::interaction::AirInteraction;
use super::word::Word;
use crate::bytes::ByteOpcode;
use crate::cpu::cols::cpu_cols::MemoryAccessCols;
use crate::cpu::cols::instruction_cols::InstructionCols;
use crate::cpu::cols::opcode_cols::OpcodeSelectors;
use crate::lookup::InteractionKind;
use p3_field::AbstractField;
use std::iter::once;

/// A trait which contains basic methods for building an AIR.
pub trait BaseAirBuilder: AirBuilder + MessageBuilder<AirInteraction<Self::Expr>> {
    /// Returns a sub-builder whose constraints are enforced only when condition is one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when(Self::Expr::from(Self::F::one()) - condition.into())
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

    /// Range checks a word.
    fn range_check_word<EWord: Into<Self::Expr> + Copy, EMult: Into<Self::Expr> + Clone>(
        &mut self,
        input: Word<EWord>,
        mult: EMult,
    ) {
        for byte_pair in input.0.chunks_exact(2) {
            self.send_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::Range as u8),
                Self::Expr::zero(),
                byte_pair[0],
                byte_pair[1],
                mult.clone(),
            );
        }
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
    fn constraint_memory_access<EClk, ESegment, Ea, Eb, EVerify>(
        &mut self,
        segment: ESegment,
        clk: EClk,
        addr: Ea,
        memory_access: MemoryAccessCols<Eb>,
        verify_memory_access: EVerify,
    ) where
        ESegment: Into<Self::Expr>,
        EClk: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        EVerify: Into<Self::Expr>,
    {
        let verify_memory_access_expr: Self::Expr = verify_memory_access.into();
        self.assert_bool(verify_memory_access_expr.clone());

        //// Check that this memory access occurs after the previous one.
        // First check if we need to compare between the segment or the clk.
        let use_clk_comparison_expr: Self::Expr = memory_access.use_clk_comparison.into();
        let current_segment_expr: Self::Expr = segment.into();
        let prev_segment_expr: Self::Expr = memory_access.prev_segment.into();
        let current_clk_expr: Self::Expr = clk.into();
        let prev_clk_expr: Self::Expr = memory_access.prev_clk.into();

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

        let prev_time_value_expr: Self::Expr = memory_access.prev_time_value.into();
        let current_time_value_expr: Self::Expr = memory_access.current_time_value.into();
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
            .chain(memory_access.prev_value.map(Into::into))
            .collect();
        let current_values = once(current_segment_expr)
            .chain(once(current_clk_expr))
            .chain(once(addr_expr.clone()))
            .chain(memory_access.value.map(Into::into))
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
}

/// A trait which contains methods related to program interactions in an AIR.
pub trait ProgramAirBuilder: BaseAirBuilder {
    /// Sends an instruction.
    fn send_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectors<ESel>,
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
        selectors: OpcodeSelectors<ESel>,
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
