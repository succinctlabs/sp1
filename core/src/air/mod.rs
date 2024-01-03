mod bool;
mod word;

use std::iter::once;

pub use bool::Bool;
use p3_air::{AirBuilder, MessageBuilder};
use p3_field::AbstractField;
pub use word::Word;

use crate::cpu::air::MemoryAccessCols;
use crate::cpu::instruction_cols::InstructionCols;
use crate::cpu::opcode_cols::OpcodeSelectors;
use crate::lookup::InteractionKind;

pub fn reduce<AB: AirBuilder>(input: Word<AB::Var>) -> AB::Expr {
    let base = [1, 1 << 8, 1 << 16, 1 << 24].map(AB::Expr::from_canonical_u32);

    input
        .0
        .into_iter()
        .enumerate()
        .map(|(i, x)| base[i].clone() * x)
        .sum()
}

pub struct AirInteraction<E> {
    pub values: Vec<E>,
    pub multiplicity: E,
    pub kind: InteractionKind,
}

/// An extension of the `AirBuilder` trait with additional methods for Curta types.
///
/// All `AirBuilder` implementations automatically implement this trait.
pub trait CurtaAirBuilder: AirBuilder + MessageBuilder<AirInteraction<Self::Expr>> {
    fn assert_word_eq<I: Into<Self::Expr>>(&mut self, left: Word<I>, right: Word<I>) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    fn assert_is_bool<I: Into<Self::Expr>>(&mut self, value: Bool<I>) {
        self.assert_bool(value.0);
    }

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

    fn constraint_memory_access<EClk, ESegment, Ea, Eb, EMult>(
        &mut self,
        segment: ESegment,
        clk: EClk,
        addr: Ea,
        memory_access: MemoryAccessCols<Eb>,
        multiplicity: EMult,
    ) where
        ESegment: Into<Self::Expr>,
        EClk: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        // TODO:
        // (segment == prev_segment && clk > prev_timestamp) OR segment > prev_segment
        let addr_expr = addr.into();
        let prev_values = once(memory_access.segment.into())
            .chain(once(memory_access.timestamp.into()))
            .chain(once(addr_expr.clone()))
            .chain(memory_access.prev_value.map(Into::into))
            .collect();
        let current_values = once(segment.into())
            .chain(once(clk.into()))
            .chain(once(addr_expr.clone()))
            .chain(memory_access.value.map(Into::into))
            .collect();

        let multiplicity_expr = multiplicity.into();
        // The previous values get sent with multiplicity * 1, for "read".
        self.send(AirInteraction::new(
            prev_values,
            multiplicity_expr.clone(),
            InteractionKind::Memory,
        ));

        // The current values get "received", i.e. multiplicity = -1
        self.receive(AirInteraction::new(
            current_values,
            multiplicity_expr.clone(),
            InteractionKind::Memory,
        ));
    }

    fn send_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectors<ESel>,
        multiplicity: EMult,
    ) where
        EPc: Into<Self::Expr>,
        EInst: Into<Self::Expr>,
        ESel: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.op_a.into_iter().map(Into::into))
            .chain(instruction.op_b.into_iter().map(Into::into))
            .chain(instruction.op_c.into_iter().map(Into::into))
            .chain(once(selectors.imm_b.into()))
            .chain(once(selectors.imm_c.into()))
            .chain(once(selectors.add_op.into()))
            .chain(once(selectors.sub_op.into()))
            .chain(once(selectors.mul_op.into()))
            .chain(once(selectors.div_op.into()))
            .chain(once(selectors.shift_op.into()))
            .chain(once(selectors.bitwise_op.into()))
            .chain(once(selectors.lt_op.into()))
            .chain(once(selectors.is_load.into()))
            .chain(once(selectors.is_store.into()))
            .chain(once(selectors.is_word.into()))
            .chain(once(selectors.is_half.into()))
            .chain(once(selectors.is_byte.into()))
            .chain(once(selectors.is_signed.into()))
            .chain(once(selectors.jalr.into()))
            .chain(once(selectors.jal.into()))
            .chain(once(selectors.auipc.into()))
            .chain(once(selectors.branch_op.into()))
            .chain(once(selectors.noop.into()))
            .chain(once(selectors.reg_0_write.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }

    fn receive_program<EPc, EInst, ESel, EMult>(
        &mut self,
        pc: EPc,
        instruction: InstructionCols<EInst>,
        selectors: OpcodeSelectors<ESel>,
        multiplicity: EMult,
    ) where
        EPc: Into<Self::Expr>,
        EInst: Into<Self::Expr>,
        ESel: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values: Vec<<Self as AirBuilder>::Expr> = once(pc.into())
            .chain(once(instruction.opcode.into()))
            .chain(instruction.op_a.into_iter().map(Into::into))
            .chain(instruction.op_b.into_iter().map(Into::into))
            .chain(instruction.op_c.into_iter().map(Into::into))
            .chain(once(selectors.imm_b.into()))
            .chain(once(selectors.imm_c.into()))
            .chain(once(selectors.add_op.into()))
            .chain(once(selectors.sub_op.into()))
            .chain(once(selectors.mul_op.into()))
            .chain(once(selectors.div_op.into()))
            .chain(once(selectors.shift_op.into()))
            .chain(once(selectors.bitwise_op.into()))
            .chain(once(selectors.lt_op.into()))
            .chain(once(selectors.is_load.into()))
            .chain(once(selectors.is_store.into()))
            .chain(once(selectors.is_word.into()))
            .chain(once(selectors.is_half.into()))
            .chain(once(selectors.is_byte.into()))
            .chain(once(selectors.is_signed.into()))
            .chain(once(selectors.jalr.into()))
            .chain(once(selectors.jal.into()))
            .chain(once(selectors.auipc.into()))
            .chain(once(selectors.branch_op.into()))
            .chain(once(selectors.noop.into()))
            .chain(once(selectors.reg_0_write.into()))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Program,
        ));
    }

    fn send_byte_lookup<EOp, Ea, Eb, Ec, EMult>(
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
        self.send(AirInteraction::new(
            vec![opcode.into(), a.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }

    fn receive_byte_lookup<EOp, Ea, Eb, Ec, EMult>(
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
        self.receive(AirInteraction::new(
            vec![opcode.into(), a.into(), b.into(), c.into()],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }
}

impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> CurtaAirBuilder for AB {}

impl<E> AirInteraction<E> {
    pub fn new(values: Vec<E>, multiplicity: E, kind: InteractionKind) -> Self {
        Self {
            values,
            multiplicity,
            kind,
        }
    }
}
