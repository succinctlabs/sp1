mod bool;
mod word;
use crate::bytes::ByteOpcode;

use std::iter::once;

pub use bool::Bool;
use p3_air::{AirBuilder, FilteredAirBuilder, MessageBuilder};
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
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when(Self::Expr::from(Self::F::one()) - condition.into())
    }

    fn assert_word_eq<I: Into<Self::Expr>>(&mut self, left: Word<I>, right: Word<I>) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    fn range_check_word<EWord: Into<Self::Expr> + Copy, EMult: Into<Self::Expr> + Clone>(
        &mut self,
        input: Word<EWord>,
        mult: EMult,
    ) {
        for byte_pair in input.0.chunks_exact(2) {
            self.send_byte_lookup(
                Self::Expr::from_canonical_u8(ByteOpcode::Range as u8),
                Self::Expr::zero(),
                byte_pair[0],
                byte_pair[1],
                mult.clone(),
            );
        }
    }

    fn assert_is_bool<I: Into<Self::Expr>>(&mut self, value: Bool<I>) {
        self.assert_bool(value.0);
    }

    fn zero_word() -> Word<Self::Expr> {
        Word([
            Self::Expr::zero(),
            Self::Expr::zero(),
            Self::Expr::zero(),
            Self::Expr::zero(),
        ])
    }

    fn extend_expr_to_word<I: Into<Self::Expr>>(expr: I) -> Word<Self::Expr> {
        Word([
            expr.into(),
            Self::Expr::zero(),
            Self::Expr::zero(),
            Self::Expr::zero(),
        ])
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
            vec![
                opcode.into(),
                a.into(),
                Self::F::zero().into(),
                b.into(),
                c.into(),
            ],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }

    fn send_byte_loookup_pair<EOp, Ea1, Ea2, Eb, Ec, EMult>(
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
            vec![
                opcode.into(),
                a.into(),
                Self::F::zero().into(),
                b.into(),
                c.into(),
            ],
            multiplicity.into(),
            InteractionKind::Byte,
        ));
    }

    fn receive_byte_lookup_pair<EOp, Ea1, Ea2, Eb, Ec, EMult>(
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
