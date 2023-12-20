mod bool;
mod word;

use std::iter::once;

pub use bool::Bool;
use p3_air::{AirBuilder, MessageBuilder};
use p3_field::AbstractField;
pub use word::Word;

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

    fn send_register<EClk, EReg, EVal, ERead, EMult>(
        &mut self,
        clk: EClk,
        register: EReg,
        value: Word<EVal>,
        is_read: ERead,
        multiplicity: EMult,
    ) where
        EClk: Into<Self::Expr>,
        EReg: Into<Self::Expr>,
        EVal: Into<Self::Expr>,
        ERead: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let register_aligned = register.into() * Self::Expr::from_canonical_u32(4);
        let values = once(clk.into())
            .chain(once(register_aligned.into()))
            .chain(
                vec![
                    Self::F::from_canonical_u32(0xFF),
                    Self::F::from_canonical_u32(0xFF),
                    Self::F::from_canonical_u32(0xFF),
                ]
                .into_iter()
                .map(Into::into),
            )
            .chain(value.map(Into::into))
            .chain(once(is_read.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Memory,
        ));
    }

    fn send_memory<EClk, Ea, Eb, Ec, EMult>(
        &mut self,
        clk: EClk,
        addr: Word<Ea>,
        value: Word<Eb>,
        is_read: Ec,
        multiplicity: EMult,
    ) where
        EClk: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(clk.into())
            .chain(addr.map(Into::into))
            .chain(value.map(Into::into))
            .chain(once(is_read.into()))
            .collect();

        self.send(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Memory,
        ));
    }

    fn recieve_memory<EClk, Ea, Eb, Ec, EMult>(
        &mut self,
        clk: EClk,
        addr: Word<Ea>,
        value: Word<Eb>,
        is_read: Ec,
        multiplicity: EMult,
    ) where
        EClk: Into<Self::Expr>,
        Ea: Into<Self::Expr>,
        Eb: Into<Self::Expr>,
        Ec: Into<Self::Expr>,
        EMult: Into<Self::Expr>,
    {
        let values = once(clk.into())
            .chain(addr.map(Into::into))
            .chain(value.map(Into::into))
            .chain(once(is_read.into()))
            .collect();

        self.receive(AirInteraction::new(
            values,
            multiplicity.into(),
            InteractionKind::Memory,
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
