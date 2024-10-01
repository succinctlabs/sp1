use p3_air::AirBuilderWithPublicValues;
use p3_field::AbstractField;
use sp1_recursion_core::air::Block;
use sp1_stark::{
    air::{AirInteraction, BaseAirBuilder, InteractionScope, MachineAirBuilder},
    InteractionKind,
};

use crate::*;

/// A trait which contains all helper methods for building SP1 recursion machine AIRs.
pub trait SP1RecursionAirBuilder: MachineAirBuilder + RecursionAirBuilder {}

impl<AB: AirBuilderWithPublicValues + RecursionAirBuilder> SP1RecursionAirBuilder for AB {}
impl<AB: BaseAirBuilder> RecursionAirBuilder for AB {}

pub trait RecursionAirBuilder: BaseAirBuilder {
    fn send_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::zero());
        padded_value[0] = val.into();
        self.send_block(Address(addr.0.into()), Block(padded_value), mult)
    }

    fn send_block<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: Block<E>,
        mult: impl Into<Self::Expr>,
    ) {
        self.send(
            AirInteraction::new(
                once(addr.0).chain(val).map(Into::into).collect(),
                mult.into(),
                InteractionKind::Memory,
            ),
            InteractionScope::Local,
        );
    }

    fn receive_single<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: E,
        mult: impl Into<Self::Expr>,
    ) {
        let mut padded_value = core::array::from_fn(|_| Self::Expr::zero());
        padded_value[0] = val.into();
        self.receive_block(Address(addr.0.into()), Block(padded_value), mult)
    }

    fn receive_block<E: Into<Self::Expr>>(
        &mut self,
        addr: Address<E>,
        val: Block<E>,
        mult: impl Into<Self::Expr>,
    ) {
        self.receive(
            AirInteraction::new(
                once(addr.0).chain(val).map(Into::into).collect(),
                mult.into(),
                InteractionKind::Memory,
            ),
            InteractionScope::Local,
        );
    }
}

use p3_air::{AirBuilder, ExtensionBuilder, FilteredAirBuilder, PermutationAirBuilder};
use sp1_stark::air::MessageBuilder;

/// The MultiBuilder is used for the multi table.  It is used to create a virtual builder for one of
/// the sub tables in the multi table.
pub struct MultiBuilder<'a, AB: AirBuilder> {
    inner: FilteredAirBuilder<'a, AB>,

    /// These fields are used to determine whether a row is is the first or last row of the
    /// subtable, which requires hinting from the parent table.
    is_first_row: AB::Expr,
    is_last_row: AB::Expr,

    next_condition: AB::Expr,
}

impl<'a, AB: AirBuilder> MultiBuilder<'a, AB> {
    pub fn new(
        builder: &'a mut AB,
        local_condition: AB::Expr,
        is_first_row: AB::Expr,
        is_last_row: AB::Expr,
        next_condition: AB::Expr,
    ) -> Self {
        let inner = builder.when(local_condition.clone());
        Self { inner, is_first_row, is_last_row, next_condition }
    }
}

impl<'a, AB: AirBuilder> AirBuilder for MultiBuilder<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = AB::M;

    fn main(&self) -> Self::M {
        self.inner.main()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row.clone()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row.clone()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.next_condition.clone() * self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }
}

impl<'a, AB: ExtensionBuilder> ExtensionBuilder for MultiBuilder<'a, AB> {
    type EF = AB::EF;
    type VarEF = AB::VarEF;
    type ExprEF = AB::ExprEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.inner.assert_zero_ext(x.into());
    }
}

impl<'a, AB: PermutationAirBuilder> PermutationAirBuilder for MultiBuilder<'a, AB> {
    type MP = AB::MP;

    type RandomVar = AB::RandomVar;

    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }
}

impl<'a, AB: AirBuilder + MessageBuilder<M>, M> MessageBuilder<M> for MultiBuilder<'a, AB> {
    fn send(&mut self, message: M, scope: InteractionScope) {
        self.inner.send(message, scope);
    }

    fn receive(&mut self, message: M, scope: InteractionScope) {
        self.inner.receive(message, scope);
    }
}

impl<'a, AB: AirBuilder + AirBuilderWithPublicValues> AirBuilderWithPublicValues
    for MultiBuilder<'a, AB>
{
    type PublicVar = AB::PublicVar;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}
