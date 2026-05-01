use std::{
    array,
    iter::once,
    ops::{Add, Mul, Sub},
};

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_air::{AirBuilder, AirBuilderWithPublicValues, FilteredAirBuilder};
use slop_algebra::{AbstractField, Field};
use slop_uni_stark::{
    ProverConstraintFolder, StarkGenericConfig, SymbolicAirBuilder, VerifierConstraintFolder,
};
use strum::{Display, EnumIter};

use super::{interaction::AirInteraction, BinomialExtension};
use crate::{lookup::InteractionKind, septic_extension::SepticExtension, ConstraintSumcheckFolder};

/// The scope of an interaction.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    EnumIter,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
pub enum InteractionScope {
    /// Global scope.
    Global = 0,
    /// Local scope.
    Local,
}

/// A builder that can send and receive messages (or interactions) with other AIRs.
pub trait MessageBuilder<M> {
    /// Sends a message.
    fn send(&mut self, message: M, scope: InteractionScope);

    /// Receives a message.
    fn receive(&mut self, message: M, scope: InteractionScope);
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyMessageBuilder: AirBuilder {}

impl<AB: EmptyMessageBuilder, M> MessageBuilder<M> for AB {
    fn send(&mut self, _message: M, _scope: InteractionScope) {}

    fn receive(&mut self, _message: M, _scope: InteractionScope) {}
}

/// A trait which contains basic methods for building an AIR.
pub trait BaseAirBuilder: AirBuilder + MessageBuilder<AirInteraction<Self::Expr>> {
    /// Returns a sub-builder whose constraints are enforced only when `condition` is not one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<'_, Self> {
        self.when_ne(condition, Self::F::one())
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        left: impl IntoIterator<Item = I1>,
        right: impl IntoIterator<Item = I2>,
    ) {
        for (left, right) in left.into_iter().zip_eq(right) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that an iterator of expressions are all zero.
    fn assert_all_zero<I: Into<Self::Expr>>(&mut self, iter: impl IntoIterator<Item = I>) {
        iter.into_iter().for_each(|expr| self.assert_zero(expr));
    }

    /// Will return `a` if `condition` is 1, else `b`.  This assumes that `condition` is already
    /// checked to be a boolean.
    #[inline]
    fn if_else(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: impl Into<Self::Expr> + Clone,
        b: impl Into<Self::Expr> + Clone,
    ) -> Self::Expr {
        condition.clone().into() * a.into() + (Self::Expr::one() - condition.into()) * b.into()
    }

    /// Index an array of expressions using an index bitmap.  This function assumes that the
    /// `EIndex` type is a boolean and that `index_bitmap`'s entries sum to 1.
    fn index_array(
        &mut self,
        array: &[impl Into<Self::Expr> + Clone],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Self::Expr {
        let mut result = Self::Expr::zero();

        for (value, i) in array.iter().zip_eq(index_bitmap) {
            result = result.clone() + value.clone().into() * i.clone().into();
        }

        result
    }
}

/// A trait which contains methods for byte interactions in an AIR.
pub trait ByteAirBuilder: BaseAirBuilder {
    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn send_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(
            AirInteraction::new(
                vec![opcode.into(), a.into(), b.into(), c.into()],
                multiplicity.into(),
                InteractionKind::Byte,
            ),
            InteractionScope::Local,
        );
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(
            AirInteraction::new(
                vec![opcode.into(), a.into(), b.into(), c.into()],
                multiplicity.into(),
                InteractionKind::Byte,
            ),
            InteractionScope::Local,
        );
    }
}

/// A trait which contains methods related to RISC-V instruction interactions in an AIR.
pub trait InstructionAirBuilder: BaseAirBuilder {
    /// Sends the current CPU state.
    fn send_state(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        pc: [impl Into<Self::Expr>; 3],
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.send(
            AirInteraction::new(
                once(clk_high.into())
                    .chain(once(clk_low.into()))
                    .chain(pc.map(Into::into))
                    .collect::<Vec<_>>(),
                multiplicity.into(),
                InteractionKind::State,
            ),
            InteractionScope::Local,
        );
    }

    /// Receives the current CPU state.
    fn receive_state(
        &mut self,
        clk_high: impl Into<Self::Expr>,
        clk_low: impl Into<Self::Expr>,
        pc: [impl Into<Self::Expr>; 3],
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.receive(
            AirInteraction::new(
                once(clk_high.into())
                    .chain(once(clk_low.into()))
                    .chain(pc.map(Into::into))
                    .collect::<Vec<_>>(),
                multiplicity.into(),
                InteractionKind::State,
            ),
            InteractionScope::Local,
        );
    }

    /// Sends an syscall operation to be processed (with "ECALL" opcode).
    #[allow(clippy::too_many_arguments)]
    fn send_syscall(
        &mut self,
        clk_high: impl Into<Self::Expr> + Clone,
        clk_low: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        trap_code: impl Into<Self::Expr> + Clone,
        arg1: [impl Into<Self::Expr>; 3],
        arg2: [impl Into<Self::Expr>; 3],
        multiplicity: impl Into<Self::Expr>,
        scope: InteractionScope,
    ) {
        let values = once(clk_high.into())
            .chain(once(clk_low.into()))
            .chain(once(syscall_id.into()))
            .chain(cfg!(feature = "mprotect").then(|| trap_code.into()))
            .chain(arg1.map(Into::into))
            .chain(arg2.map(Into::into))
            .collect::<Vec<_>>();

        self.send(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Syscall),
            scope,
        );
    }

    /// Receives a syscall operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn receive_syscall(
        &mut self,
        clk_high: impl Into<Self::Expr> + Clone,
        clk_low: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        trap_code: impl Into<Self::Expr> + Clone,
        arg1: [Self::Expr; 3],
        arg2: [Self::Expr; 3],
        multiplicity: impl Into<Self::Expr>,
        scope: InteractionScope,
    ) {
        let values = once(clk_high.into())
            .chain(once(clk_low.into()))
            .chain(once(syscall_id.into()))
            .chain(cfg!(feature = "mprotect").then(|| trap_code.into()))
            .chain(arg1)
            .chain(arg2)
            .collect::<Vec<_>>();

        self.receive(
            AirInteraction::new(values, multiplicity.into(), InteractionKind::Syscall),
            scope,
        );
    }
}

/// A builder that can operation on extension elements.
pub trait ExtensionAirBuilder: BaseAirBuilder {
    /// Asserts that the two field extensions are equal.
    fn assert_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: BinomialExtension<I>,
        right: BinomialExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Checks if an extension element is a base element.
    fn assert_is_base_element<I: Into<Self::Expr> + Clone>(
        &mut self,
        element: BinomialExtension<I>,
    ) {
        let base_slice = element.as_base_slice();
        let degree = base_slice.len();
        base_slice[1..degree].iter().for_each(|coeff| {
            self.assert_zero(coeff.clone().into());
        });
    }

    /// Performs an if else on extension elements.
    fn if_else_ext(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: BinomialExtension<impl Into<Self::Expr> + Clone>,
        b: BinomialExtension<impl Into<Self::Expr> + Clone>,
    ) -> BinomialExtension<Self::Expr> {
        BinomialExtension(array::from_fn(|i| {
            self.if_else(condition.clone(), a.0[i].clone(), b.0[i].clone())
        }))
    }
}

/// A builder that can operation on septic extension elements.
pub trait SepticExtensionAirBuilder: BaseAirBuilder {
    /// Asserts that the two field extensions are equal.
    fn assert_septic_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: SepticExtension<I>,
        right: SepticExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }
}

/// A trait that contains the common helper methods for building `SP1 recursion` and SP1 machine
/// AIRs.
pub trait MachineAirBuilder:
    BaseAirBuilder + ExtensionAirBuilder + SepticExtensionAirBuilder + AirBuilderWithPublicValues
{
    /// Extract public values from the air builder and convert them to the proper type.
    /// This is commonly used throughout the codebase to access public values in AIR
    /// implementations.
    #[allow(clippy::type_complexity)]
    fn extract_public_values(
        &self,
    ) -> super::PublicValues<
        [Self::PublicVar; 4],
        [Self::PublicVar; 3],
        [Self::PublicVar; 4],
        Self::PublicVar,
    > {
        use super::{PublicValues, SP1_PROOF_NUM_PV_ELTS};
        use std::borrow::Borrow;

        let public_values_slice: [Self::PublicVar; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| self.public_values()[i]);
        let public_values: &PublicValues<
            [Self::PublicVar; 4],
            [Self::PublicVar; 3],
            [Self::PublicVar; 4],
            Self::PublicVar,
        > = public_values_slice.as_slice().borrow();
        *public_values
    }
}

/// A trait which contains all helper methods for building SP1 machine AIRs.
pub trait SP1AirBuilder: MachineAirBuilder + ByteAirBuilder + InstructionAirBuilder {}

impl<AB: AirBuilder + MessageBuilder<M>, M> MessageBuilder<M> for FilteredAirBuilder<'_, AB> {
    fn send(&mut self, message: M, scope: InteractionScope) {
        self.inner.send(message, scope);
    }

    fn receive(&mut self, message: M, scope: InteractionScope) {
        self.inner.receive(message, scope);
    }
}

impl<AB: AirBuilder + MessageBuilder<AirInteraction<AB::Expr>>> BaseAirBuilder for AB {}
impl<AB: BaseAirBuilder> ByteAirBuilder for AB {}
impl<AB: BaseAirBuilder> InstructionAirBuilder for AB {}

impl<AB: BaseAirBuilder> ExtensionAirBuilder for AB {}
impl<AB: BaseAirBuilder> SepticExtensionAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> MachineAirBuilder for AB {}
impl<AB: BaseAirBuilder + AirBuilderWithPublicValues> SP1AirBuilder for AB {}

impl<SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'_, SC> {}
impl<SC: StarkGenericConfig> EmptyMessageBuilder for VerifierConstraintFolder<'_, SC> {}
impl<
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF>,
    > EmptyMessageBuilder for ConstraintSumcheckFolder<'_, F, K, EF>
{
}
impl<F: Field> EmptyMessageBuilder for SymbolicAirBuilder<F> {}

#[cfg(debug_assertions)]
#[cfg(not(doctest))]
impl<F: Field> EmptyMessageBuilder for slop_uni_stark::DebugConstraintBuilder<'_, F> {}
