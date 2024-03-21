use p3_air::{AirBuilder, ExtensionBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView};
use sp1_core::air::{EmptyMessageBuilder, MultiTableAirBuilder};

use crate::{
    ir::{Builder, Config, Ext},
    prelude::SymbolicExt,
};

pub struct RecursiveVerifierConstraintFolder<'a, C: Config> {
    pub builder: &'a mut Builder<C>,
    pub preprocessed: TwoRowMatrixView<'a, Ext<C::F, C::EF>>,
    pub main: TwoRowMatrixView<'a, Ext<C::F, C::EF>>,
    pub perm: TwoRowMatrixView<'a, Ext<C::F, C::EF>>,
    pub perm_challenges: &'a [C::EF],
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub is_first_row: Ext<C::F, C::EF>,
    pub is_last_row: Ext<C::F, C::EF>,
    pub is_transition: Ext<C::F, C::EF>,
    pub alpha: Ext<C::F, C::EF>,
    pub accumulator: Ext<C::F, C::EF>,
}

impl<'a, C: Config> AirBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type F = C::F;
    type Expr = SymbolicExt<C::F, C::EF>;
    type Var = Ext<C::F, C::EF>;
    type M = TwoRowMatrixView<'a, Ext<C::F, C::EF>>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row.into()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row.into()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition.into()
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Self::Expr = x.into();
        self.builder
            .assign(self.accumulator, self.accumulator * self.alpha);
        self.builder.assign(self.accumulator, self.accumulator + x);
    }
}

impl<'a, C: Config> ExtensionBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type EF = C::EF;
    type ExprEF = SymbolicExt<C::F, C::EF>;
    type VarEF = Ext<C::F, C::EF>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x)
    }
}

impl<'a, C: Config> PermutationAirBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type MP = TwoRowMatrixView<'a, Self::Var>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, C: Config> MultiTableAirBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    type Sum = Self::Var;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, C: Config> PairBuilder for RecursiveVerifierConstraintFolder<'a, C> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, C: Config> EmptyMessageBuilder for RecursiveVerifierConstraintFolder<'a, C> {}
