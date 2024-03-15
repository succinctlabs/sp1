use std::marker::PhantomData;

use super::{PackedChallenge, PackedVal, StarkGenericConfig};
use crate::air::{EmptyMessageBuilder, MultiTableAirBuilder};
use p3_air::{AirBuilder, ExtensionBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field};

/// A folder for prover constraints.
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    pub preprocessed: TwoRowMatrixView<'a, PackedVal<SC>>,
    pub main: TwoRowMatrixView<'a, PackedVal<SC>>,
    pub perm: TwoRowMatrixView<'a, PackedChallenge<SC>>,
    pub perm_challenges: &'a [SC::Challenge],
    pub cumulative_sum: SC::Challenge,
    pub is_first_row: PackedVal<SC>,
    pub is_last_row: PackedVal<SC>,
    pub is_transition: PackedVal<SC>,
    pub alpha: SC::Challenge,
    pub accumulator: PackedChallenge<SC>,
}

impl<'a, SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
    type F = SC::Val;
    type Expr = PackedVal<SC>;
    type Var = PackedVal<SC>;
    type M = TwoRowMatrixView<'a, PackedVal<SC>>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: PackedVal<SC> = x.into();
        self.accumulator *= PackedChallenge::<SC>::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> ExtensionBuilder for ProverConstraintFolder<'a, SC> {
    type EF = SC::Challenge;

    type ExprEF = PackedChallenge<SC>;

    type VarEF = PackedChallenge<SC>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: PackedChallenge<SC> = x.into();
        self.accumulator *= PackedChallenge::<SC>::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> PermutationAirBuilder for ProverConstraintFolder<'a, SC> {
    type MP = TwoRowMatrixView<'a, PackedChallenge<SC>>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkGenericConfig> MultiTableAirBuilder for ProverConstraintFolder<'a, SC> {
    type Sum = PackedChallenge<SC>;

    fn cumulative_sum(&self) -> Self::Sum {
        PackedChallenge::<SC>::from_f(self.cumulative_sum)
    }
}

impl<'a, SC: StarkGenericConfig> PairBuilder for ProverConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}

/// A folder for verifier constraints.
pub struct VerifierConstraintFolder<'a, F, EF> {
    pub preprocessed: TwoRowMatrixView<'a, EF>,
    pub main: TwoRowMatrixView<'a, EF>,
    pub perm: TwoRowMatrixView<'a, EF>,
    pub perm_challenges: &'a [EF],
    pub cumulative_sum: EF,
    pub is_first_row: EF,
    pub is_last_row: EF,
    pub is_transition: EF,
    pub alpha: EF,
    pub accumulator: EF,
    pub phantom: PhantomData<F>,
}

impl<'a, F: Field, EF: AbstractExtensionField<F> + Copy> AirBuilder
    for VerifierConstraintFolder<'a, F, EF>
{
    type F = F;
    type Expr = EF;
    type Var = EF;
    type M = TwoRowMatrixView<'a, EF>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator *= self.alpha;
        self.accumulator += x.into();
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> ExtensionBuilder for VerifierConstraintFolder<'a, F, EF> {
    type EF = EF;
    type ExprEF = EF;
    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x)
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> PermutationAirBuilder
    for VerifierConstraintFolder<'a, F, EF>
{
    type MP = TwoRowMatrixView<'a, EF>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> MultiTableAirBuilder
    for VerifierConstraintFolder<'a, F, EF>
{
    type Sum = EF;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> PairBuilder for VerifierConstraintFolder<'a, F, EF> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> EmptyMessageBuilder
    for VerifierConstraintFolder<'a, F, EF>
{
}
