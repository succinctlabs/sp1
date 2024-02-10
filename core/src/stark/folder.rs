use super::StarkGenericConfig;
use crate::air::{EmptyMessageBuilder, MultiTableAirBuilder};
use p3_air::{AirBuilder, ExtensionBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView};
use p3_field::AbstractField;

/// A folder for prover constraints.
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    pub preprocessed: TwoRowMatrixView<'a, SC::PackedVal>,
    pub main: TwoRowMatrixView<'a, SC::PackedVal>,
    pub perm: TwoRowMatrixView<'a, SC::PackedChallenge>,
    pub perm_challenges: &'a [SC::Challenge],
    pub cumulative_sum: SC::Challenge,
    pub is_first_row: SC::PackedVal,
    pub is_last_row: SC::PackedVal,
    pub is_transition: SC::PackedVal,
    pub alpha: SC::Challenge,
    pub accumulator: SC::PackedChallenge,
}

impl<'a, SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
    type F = SC::Val;
    type Expr = SC::PackedVal;
    type Var = SC::PackedVal;
    type M = TwoRowMatrixView<'a, SC::PackedVal>;

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
        let x: SC::PackedVal = x.into();
        self.accumulator *= SC::PackedChallenge::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> ExtensionBuilder for ProverConstraintFolder<'a, SC> {
    type EF = SC::Challenge;

    type ExprEF = SC::PackedChallenge;

    type VarEF = SC::PackedChallenge;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let x: SC::PackedChallenge = x.into();
        self.accumulator *= SC::PackedChallenge::from_f(self.alpha);
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> PermutationAirBuilder for ProverConstraintFolder<'a, SC> {
    type MP = TwoRowMatrixView<'a, SC::PackedChallenge>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkGenericConfig> MultiTableAirBuilder for ProverConstraintFolder<'a, SC> {
    type Sum = SC::PackedChallenge;

    fn cumulative_sum(&self) -> Self::Sum {
        SC::PackedChallenge::from_f(self.cumulative_sum)
    }
}

impl<'a, SC: StarkGenericConfig> PairBuilder for ProverConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}

/// A folder for verifier constraints.
pub struct VerifierConstraintFolder<'a, SC: StarkGenericConfig> {
    pub preprocessed: TwoRowMatrixView<'a, SC::Challenge>,
    pub main: TwoRowMatrixView<'a, SC::Challenge>,
    pub perm: TwoRowMatrixView<'a, SC::Challenge>,
    pub perm_challenges: &'a [SC::Challenge],
    pub cumulative_sum: SC::Challenge,
    pub is_first_row: SC::Challenge,
    pub is_last_row: SC::Challenge,
    pub is_transition: SC::Challenge,
    pub alpha: SC::Challenge,
    pub accumulator: SC::Challenge,
}

impl<'a, SC: StarkGenericConfig> AirBuilder for VerifierConstraintFolder<'a, SC> {
    type F = SC::Val;
    type Expr = SC::Challenge;
    type Var = SC::Challenge;
    type M = TwoRowMatrixView<'a, SC::Challenge>;

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
        let x: SC::Challenge = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }
}

impl<'a, SC: StarkGenericConfig> ExtensionBuilder for VerifierConstraintFolder<'a, SC> {
    type EF = SC::Challenge;
    type ExprEF = SC::Challenge;
    type VarEF = SC::Challenge;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x)
    }
}

impl<'a, SC: StarkGenericConfig> PermutationAirBuilder for VerifierConstraintFolder<'a, SC> {
    type MP = TwoRowMatrixView<'a, SC::Challenge>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkGenericConfig> MultiTableAirBuilder for VerifierConstraintFolder<'a, SC> {
    type Sum = SC::Challenge;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, SC: StarkGenericConfig> PairBuilder for VerifierConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for VerifierConstraintFolder<'a, SC> {}
