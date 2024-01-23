use p3_air::{
    AirBuilder, EmptyMessageBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView,
};
use p3_field::{AbstractField, Field};

use p3_uni_stark::StarkConfig;

pub struct ProverConstraintFolder<'a, SC: StarkConfig> {
    pub preprocessed: TwoRowMatrixView<'a, SC::PackedVal>,
    pub main: TwoRowMatrixView<'a, SC::PackedVal>,
    pub perm: TwoRowMatrixView<'a, SC::PackedChallenge>,
    pub perm_challenges: &'a [SC::Challenge],
    pub is_first_row: SC::PackedVal,
    pub is_last_row: SC::PackedVal,
    pub is_transition: SC::PackedVal,
    pub alpha: SC::Challenge,
    pub accumulator: SC::PackedChallenge,
}

pub struct VerifierConstraintFolder<'a, Challenge> {
    pub preprocessed: TwoRowMatrixView<'a, Challenge>,
    pub main: TwoRowMatrixView<'a, Challenge>,
    pub perm: TwoRowMatrixView<'a, Challenge>,
    pub perm_challenges: &'a [Challenge],
    pub is_first_row: Challenge,
    pub is_last_row: Challenge,
    pub is_transition: Challenge,
    pub alpha: Challenge,
    pub accumulator: Challenge,
}

impl<'a, SC: StarkConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
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

impl<'a, SC: StarkConfig> PermutationAirBuilder for ProverConstraintFolder<'a, SC> {
    type EF = SC::Challenge;

    type ExprEF = SC::PackedChallenge;

    type VarEF = SC::PackedChallenge;

    type MP = TwoRowMatrixView<'a, SC::PackedChallenge>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkConfig> PairBuilder for ProverConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, SC: StarkConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}

impl<'a, Challenge: Field> AirBuilder for VerifierConstraintFolder<'a, Challenge> {
    type F = Challenge;
    type Expr = Challenge;
    type Var = Challenge;
    type M = TwoRowMatrixView<'a, Challenge>;

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
        let x: Challenge = x.into();
        self.accumulator *= self.alpha;
        self.accumulator += x;
    }
}

impl<'a, Challenge: Field> PermutationAirBuilder for VerifierConstraintFolder<'a, Challenge> {
    type EF = Challenge;

    type ExprEF = Challenge;

    type VarEF = Challenge;

    type MP = TwoRowMatrixView<'a, Challenge>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, Challenge: Field> PairBuilder for VerifierConstraintFolder<'a, Challenge> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, Challenge: Field> EmptyMessageBuilder for VerifierConstraintFolder<'a, Challenge> {}
