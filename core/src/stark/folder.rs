use p3_air::{AirBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView};
use p3_field::{AbstractExtensionField, AbstractField, Field};
use p3_field::{ExtensionField, Res};

use crate::air::EmptyMessageBuilder;

use super::StarkConfig;

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

pub struct VerifierConstraintFolder<'a, F, EF, EA> {
    pub preprocessed: TwoRowMatrixView<'a, Res<F, EF>>,
    pub main: TwoRowMatrixView<'a, Res<F, EF>>,
    pub perm: TwoRowMatrixView<'a, EA>,
    pub perm_challenges: &'a [EF],
    pub is_first_row: EF,
    pub is_last_row: EF,
    pub is_transition: EF,
    pub alpha: EF,
    pub accumulator: Res<F, EF>,
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

impl<'a, F: Field, EF: ExtensionField<F>, EA: AbstractExtensionField<Res<F, EF>, F = EF>> AirBuilder
    for VerifierConstraintFolder<'a, F, EF, EA>
{
    type F = F;
    type Expr = Res<F, EF>;
    type Var = Res<F, EF>;
    type M = TwoRowMatrixView<'a, Res<F, EF>>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        Res::from_inner(self.is_first_row)
    }

    fn is_last_row(&self) -> Self::Expr {
        Res::from_inner(self.is_last_row)
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            Res::from_inner(self.is_transition)
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Res<F, EF> = x.into();
        self.accumulator *= Self::Expr::from_inner(self.alpha);
        self.accumulator += x;
    }
}

impl<'a, F, EF, EA> PermutationAirBuilder for VerifierConstraintFolder<'a, F, EF, EA>
where
    F: Field,
    EF: ExtensionField<F>,
    EA: AbstractExtensionField<Res<F, EF>, F = EF> + Copy,
{
    type EF = EF;

    type ExprEF = EA;

    type VarEF = EA;

    type MP = TwoRowMatrixView<'a, EA>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, F, EF, EA> PairBuilder for VerifierConstraintFolder<'a, F, EF, EA>
where
    F: Field,
    EF: ExtensionField<F>,
    EA: AbstractExtensionField<Res<F, EF>, F = EF> + Copy,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, F, EF, EA> EmptyMessageBuilder for VerifierConstraintFolder<'a, F, EF, EA>
where
    F: Field,
    EF: ExtensionField<F>,
    EA: AbstractExtensionField<Res<F, EF>, F = EF> + Copy,
{
}
