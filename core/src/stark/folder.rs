use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
};

use super::{PackedChallenge, PackedVal, StarkGenericConfig, SuperChallenge};
use crate::air::{EmptyMessageBuilder, MultiTableAirBuilder};

use p3_air::{AirBuilder, ExtensionBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field};

/// A folder for prover constraints.
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    pub preprocessed: TwoRowMatrixView<'a, PackedVal<SC>>,
    pub main: TwoRowMatrixView<'a, PackedVal<SC>>,
    pub perm: TwoRowMatrixView<'a, PackedChallenge<SC>>,
    pub perm_challenges: &'a [SuperChallenge<SC::Val>],
    pub cumulative_sum: SuperChallenge<SC::Val>,
    pub is_first_row: PackedVal<SC>,
    pub is_last_row: PackedVal<SC>,
    pub is_transition: PackedVal<SC>,
    pub alpha: SuperChallenge<SC::Val>,
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
    type EF = SuperChallenge<SC::Val>;

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
pub struct VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF> {
    pub preprocessed: TwoRowMatrixView<'a, VarEF>,
    pub main: TwoRowMatrixView<'a, VarEF>,
    pub perm: TwoRowMatrixView<'a, VarEF>,
    pub perm_challenges: &'a [EF],
    pub cumulative_sum: VarEF,
    pub is_first_row: ExprEF,
    pub is_last_row: ExprEF,
    pub is_transition: ExprEF,
    pub alpha: VarEF,
    pub accumulator: ExprEF,
    pub phantom: PhantomData<(F, EF, VarF, VarEF, ExprF, ExprEF)>,
}

impl<'a, F, EF, VarF, VarEF, ExprF, ExprEF> AirBuilder
    for VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF>
where
    F: Field,
    ExprEF: AbstractField
        + From<F>
        + Add<VarEF, Output = ExprEF>
        + Add<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>,
    VarEF: Into<ExprEF>
        + Copy
        + Add<F, Output = ExprEF>
        + Add<VarEF, Output = ExprEF>
        + Add<ExprEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<ExprEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<ExprEF, Output = ExprEF>,
{
    type F = F;
    type Expr = ExprEF;
    type Var = VarEF;
    type M = TwoRowMatrixView<'a, VarEF>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row.clone()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row.clone()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition.clone()
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator *= self.alpha.into();
        self.accumulator += x.into();
    }
}

impl<'a, F, EF, VarF, VarEF, ExprF, ExprEF> ExtensionBuilder
    for VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF>
where
    F: Field,
    EF: ExtensionField<F> + Mul<VarEF, Output = ExprEF>,
    ExprEF: AbstractField<F = EF>
        + AbstractExtensionField<F>
        + From<F>
        + Add<VarEF, Output = ExprEF>
        + Add<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>,
    VarEF: Into<ExprEF>
        + Copy
        + Add<F, Output = ExprEF>
        + Add<VarEF, Output = ExprEF>
        + Add<ExprEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<ExprEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<ExprEF, Output = ExprEF>,
{
    type EF = EF;
    type ExprEF = ExprEF;
    type VarEF = VarEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x)
    }
}

impl<'a, F, EF, VarF, VarEF, ExprF, ExprEF> PermutationAirBuilder
    for VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF>
where
    F: Field,
    EF: ExtensionField<F> + Mul<VarEF, Output = ExprEF>,
    ExprEF: AbstractField<F = EF>
        + AbstractExtensionField<F>
        + From<F>
        + Add<VarEF, Output = ExprEF>
        + Add<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>,
    VarEF: Into<ExprEF>
        + Copy
        + Add<F, Output = ExprEF>
        + Add<VarEF, Output = ExprEF>
        + Add<ExprEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<ExprEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<ExprEF, Output = ExprEF>,
{
    type MP = TwoRowMatrixView<'a, VarEF>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.perm_challenges
    }
}

impl<'a, F, EF, VarF, VarEF, ExprF, ExprEF> MultiTableAirBuilder
    for VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF>
where
    F: Field,
    EF: ExtensionField<F> + Mul<VarEF, Output = ExprEF>,
    ExprEF: AbstractField<F = EF>
        + AbstractExtensionField<F>
        + From<F>
        + Add<VarEF, Output = ExprEF>
        + Add<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>,
    VarEF: Into<ExprEF>
        + Copy
        + Add<F, Output = ExprEF>
        + Add<VarEF, Output = ExprEF>
        + Add<ExprEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<ExprEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<ExprEF, Output = ExprEF>,
{
    type Sum = ExprEF;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum.into()
    }
}

impl<'a, F, EF, VarF, VarEF, ExprF, ExprEF> PairBuilder
    for VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF>
where
    F: Field,
    EF: ExtensionField<F> + Mul<VarEF, Output = ExprEF>,
    ExprEF: AbstractField<F = EF>
        + AbstractExtensionField<F>
        + From<F>
        + Add<VarEF, Output = ExprEF>
        + Add<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>,
    VarEF: Into<ExprEF>
        + Copy
        + Add<F, Output = ExprEF>
        + Add<VarEF, Output = ExprEF>
        + Add<ExprEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<ExprEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<ExprEF, Output = ExprEF>,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, F, EF, VarF, VarEF, ExprF, ExprEF> EmptyMessageBuilder
    for VerifierConstraintFolder<'a, F, EF, VarF, VarEF, ExprF, ExprEF>
where
    F: Field,
    EF: ExtensionField<F> + Mul<VarEF, Output = ExprEF>,
    ExprEF: AbstractField<F = EF>
        + AbstractExtensionField<F>
        + From<F>
        + Add<VarEF, Output = ExprEF>
        + Add<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>,
    VarEF: Into<ExprEF>
        + Copy
        + Add<F, Output = ExprEF>
        + Add<VarEF, Output = ExprEF>
        + Add<ExprEF, Output = ExprEF>
        + Sub<F, Output = ExprEF>
        + Sub<VarEF, Output = ExprEF>
        + Sub<ExprEF, Output = ExprEF>
        + Mul<F, Output = ExprEF>
        + Mul<VarEF, Output = ExprEF>
        + Mul<ExprEF, Output = ExprEF>,
{
}
