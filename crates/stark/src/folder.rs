use std::{
    marker::PhantomData,
    ops::{Add, Mul, MulAssign, Sub},
};

use p3_field::{AbstractField, ExtensionField, Field};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair};

use super::{Challenge, PackedChallenge, PackedVal, StarkGenericConfig, Val};
use crate::air::{EmptyMessageBuilder, MultiTableAirBuilder};
use p3_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder, PermutationAirBuilder,
};

/// A folder for prover constraints.
pub struct ProverConstraintFolder<'a, SC: StarkGenericConfig> {
    /// The preprocessed trace.
    pub preprocessed:
        VerticalPair<RowMajorMatrixView<'a, PackedVal<SC>>, RowMajorMatrixView<'a, PackedVal<SC>>>,
    /// The main trace.
    pub main:
        VerticalPair<RowMajorMatrixView<'a, PackedVal<SC>>, RowMajorMatrixView<'a, PackedVal<SC>>>,
    /// The permutation trace.
    pub perm: VerticalPair<
        RowMajorMatrixView<'a, PackedChallenge<SC>>,
        RowMajorMatrixView<'a, PackedChallenge<SC>>,
    >,
    /// The challenges for the permutation.
    pub perm_challenges: &'a [PackedChallenge<SC>],
    /// The cumulative sums for the permutation.
    pub cumulative_sums: &'a [PackedChallenge<SC>],
    /// The selector for the first row.
    pub is_first_row: PackedVal<SC>,
    /// The selector for the last row.
    pub is_last_row: PackedVal<SC>,
    /// The selector for the transition.
    pub is_transition: PackedVal<SC>,
    /// The constraint folding challenge.
    pub alpha: SC::Challenge,
    /// The accumulator for the constraint folding.
    pub accumulator: PackedChallenge<SC>,
    /// The public values.
    pub public_values: &'a [Val<SC>],
}

impl<'a, SC: StarkGenericConfig> AirBuilder for ProverConstraintFolder<'a, SC> {
    type F = Val<SC>;
    type Expr = PackedVal<SC>;
    type Var = PackedVal<SC>;
    type M =
        VerticalPair<RowMajorMatrixView<'a, PackedVal<SC>>, RowMajorMatrixView<'a, PackedVal<SC>>>;

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
    type MP = VerticalPair<
        RowMajorMatrixView<'a, PackedChallenge<SC>>,
        RowMajorMatrixView<'a, PackedChallenge<SC>>,
    >;

    type RandomVar = PackedChallenge<SC>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.perm_challenges
    }
}

impl<'a, SC: StarkGenericConfig> MultiTableAirBuilder<'a> for ProverConstraintFolder<'a, SC> {
    type Sum = PackedChallenge<SC>;

    fn cumulative_sums(&self) -> &'a [Self::Sum] {
        self.cumulative_sums
    }
}

impl<'a, SC: StarkGenericConfig> PairBuilder for ProverConstraintFolder<'a, SC> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, SC: StarkGenericConfig> EmptyMessageBuilder for ProverConstraintFolder<'a, SC> {}

impl<'a, SC: StarkGenericConfig> AirBuilderWithPublicValues for ProverConstraintFolder<'a, SC> {
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

/// A folder for verifier constraints.
pub type VerifierConstraintFolder<'a, SC> = GenericVerifierConstraintFolder<
    'a,
    Val<SC>,
    Challenge<SC>,
    Val<SC>,
    Challenge<SC>,
    Challenge<SC>,
>;

/// A folder for verifier constraints.
pub struct GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr> {
    /// The preprocessed trace.
    pub preprocessed: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The main trace.
    pub main: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The permutation trace.
    pub perm: VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>,
    /// The challenges for the permutation.
    pub perm_challenges: &'a [Var],
    /// The cumulative sums of the permutation.
    pub cumulative_sums: &'a [Var],
    /// The selector for the first row.
    pub is_first_row: Var,
    /// The selector for the last row.
    pub is_last_row: Var,
    /// The selector for the transition.
    pub is_transition: Var,
    /// The constraint folding challenge.
    pub alpha: Var,
    /// The accumulator for the constraint folding.
    pub accumulator: Expr,
    /// The public values.
    pub public_values: &'a [PubVar],
    /// The marker type.
    pub _marker: PhantomData<(F, EF)>,
}

impl<'a, F, EF, PubVar, Var, Expr> AirBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type F = F;
    type Expr = Expr;
    type Var = Var;
    type M = VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>;

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
        let x: Expr = x.into();
        self.accumulator *= self.alpha.into();
        self.accumulator += x;
    }
}

impl<'a, F, EF, PubVar, Var, Expr> ExtensionBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type EF = EF;
    type ExprEF = Expr;
    type VarEF = Var;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.assert_zero(x);
    }
}

impl<'a, F, EF, PubVar, Var, Expr> PermutationAirBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type MP = VerticalPair<RowMajorMatrixView<'a, Var>, RowMajorMatrixView<'a, Var>>;
    type RandomVar = Var;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        self.perm_challenges
    }
}

impl<'a, F, EF, PubVar, Var, Expr> MultiTableAirBuilder<'a>
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type Sum = Var;

    fn cumulative_sums(&self) -> &'a [Self::Sum] {
        self.cumulative_sums
    }
}

impl<'a, F, EF, PubVar, Var, Expr> PairBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, F, EF, PubVar, Var, Expr> EmptyMessageBuilder
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
}

impl<'a, F, EF, PubVar, Var, Expr> AirBuilderWithPublicValues
    for GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr>
where
    F: Field,
    EF: ExtensionField<F>,
    Expr: AbstractField<F = EF>
        + From<F>
        + Add<Var, Output = Expr>
        + Add<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<F, Output = Expr>
        + MulAssign<EF>,
    Var: Into<Expr>
        + Copy
        + Add<F, Output = Expr>
        + Add<Var, Output = Expr>
        + Add<Expr, Output = Expr>
        + Sub<F, Output = Expr>
        + Sub<Var, Output = Expr>
        + Sub<Expr, Output = Expr>
        + Mul<F, Output = Expr>
        + Mul<Var, Output = Expr>
        + Mul<Expr, Output = Expr>
        + Send
        + Sync,
    PubVar: Into<Expr> + Copy,
{
    type PublicVar = PubVar;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}
