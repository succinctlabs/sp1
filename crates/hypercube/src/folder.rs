use crate::InteractionKind;
use std::{
    marker::PhantomData,
    ops::{Add, Div, Mul, MulAssign, Sub},
};

use crate::air::{AirInteraction, EmptyMessageBuilder, InteractionScope, MessageBuilder};
use slop_air::{
    AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, GlobalBuilder, PairBuilder,
    PermutationAirBuilder,
};
use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use slop_challenger::IopCtx;
use slop_matrix::dense::RowMajorMatrixView;

/// A folder for verifier constraints.
pub type VerifierConstraintFolder<'a, F, EF> =
    GenericVerifierConstraintFolder<'a, F, EF, F, EF, EF>;

/// A folder for verifier constraints.
pub struct GenericVerifierConstraintFolder<'a, F, EF, PubVar, Var, Expr> {
    /// The preprocessed trace.
    pub preprocessed: RowMajorMatrixView<'a, Var>,
    /// The global trace.
    pub global: RowMajorMatrixView<'a, Var>,
    /// The main trace.
    pub main: RowMajorMatrixView<'a, Var>,
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
    type M = RowMajorMatrixView<'a, Var>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_transition_window(&self, _: usize) -> Self::Expr {
        unimplemented!()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Expr = x.into();
        self.accumulator *= self.alpha.into();
        self.accumulator += x;
    }
}

impl<F, EF, PubVar, Var, Expr> ExtensionBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
    type MP = RowMajorMatrixView<'a, Var>;
    type RandomVar = Var;

    fn permutation(&self) -> Self::MP {
        unimplemented!();
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        unimplemented!()
    }
}

impl<F, EF, PubVar, Var, Expr> PairBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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

impl<F, EF, PubVar, Var, Expr> GlobalBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
    fn global(&self) -> Self::M {
        self.global
    }
}

impl<F, EF, PubVar, Var, Expr> EmptyMessageBuilder
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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

impl<F, EF, PubVar, Var, Expr> AirBuilderWithPublicValues
    for GenericVerifierConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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

/// A folder for the zerocheck sumcheck poly.
pub struct ConstraintSumcheckFolder<'a, F: Field, K: Field, EF> {
    /// The preprocessed row.
    pub preprocessed: RowMajorMatrixView<'a, K>,
    /// The global row.
    pub global: RowMajorMatrixView<'a, K>,
    /// The main row.
    pub main: RowMajorMatrixView<'a, K>,
    /// The constraint folding challenge.
    pub powers_of_alpha: &'a [EF],
    /// The accumulator for the constraint folding.
    pub accumulator: EF,
    /// The public values.
    pub public_values: &'a [F],
    /// The constraint index.
    pub constraint_index: usize,
}

impl<
        'a,
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF>,
    > AirBuilder for ConstraintSumcheckFolder<'a, F, K, EF>
{
    type F = F;
    type Expr = K;
    type Var = K;
    type M = RowMajorMatrixView<'a, K>;

    fn main(&self) -> Self::M {
        self.main
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_transition_window(&self, _: usize) -> Self::Expr {
        unimplemented!()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.accumulator += self.powers_of_alpha[self.constraint_index] * x.into();
        self.constraint_index += 1;
    }
}

impl<
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF> + ExtensionField<F> + AbstractExtensionField<K> + From<K>,
    > ExtensionBuilder for ConstraintSumcheckFolder<'_, F, K, EF>
{
    type EF = EF;

    type ExprEF = EF;

    type VarEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.accumulator += self.powers_of_alpha[self.constraint_index] * x.into();
        self.constraint_index += 1;
    }
}

impl<
        'a,
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF> + ExtensionField<F> + AbstractExtensionField<K>,
    > PermutationAirBuilder for ConstraintSumcheckFolder<'a, F, K, EF>
{
    type MP = RowMajorMatrixView<'a, EF>;

    type RandomVar = EF;

    fn permutation(&self) -> Self::MP {
        unimplemented!()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        unimplemented!()
    }
}

impl<
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF>,
    > PairBuilder for ConstraintSumcheckFolder<'_, F, K, EF>
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF>,
    > GlobalBuilder for ConstraintSumcheckFolder<'_, F, K, EF>
{
    fn global(&self) -> Self::M {
        self.global
    }
}

impl<
        F: Field,
        K: Field + From<F> + Add<F, Output = K> + Sub<F, Output = K> + Mul<F, Output = K>,
        EF: Field + Mul<K, Output = EF>,
    > AirBuilderWithPublicValues for ConstraintSumcheckFolder<'_, F, K, EF>
{
    type PublicVar = Self::F;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

/// A folder for verifier constraints on public values.
pub type VerifierPublicValuesConstraintFolder<'a, C> = GenericVerifierPublicValuesConstraintFolder<
    'a,
    <C as IopCtx>::F,
    <C as IopCtx>::EF,
    <C as IopCtx>::F,
    <C as IopCtx>::EF,
    <C as IopCtx>::EF,
>;

/// A folder for verifier constraints.
pub struct GenericVerifierPublicValuesConstraintFolder<'a, F, EF, PubVar, Var, Expr> {
    /// The challenges for the permutation (local scope).
    pub perm_challenges: (&'a Var, &'a [Expr]),
    /// The challenges for the permutation (global scope).
    pub global_perm_challenges: Option<(&'a Var, &'a [Expr])>,
    /// The constraint folding challenge.
    pub alpha: Var,
    /// The accumulator for the constraint folding.
    pub accumulator: Expr,
    /// The public values.
    pub public_values: &'a [PubVar],
    /// The local interaction digest.
    pub local_interaction_digest: Expr,
    /// The global interaction digest.
    pub global_interaction_digest: Expr,
    /// The marker type.
    pub _marker: PhantomData<(F, EF)>,
}

impl<'a, F, EF, PubVar, Var, Expr> AirBuilder
    for GenericVerifierPublicValuesConstraintFolder<'a, F, EF, PubVar, Var, Expr>
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
    type F = F;
    type Expr = Expr;
    type Var = Var;
    type M = RowMajorMatrixView<'a, Var>;

    fn main(&self) -> Self::M {
        unimplemented!()
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_transition_window(&self, _: usize) -> Self::Expr {
        unimplemented!()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Expr = x.into();
        self.accumulator *= self.alpha.into();
        self.accumulator += x;
    }
}

impl<F, EF, PubVar, Var, Expr> ExtensionBuilder
    for GenericVerifierPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
    for GenericVerifierPublicValuesConstraintFolder<'a, F, EF, PubVar, Var, Expr>
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
    type MP = RowMajorMatrixView<'a, Var>;
    type RandomVar = Var;

    fn permutation(&self) -> Self::MP {
        unimplemented!()
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        unimplemented!()
    }
}

impl<F, EF, PubVar, Var, Expr> PairBuilder
    for GenericVerifierPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
        unimplemented!()
    }
}

impl<F, EF, PubVar, Var, Expr> MessageBuilder<AirInteraction<Expr>>
    for GenericVerifierPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
        + MulAssign<EF>
        + Div<Expr, Output = Expr>,
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
    fn send(&mut self, message: AirInteraction<Expr>, scope: InteractionScope) {
        let digest = self.interaction_digest(message, scope);
        match scope {
            InteractionScope::Local => self.local_interaction_digest += digest,
            InteractionScope::Global => self.global_interaction_digest += digest,
        }
    }

    fn receive(&mut self, message: AirInteraction<Expr>, scope: InteractionScope) {
        let digest = self.interaction_digest(message, scope);
        match scope {
            InteractionScope::Local => self.local_interaction_digest -= digest,
            InteractionScope::Global => self.global_interaction_digest -= digest,
        }
    }
}

impl<F, EF, PubVar, Var, Expr>
    GenericVerifierPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
        + MulAssign<EF>
        + Div<Expr, Output = Expr>,
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
    /// The interaction's digest, fingerprinted with the challenge pair of its scope.
    fn interaction_digest(&self, message: AirInteraction<Expr>, scope: InteractionScope) -> Expr {
        let (alpha, betas) = match scope {
            InteractionScope::Local => self.perm_challenges,
            InteractionScope::Global => self.global_perm_challenges.expect(
                "global-scope public-value interaction on a machine without a global round",
            ),
        };
        let mut denominator: Expr = (*alpha).into();
        let mut betas = betas.iter().cloned();
        denominator += betas.next().unwrap() * F::from_canonical_usize(message.kind as usize);
        for value in message.values {
            denominator += value * betas.next().unwrap();
        }
        message.multiplicity / denominator
    }
}

impl<F, EF, PubVar, Var, Expr> AirBuilderWithPublicValues
    for GenericVerifierPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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

/// A folder for verifier constraints on public values.
pub type DebugPublicValuesConstraintFolder<'a, F> =
    GenericDebugPublicValuesConstraintFolder<'a, F, F, F, F, F>;

/// A folder for verifier constraints.
pub struct GenericDebugPublicValuesConstraintFolder<'a, F, EF, PubVar, Var, Expr> {
    /// The challenges for the permutation.
    pub perm_challenges: (&'a Var, &'a [Var]),
    /// The constraint folding challenge.
    pub alpha: Var,
    /// The accumulator for the constraint folding.
    pub accumulator: Expr,
    /// The public values.
    pub public_values: &'a [PubVar],
    /// The interactions.
    pub interactions: Vec<(InteractionKind, InteractionScope, Vec<Expr>, Expr)>,
    /// The marker type.
    pub _marker: PhantomData<(F, EF, Expr)>,
}

impl<'a, F, EF, PubVar, Var, Expr> AirBuilder
    for GenericDebugPublicValuesConstraintFolder<'a, F, EF, PubVar, Var, Expr>
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
    type F = F;
    type Expr = Expr;
    type Var = Var;
    type M = RowMajorMatrixView<'a, Var>;

    fn main(&self) -> Self::M {
        unimplemented!()
    }

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_transition_window(&self, _: usize) -> Self::Expr {
        unimplemented!()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let x: Expr = x.into();
        self.accumulator *= self.alpha.into();
        self.accumulator += x;
    }
}

impl<F, EF, PubVar, Var, Expr> ExtensionBuilder
    for GenericDebugPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
    for GenericDebugPublicValuesConstraintFolder<'a, F, EF, PubVar, Var, Expr>
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
    type MP = RowMajorMatrixView<'a, Var>;
    type RandomVar = Var;

    fn permutation(&self) -> Self::MP {
        unimplemented!()
    }

    fn permutation_randomness(&self) -> &[Self::Var] {
        unimplemented!()
    }
}

impl<F, EF, PubVar, Var, Expr> PairBuilder
    for GenericDebugPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
        unimplemented!()
    }
}

impl<F, EF, PubVar, Var, Expr> MessageBuilder<AirInteraction<Expr>>
    for GenericDebugPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
        + MulAssign<EF>
        + Div<Expr, Output = Expr>,
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
    fn send(&mut self, message: AirInteraction<Expr>, scope: InteractionScope) {
        self.interactions.push((message.kind, scope, message.values, message.multiplicity));
    }

    fn receive(&mut self, message: AirInteraction<Expr>, scope: InteractionScope) {
        self.interactions.push((message.kind, scope, message.values, -message.multiplicity));
    }
}

impl<F, EF, PubVar, Var, Expr> AirBuilderWithPublicValues
    for GenericDebugPublicValuesConstraintFolder<'_, F, EF, PubVar, Var, Expr>
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
