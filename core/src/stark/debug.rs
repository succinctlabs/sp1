use p3_air::{AirBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView};
use p3_field::{ExtensionField, Field};

use crate::air::EmptyMessageBuilder;

pub struct DebugConstraintBuilder<'a, F: Field, EF: ExtensionField<F>> {
    pub(crate) main: TwoRowMatrixView<'a, F>,
    pub(crate) preprocessed: TwoRowMatrixView<'a, F>,
    pub(crate) perm: TwoRowMatrixView<'a, EF>,
    pub(crate) perm_challenges: &'a [EF],
    pub(crate) is_first_row: F,
    pub(crate) is_last_row: F,
    pub(crate) is_transition: F,
}

impl<'a, F, EF> PermutationAirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type VarEF = EF;
    type ExprEF = EF;
    type MP = TwoRowMatrixView<'a, EF>;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        // TODO: implement
        self.perm_challenges
    }
}

impl<'a, F, EF> PairBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

impl<'a, F, EF> AirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = F;
    type Var = F;
    type M = TwoRowMatrixView<'a, F>;

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
            panic!("only supports a window size of 2")
        }
    }

    fn main(&self) -> Self::M {
        self.main
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        assert_eq!(x.into(), F::zero(), "constraints must evaluate to zero");
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> EmptyMessageBuilder
    for DebugConstraintBuilder<'a, F, EF>
{
}
