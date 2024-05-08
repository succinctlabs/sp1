use p3_air::{AirBuilder, ExtensionBuilder, FilteredAirBuilder, PermutationAirBuilder};
use sp1_core::air::MessageBuilder;

/// The MultiBuilder is used for the multi table.  It is used to create a virtual builder for one of
/// the sub tables in the multi table.
pub struct MultiBuilder<'a, AB: AirBuilder> {
    inner: FilteredAirBuilder<'a, AB>,
    next_condition: AB::Expr,
}

impl<'a, AB: AirBuilder> MultiBuilder<'a, AB> {
    pub fn new(builder: &'a mut AB, local_condition: AB::Expr, next_condition: AB::Expr) -> Self {
        let inner = builder.when(local_condition.clone());
        Self {
            inner,
            next_condition,
        }
    }
}

impl<'a, AB: AirBuilder> AirBuilder for MultiBuilder<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = AB::M;

    fn main(&self) -> Self::M {
        self.inner.main()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.next_condition.clone() * self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }
}

impl<'a, AB: ExtensionBuilder> ExtensionBuilder for MultiBuilder<'a, AB> {
    type EF = AB::EF;
    type VarEF = AB::VarEF;
    type ExprEF = AB::ExprEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.inner.assert_zero_ext(x.into());
    }
}

impl<'a, AB: PermutationAirBuilder> PermutationAirBuilder for MultiBuilder<'a, AB> {
    type MP = AB::MP;

    type RandomVar = AB::RandomVar;

    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }
}

impl<'a, AB: AirBuilder + MessageBuilder<M>, M> MessageBuilder<M> for MultiBuilder<'a, AB> {
    fn send(&mut self, message: M) {
        self.inner.send(message);
    }

    fn receive(&mut self, message: M) {
        self.inner.receive(message);
    }
}
