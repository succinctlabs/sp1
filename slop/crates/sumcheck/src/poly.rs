use slop_algebra::{Field, UnivariatePolynomial};

/// The basic functionality required of a struct for which a sumcheck proof can be generated.
pub trait SumcheckPolyBase {
    fn num_variables(&self) -> u32;
}

pub trait ComponentPoly<K: Field> {
    fn get_component_poly_evals(&self) -> Vec<K>;
}

/// A sumcheck polynomial that can prove the first rounds of a sumcheck, typically holding data
/// in a smaller field than `K`.
///
/// The parameter `t` is a lookahead depth: an implementation supporting `t > 1` computes the
/// messages of the first `t` rounds together in
/// [`Self::sum_as_poly_in_last_t_variables`], typically from a single pass over its data. The
/// transcript is unaffected by `t` — the prover still sends one message and samples one
/// challenge per variable.
pub trait SumcheckPolyFirstRound<K: Field>: SumcheckPolyBase {
    type NextRoundPoly: SumcheckPoly<K>;

    /// Fixes the last variable to `alpha`, producing the polynomial used from the second round
    /// onwards. `t` must match the value passed to [`Self::sum_as_poly_in_last_t_variables`], so
    /// that the prepared messages of rounds `2..=t` can be carried over to the next-round
    /// polynomial.
    fn fix_t_variables(self, alpha: K, t: usize) -> Self::NextRoundPoly;

    /// The first round message: the univariate polynomial obtained by summing all variables but
    /// the last over the boolean hypercube. With `t > 1`, the implementation also prepares the
    /// messages of rounds `2..=t` from the same pass over the data.
    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<K>,
        t: usize,
    ) -> UnivariatePolynomial<K>;
}

/// The fix_first_variable function applied to a sumcheck's post first rounds' polynomial.
pub trait SumcheckPoly<K: Field>: SumcheckPolyBase + ComponentPoly<K> + Sized {
    fn fix_last_variable(self, alpha: K) -> Self;

    fn sum_as_poly_in_last_variable(&self, claim: Option<K>) -> UnivariatePolynomial<K>;
}
