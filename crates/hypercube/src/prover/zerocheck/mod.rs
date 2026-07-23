//! Zerocheck Sumcheck polynomial.

mod first_two_rounds;
mod fix_last_variable;
mod sum_as_poly;

use std::{fmt::Debug, sync::OnceLock};

pub use first_two_rounds::*;
pub use fix_last_variable::*;
use slop_air::Air;
use slop_algebra::{ExtensionField, Field, UnivariatePolynomial};
use slop_alloc::{CpuBackend, HasBackend};
use slop_multilinear::{PaddedMle, Point, VirtualGeq};
use slop_sumcheck::{
    ComponentPolyEvalBackend, SumCheckPolyFirstRoundBackend, SumcheckPolyBackend, SumcheckPolyBase,
};
use slop_uni_stark::SymbolicAirBuilder;
pub use sum_as_poly::*;

use crate::{
    air::MachineAir, ConstraintSumcheckFolder, DebugConstraintBuilder, VerifierConstraintFolder,
};

/// Zerocheck sumcheck polynomial.
#[derive(Clone)]
pub struct ZeroCheckPoly<K, F, EF, A> {
    /// The data that contains the constraint polynomial.
    pub air_data: ZerocheckCpuProver<F, EF, A>,
    /// The random challenge point at which the polynomial is evaluated.
    pub zeta: Point<EF>,
    /// The preprocessed trace.
    pub preprocessed_columns: Option<PaddedMle<K>>,
    /// The main trace.
    pub main_columns: PaddedMle<K>,
    /// The adjustment factor from the constant part of the eq polynomial.
    pub eq_adjustment: EF,
    ///  The geq polynomial value.  This will be 0 for all zerocheck polys that are at least one
    /// non-padded variable.
    pub geq_value: EF,
    /// Num padded variables.  These padded variables are the first-most (e.g. the most
    /// significant) variables.
    // pub num_padded_vars: usize,
    /// The padded row adjustment.
    pub padded_row_adjustment: EF,

    /// A virtual materialization keeping track the geq polynomial which is used to adjust the sums
    /// for airs in which the zero row doesn't satisfy the constraints.
    pub virtual_geq: VirtualGeq<K>,

    /// The bivariate grid evaluations backing the fused first two rounds (lookahead `t = 2`),
    /// computed lazily by the first-round message and consumed when the first challenge is fixed.
    /// `None` inside the lock marks a fully padded chip, whose round messages are zero.
    pub(crate) bivariate_evals: OnceLock<Option<ZerocheckBivariateEvals<EF>>>,
    /// The round message interpolated ahead of time from the bivariate grid, making the second
    /// round of a lookahead sumcheck free of any pass over the trace.
    pub(crate) lookahead_message: Option<UnivariatePolynomial<EF>>,
}

impl<K: Field, F: Field, EF: ExtensionField<F>, AirData> ZeroCheckPoly<K, F, EF, AirData> {
    /// Creates a new `ZeroCheckPoly`.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        air_data: ZerocheckCpuProver<F, EF, AirData>,
        zeta: Point<EF>,
        preprocessed_values: Option<PaddedMle<K>>,
        main_values: PaddedMle<K>,
        eq_adjustment: EF,
        geq_value: EF,
        padded_row_adjustment: EF,
        virtual_geq: VirtualGeq<K>,
    ) -> Self {
        Self {
            air_data,
            zeta,
            preprocessed_columns: preprocessed_values,
            main_columns: main_values,
            eq_adjustment,
            geq_value,
            padded_row_adjustment,
            virtual_geq,
            bivariate_evals: OnceLock::new(),
            lookahead_message: None,
        }
    }
}

impl<K: Field, F: Field, EF, AirData> SumcheckPolyBase for ZeroCheckPoly<K, F, EF, AirData>
where
    K: Field,
{
    #[inline]
    fn num_variables(&self) -> u32 {
        self.main_columns.num_variables()
    }
}

impl<K, F, EF, AirData> ComponentPolyEvalBackend<ZeroCheckPoly<K, F, EF, AirData>, EF>
    for CpuBackend
where
    K: Field,
    F: Field,
    EF: ExtensionField<F> + ExtensionField<K>,
    AirData: Sync + Send,
{
    fn get_component_poly_evals(poly: &ZeroCheckPoly<K, F, EF, AirData>) -> Vec<EF> {
        assert_eq!(poly.num_variables(), 0);

        let prep_columns = poly.preprocessed_columns.as_ref();
        // First get the preprocessed values.
        let prep_evals = if let Some(preprocessed_values) = prep_columns {
            preprocessed_values.inner().as_ref().unwrap().guts().as_slice()
        } else {
            &[]
        };

        let main_evals = poly
            .main_columns
            .inner()
            .as_ref()
            .map(|mle| mle.guts().as_slice().to_vec())
            .unwrap_or(vec![K::zero(); poly.main_columns.num_polynomials()]);

        // Add the main values.
        prep_evals.iter().copied().chain(main_evals).map(Into::into).collect::<Vec<_>>()
    }
}

impl<F, EF, A: Send + Sync> SumCheckPolyFirstRoundBackend<ZeroCheckPoly<F, F, EF, A>, EF>
    for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
    A: ZerocheckAir<F, EF>,
{
    type NextRoundPoly = ZeroCheckPoly<EF, F, EF, A>;

    #[inline]
    fn fix_t_variables(
        poly: ZeroCheckPoly<F, F, EF, A>,
        alpha: EF,
        t: usize,
    ) -> Self::NextRoundPoly {
        match t {
            1 => zerocheck_fix_last_variable(poly, alpha),
            2 => zerocheck_fix_last_variable_with_lookahead(poly, alpha),
            _ => panic!("the zerocheck polynomial supports a lookahead of at most two rounds"),
        }
    }

    #[inline]
    fn sum_as_poly_in_last_t_variables(
        poly: &ZeroCheckPoly<F, F, EF, A>,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        debug_assert!(poly.num_variables() >= t as u32);
        match t {
            1 => zerocheck_sum_as_poly_in_last_variable::<F, F, EF, A, true>(poly, claim),
            2 => zerocheck_sum_as_poly_in_last_two_variables(poly, claim),
            _ => panic!("the zerocheck polynomial supports a lookahead of at most two rounds"),
        }
    }
}

impl<F, EF, A: Send + Sync> SumcheckPolyBackend<ZeroCheckPoly<EF, F, EF, A>, EF> for CpuBackend
where
    F: Field,
    EF: ExtensionField<F>,
    A: ZerocheckAir<F, EF>,
{
    #[inline]
    fn fix_last_variable(
        poly: ZeroCheckPoly<EF, F, EF, A>,
        alpha: EF,
    ) -> ZeroCheckPoly<EF, F, EF, A> {
        zerocheck_fix_last_variable(poly, alpha)
    }

    #[inline]
    fn sum_as_poly_in_last_variable(
        poly: &ZeroCheckPoly<EF, F, EF, A>,
        claim: Option<EF>,
    ) -> UnivariatePolynomial<EF> {
        debug_assert!(poly.num_variables() > 0);
        // A polynomial produced with a lookahead already carries this round's message.
        if let Some(message) = &poly.lookahead_message {
            if let Some(claim) = claim {
                debug_assert_eq!(
                    message.eval_one_plus_eval_zero(),
                    claim,
                    "lookahead round message inconsistent with the claim"
                );
            }
            return message.clone();
        }
        zerocheck_sum_as_poly_in_last_variable::<EF, F, EF, A, false>(poly, claim)
    }
}

impl<K, F, EF, AirData> HasBackend for ZeroCheckPoly<K, F, EF, AirData> {
    type Backend = CpuBackend;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.main_columns.backend()
    }
}

/// An AIR compatible with the standard zerocheck prover.
pub trait ZerocheckAir<F: Field, EF: ExtensionField<F>>:
    Debug
    + MachineAir<F>
    + Air<SymbolicAirBuilder<F>>
    + for<'b> Air<ConstraintSumcheckFolder<'b, F, F, EF>>
    + for<'b> Air<ConstraintSumcheckFolder<'b, F, EF, EF>>
    + for<'b> Air<DebugConstraintBuilder<'b, F, EF>>
    + for<'a> Air<VerifierConstraintFolder<'a, F, EF>>
{
}

impl<F: Field, EF: ExtensionField<F>, A> ZerocheckAir<F, EF> for A where
    A: MachineAir<F>
        + Debug
        + Air<SymbolicAirBuilder<F>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, F, F, EF>>
        + for<'b> Air<ConstraintSumcheckFolder<'b, F, EF, EF>>
        + for<'b> Air<DebugConstraintBuilder<'b, F, EF>>
        + for<'a> Air<VerifierConstraintFolder<'a, F, EF>>
{
}
