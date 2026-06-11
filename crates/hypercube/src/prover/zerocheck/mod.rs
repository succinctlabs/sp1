//! Zerocheck Sumcheck polynomial.

mod fix_last_variable;
mod sum_as_poly;

use std::fmt::Debug;

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
    /// The global trace.
    pub global_columns: Option<PaddedMle<K>>,
    /// The main trace.
    pub main_columns: Option<PaddedMle<K>>,
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
}

impl<K: Field, F: Field, EF: ExtensionField<F>, AirData> ZeroCheckPoly<K, F, EF, AirData> {
    /// Creates a new `ZeroCheckPoly`.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub fn new(
        air_data: ZerocheckCpuProver<F, EF, AirData>,
        zeta: Point<EF>,
        preprocessed_values: Option<PaddedMle<K>>,
        global_values: Option<PaddedMle<K>>,
        main_values: Option<PaddedMle<K>>,
        eq_adjustment: EF,
        geq_value: EF,
        padded_row_adjustment: EF,
        virtual_geq: VirtualGeq<K>,
    ) -> Self {
        Self {
            air_data,
            zeta,
            preprocessed_columns: preprocessed_values,
            global_columns: global_values,
            main_columns: main_values,
            eq_adjustment,
            geq_value,
            padded_row_adjustment,
            virtual_geq,
        }
    }
}

impl<K: Field, F, EF, AirData> ZeroCheckPoly<K, F, EF, AirData> {
    /// The trace group that determines the chip height.
    #[inline]
    pub fn height_columns(&self) -> &PaddedMle<K> {
        self.main_columns
            .as_ref()
            .or(self.global_columns.as_ref())
            .expect("chip has neither main nor global columns")
    }

    /// The number of real (non-padded) rows of the chip.
    #[inline]
    #[must_use]
    pub fn num_real_entries(&self) -> usize {
        self.height_columns().num_real_entries()
    }
}

impl<K: Field, F: Field, EF, AirData> SumcheckPolyBase for ZeroCheckPoly<K, F, EF, AirData>
where
    K: Field,
{
    #[inline]
    fn num_variables(&self) -> u32 {
        self.height_columns().num_variables()
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

        let prep_evals = group_evals(poly.preprocessed_columns.as_ref());
        let global_evals = group_evals(poly.global_columns.as_ref());
        let main_evals = group_evals(poly.main_columns.as_ref());

        prep_evals
            .into_iter()
            .chain(global_evals)
            .chain(main_evals)
            .map(Into::into)
            .collect::<Vec<_>>()
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
        debug_assert_eq!(t, 1);
        zerocheck_fix_last_variable(poly, alpha)
    }

    #[inline]
    fn sum_as_poly_in_last_t_variables(
        poly: &ZeroCheckPoly<F, F, EF, A>,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        debug_assert_eq!(t, 1);
        debug_assert!(poly.num_variables() > 0);
        zerocheck_sum_as_poly_in_last_variable::<F, F, EF, A, true>(poly, claim)
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
        zerocheck_sum_as_poly_in_last_variable::<EF, F, EF, A, false>(poly, claim)
    }
}

impl<K: Field, F, EF, AirData> HasBackend for ZeroCheckPoly<K, F, EF, AirData> {
    type Backend = CpuBackend;

    #[inline]
    fn backend(&self) -> &Self::Backend {
        self.height_columns().backend()
    }
}

/// The evaluations of a fully-fixed trace group.
fn group_evals<K: Field>(columns: Option<&PaddedMle<K>>) -> Vec<K> {
    columns.map_or_else(Vec::new, |mle| {
        mle.inner().as_ref().map_or_else(
            || vec![K::zero(); mle.num_polynomials()],
            |inner| inner.guts().as_slice().to_vec(),
        )
    })
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
