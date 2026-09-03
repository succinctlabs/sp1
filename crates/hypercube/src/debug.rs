use std::{borrow::Borrow, collections::BTreeMap};

use rayon::prelude::*;
use slop_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder,
    PermutationAirBuilder,
};
use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_challenger::IopCtx;
use slop_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    Matrix,
};
use slop_multilinear::Mle;

use crate::{
    air::{EmptyMessageBuilder, MachineAir},
    prover::Traces,
    Chip,
};

/// Checks that the constraints of the given AIR are satisfied, including the permutation trace.
///
/// Note that this does not actually verify the proof.
#[allow(clippy::too_many_arguments)]
pub fn debug_constraints<GC, A>(
    chip: &Chip<GC::F, A>,
    preprocessed: Option<&Mle<GC::F>>,
    main: &Mle<GC::F>,
    public_values: &[GC::F],
) -> Vec<(usize, Vec<usize>, Vec<GC::F>)>
where
    GC: IopCtx,
    A: MachineAir<GC::F> + for<'a> Air<DebugConstraintBuilder<'a, GC::F, GC::EF>>,
{
    let main: RowMajorMatrix<GC::F> = main.clone().into_guts().try_into().unwrap();
    let preprocessed: Option<RowMajorMatrix<GC::F>> =
        preprocessed.map(|pre| pre.clone().into_guts().try_into().unwrap());
    let height = main.height();
    if height == 0 {
        return Vec::new();
    }

    // Check that constraints are satisfied.
    let mut failed_rows = (0..height)
        .par_bridge()
        .filter_map(|i| {
            let main_local = main.row_slice(i);
            let main_local = &(*main_local);
            let preprocessed_local = if let Some(preprocessed) = preprocessed.as_ref() {
                let row = preprocessed.row_slice(i);
                let row: &[_] = (*row).borrow();
                row.to_vec()
            } else {
                Vec::new()
            };

            let mut builder = DebugConstraintBuilder {
                preprocessed: RowMajorMatrixView::new_row(&preprocessed_local),
                main: RowMajorMatrixView::new_row(main_local),
                public_values,
                failing_constraints: Vec::new(),
                num_constraints_evaluated: 0,
                phantom: std::marker::PhantomData,
            };
            chip.eval(&mut builder);
            if !builder.failing_constraints.is_empty() {
                Some((i, builder.failing_constraints, main_local.to_vec()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    failed_rows.sort_unstable();

    failed_rows
}

/// Checks that the constraints of all the given AIRs are satisfied on the proposed witnesses sent
/// in `main` and `preprocessed`.
pub fn debug_constraints_all_chips<GC, A>(
    chips: &[Chip<GC::F, A>],
    preprocessed: &Traces<GC::F, CpuBackend>,
    main: &Traces<GC::F, CpuBackend>,
    public_values: &[GC::F],
) where
    GC: IopCtx,
    A: MachineAir<GC::F> + for<'a> Air<DebugConstraintBuilder<'a, GC::F, GC::EF>>,
{
    let mut result = BTreeMap::new();
    for chip in chips.iter() {
        let preprocessed_trace =
            preprocessed.get(chip.air.name()).map(|t| t.inner().as_ref().unwrap().as_ref());
        let maybe_main_trace = main.get(chip.air.name()).unwrap().inner().as_ref();

        if maybe_main_trace.is_none() {
            continue;
        }
        let main_trace = maybe_main_trace.unwrap().as_ref();
        let failed_rows =
            crate::debug_constraints::<GC, A>(chip, preprocessed_trace, main_trace, public_values);
        if !failed_rows.is_empty() {
            result.insert(chip.name().to_string(), failed_rows);
        }
    }

    for (chip_name, failed_rows) in result {
        if !failed_rows.is_empty() {
            tracing::error!("======== CONSTRAINTS FAILED ON CHIP '{}' ========", chip_name);
            tracing::error!("Total failing rows: {}", failed_rows.len());
            tracing::error!("Printing information for up to three failing rows:");
        }

        for i in 0..3.min(failed_rows.len()) {
            // Print up to three failing rows.
            let (row_idx, failing_constraints, row) = &failed_rows[i];

            tracing::error!("--------------------------------------------------");
            tracing::error!("row {} failed", row_idx);
            tracing::error!("constraint indices failed {:?}", failing_constraints);
            tracing::error!("row values: {:?}", row);
            tracing::error!("--------------------------------------------------");
        }
        if !failed_rows.is_empty() {
            tracing::error!("==================================================");
        }
    }
}

/// A builder for debugging constraints.
pub struct DebugConstraintBuilder<'a, F: Field, EF: ExtensionField<F>> {
    pub(crate) preprocessed: RowMajorMatrixView<'a, F>,
    pub(crate) main: RowMajorMatrixView<'a, F>,
    pub(crate) public_values: &'a [F],
    failing_constraints: Vec<usize>,
    num_constraints_evaluated: usize,
    phantom: std::marker::PhantomData<EF>,
}

impl<F, EF> ExtensionBuilder for DebugConstraintBuilder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type VarEF = EF;
    type ExprEF = EF;

    fn assert_zero_ext<I>(&mut self, _x: I)
    where
        I: Into<Self::ExprEF>,
    {
        panic!("Extension fields not supported in debug builder, SP1 Hypercube traces are over base field");
    }
}

impl<'a, F, EF> PermutationAirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type MP = RowMajorMatrixView<'a, EF>;

    type RandomVar = EF;

    fn permutation(&self) -> Self::MP {
        unimplemented!()
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        unimplemented!()
    }
}

impl<F, EF> PairBuilder for DebugConstraintBuilder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn preprocessed(&self) -> Self::M {
        self.preprocessed
    }
}

/// Test-only constructor and accessors.
///
/// These let an individual AIR operation be evaluated against a witness row in a unit test,
/// instead of only through a full machine proof.
#[cfg(test)]
impl<'a, F, EF> DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Build a builder over a single main-trace row, with no preprocessed trace.
    pub(crate) fn for_single_row(main: &'a [F], public_values: &'a [F]) -> Self {
        Self {
            preprocessed: RowMajorMatrixView::new(&[], 0),
            main: RowMajorMatrixView::new_row(main),
            public_values,
            failing_constraints: Vec::new(),
            num_constraints_evaluated: 0,
            phantom: std::marker::PhantomData,
        }
    }

    /// The indices of the constraints that did not hold.
    pub(crate) fn failing_constraints(&self) -> &[usize] {
        &self.failing_constraints
    }

    /// The total number of constraints evaluated so far.
    pub(crate) fn num_constraints_evaluated(&self) -> usize {
        self.num_constraints_evaluated
    }
}

impl<F, EF> DebugConstraintBuilder<'_, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    #[allow(clippy::unused_self)]
    #[inline]
    fn debug_constraint(&mut self, x: F, y: F) {
        if x != y {
            self.failing_constraints.push(self.num_constraints_evaluated);
        }
        self.num_constraints_evaluated += 1;
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
    type M = RowMajorMatrixView<'a, F>;

    fn is_first_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_last_row(&self) -> Self::Expr {
        unimplemented!()
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        unimplemented!()
    }

    fn main(&self) -> Self::M {
        self.main
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.debug_constraint(x.into(), F::zero());
    }

    fn assert_one<I: Into<Self::Expr>>(&mut self, x: I) {
        self.debug_constraint(x.into(), F::one());
    }

    fn assert_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(&mut self, x: I1, y: I2) {
        self.debug_constraint(x.into(), y.into());
    }

    /// Assert that `x` is a boolean, i.e. either 0 or 1.
    fn assert_bool<I: Into<Self::Expr>>(&mut self, x: I) {
        let x = x.into();
        if x != F::zero() && x != F::one() {
            self.failing_constraints.push(self.num_constraints_evaluated);
        }
        self.num_constraints_evaluated += 1;
    }
}

impl<F: Field, EF: ExtensionField<F>> EmptyMessageBuilder for DebugConstraintBuilder<'_, F, EF> {}

impl<F: Field, EF: ExtensionField<F>> AirBuilderWithPublicValues
    for DebugConstraintBuilder<'_, F, EF>
{
    type PublicVar = F;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}
