use std::{
    borrow::Borrow,
    panic::{self, AssertUnwindSafe},
    process::exit,
};

use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder,
    PermutationAirBuilder,
};
use p3_field::{AbstractField, ExtensionField, Field, PrimeField32};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    stack::VerticalPair,
    Matrix,
};
use p3_maybe_rayon::prelude::ParallelBridge;
use p3_maybe_rayon::prelude::ParallelIterator;

use super::{MachineChip, StarkGenericConfig, Val};
use crate::air::{EmptyMessageBuilder, MachineAir, MultiTableAirBuilder};

/// Checks that the constraints of the given AIR are satisfied, including the permutation trace.
///
/// Note that this does not actually verify the proof.
#[allow(clippy::too_many_arguments)]
pub fn debug_constraints<SC, A>(
    chip: &MachineChip<SC, A>,
    preprocessed: Option<&RowMajorMatrix<Val<SC>>>,
    main: &RowMajorMatrix<Val<SC>>,
    perm: &RowMajorMatrix<SC::Challenge>,
    perm_challenges: &[SC::Challenge],
    public_values: &[Val<SC>],
    cumulative_sums: &[SC::Challenge],
) where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32,
    A: MachineAir<Val<SC>> + for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
{
    assert_eq!(main.height(), perm.height());
    let height = main.height();
    if height == 0 {
        return;
    }

    // Check that constraints are satisfied.
    (0..height).par_bridge().for_each(|i| {
        let i_next = (i + 1) % height;

        let main_local = main.row_slice(i);
        let main_local = &(*main_local);
        let main_next = main.row_slice(i_next);
        let main_next = &(*main_next);
        let preprocessed_local = if let Some(preprocessed) = preprocessed {
            let row = preprocessed.row_slice(i);
            let row: &[_] = (*row).borrow();
            row.to_vec()
        } else {
            Vec::new()
        };
        let preprocessed_next = if let Some(preprocessed) = preprocessed {
            let row = preprocessed.row_slice(i_next);
            let row: &[_] = (*row).borrow();
            row.to_vec()
        } else {
            Vec::new()
        };
        let perm_local = perm.row_slice(i);
        let perm_local = &(*perm_local);
        let perm_next = perm.row_slice(i_next);
        let perm_next = &(*perm_next);

        let mut builder = DebugConstraintBuilder {
            preprocessed: VerticalPair::new(
                RowMajorMatrixView::new_row(&preprocessed_local),
                RowMajorMatrixView::new_row(&preprocessed_next),
            ),
            main: VerticalPair::new(
                RowMajorMatrixView::new_row(main_local),
                RowMajorMatrixView::new_row(main_next),
            ),
            perm: VerticalPair::new(
                RowMajorMatrixView::new_row(perm_local),
                RowMajorMatrixView::new_row(perm_next),
            ),
            perm_challenges,
            cumulative_sums,
            is_first_row: Val::<SC>::zero(),
            is_last_row: Val::<SC>::zero(),
            is_transition: Val::<SC>::one(),
            public_values,
        };
        if i == 0 {
            builder.is_first_row = Val::<SC>::one();
        }
        if i == height - 1 {
            builder.is_last_row = Val::<SC>::one();
            builder.is_transition = Val::<SC>::zero();
        }
        let result = catch_unwind_silent(AssertUnwindSafe(|| {
            chip.eval(&mut builder);
        }));
        if result.is_err() {
            eprintln!("local: {main_local:?}");
            eprintln!("next:  {main_next:?}");
            eprintln!("failed at row {} of chip {}", i, chip.name());
            exit(1);
        }
    });
}

fn catch_unwind_silent<F: FnOnce() -> R + panic::UnwindSafe, R>(f: F) -> std::thread::Result<R> {
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(f);
    panic::set_hook(prev_hook);
    result
}

/// Checks that all the interactions between the chips has been satisfied.
///
/// Note that this does not actually verify the proof.
pub fn debug_cumulative_sums<F: Field, EF: ExtensionField<F>>(perms: &[RowMajorMatrix<EF>]) {
    let sum: EF = perms.iter().map(|perm| *perm.row_slice(perm.height() - 1).last().unwrap()).sum();
    assert_eq!(sum, EF::zero());
}

/// A builder for debugging constraints.
pub struct DebugConstraintBuilder<'a, F: Field, EF: ExtensionField<F>> {
    pub(crate) preprocessed: VerticalPair<RowMajorMatrixView<'a, F>, RowMajorMatrixView<'a, F>>,
    pub(crate) main: VerticalPair<RowMajorMatrixView<'a, F>, RowMajorMatrixView<'a, F>>,
    pub(crate) perm: VerticalPair<RowMajorMatrixView<'a, EF>, RowMajorMatrixView<'a, EF>>,
    pub(crate) cumulative_sums: &'a [EF],
    pub(crate) perm_challenges: &'a [EF],
    pub(crate) is_first_row: F,
    pub(crate) is_last_row: F,
    pub(crate) is_transition: F,
    pub(crate) public_values: &'a [F],
}

impl<'a, F, EF> ExtensionBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type VarEF = EF;
    type ExprEF = EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        assert_eq!(x.into(), EF::zero(), "constraints must evaluate to zero");
    }
}

impl<'a, F, EF> PermutationAirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type MP = VerticalPair<RowMajorMatrixView<'a, EF>, RowMajorMatrixView<'a, EF>>;

    type RandomVar = EF;

    fn permutation(&self) -> Self::MP {
        self.perm
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
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

impl<'a, F, EF> DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    #[allow(clippy::unused_self)]
    #[inline]
    fn debug_constraint(&self, x: F, y: F) {
        if x != y {
            let backtrace = std::backtrace::Backtrace::force_capture();
            eprintln!("constraint failed: {x:?} != {y:?}\n{backtrace}");
            panic!();
        }
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
    type M = VerticalPair<RowMajorMatrixView<'a, F>, RowMajorMatrixView<'a, F>>;

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
            let backtrace = std::backtrace::Backtrace::force_capture();
            eprintln!("constraint failed: {x:?} is not a bool\n{backtrace}");
            panic!();
        }
    }
}

impl<'a, F, EF> MultiTableAirBuilder<'a> for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Sum = EF;

    fn cumulative_sums(&self) -> &'a [Self::Sum] {
        self.cumulative_sums
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> EmptyMessageBuilder
    for DebugConstraintBuilder<'a, F, EF>
{
}

impl<'a, F: Field, EF: ExtensionField<F>> AirBuilderWithPublicValues
    for DebugConstraintBuilder<'a, F, EF>
{
    type PublicVar = F;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}
