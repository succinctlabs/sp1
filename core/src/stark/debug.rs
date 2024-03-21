use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_air::{
    Air, AirBuilder, ExtensionBuilder, PairBuilder, PermutationAirBuilder, TwoRowMatrixView,
};
use p3_field::{AbstractField, PrimeField32};
use p3_field::{ExtensionField, Field};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices};

use crate::air::{EmptyMessageBuilder, MachineAir, MultiTableAirBuilder};

use super::{MachineChip, StarkGenericConfig, Val};

/// Checks that the constraints of the given AIR are satisfied, including the permutation trace.
///
/// Note that this does not actually verify the proof.
pub fn debug_constraints<SC: StarkGenericConfig, A: MachineAir<Val<SC>>>(
    chip: &MachineChip<SC, A>,
    preprocessed: Option<&RowMajorMatrix<Val<SC>>>,
    main: &RowMajorMatrix<Val<SC>>,
    perm: &RowMajorMatrix<SC::Challenge>,
    perm_challenges: &[SC::Challenge],
) where
    Val<SC>: PrimeField32,
    A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
{
    assert_eq!(main.height(), perm.height());
    let height = main.height();
    if height == 0 {
        return;
    }

    let cumulative_sum = perm.row_slice(perm.height() - 1).last().copied().unwrap();

    // Check that constraints are satisfied.
    (0..height).for_each(|i| {
        let i_next = (i + 1) % height;

        let main_local = main.row_slice(i);
        let main_next = main.row_slice(i_next);
        let preprocessed_local = if let Some(preprocessed) = preprocessed {
            preprocessed.row_slice(i)
        } else {
            &[]
        };
        let preprocessed_next = if let Some(preprocessed) = preprocessed {
            preprocessed.row_slice(i_next)
        } else {
            &[]
        };
        let perm_local = perm.row_slice(i);
        let perm_next = perm.row_slice(i_next);

        let mut builder = DebugConstraintBuilder {
            preprocessed: TwoRowMatrixView {
                local: preprocessed_local,
                next: preprocessed_next,
            },
            main: TwoRowMatrixView {
                local: main_local,
                next: main_next,
            },
            perm: TwoRowMatrixView {
                local: perm_local,
                next: perm_next,
            },
            perm_challenges,
            cumulative_sum,
            is_first_row: Val::<SC>::zero(),
            is_last_row: Val::<SC>::zero(),
            is_transition: Val::<SC>::one(),
        };
        if i == 0 {
            builder.is_first_row = Val::<SC>::one();
        }
        if i == height - 1 {
            builder.is_last_row = Val::<SC>::one();
            builder.is_transition = Val::<SC>::zero();
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            chip.eval(&mut builder);
        }));
        if result.is_err() {
            println!("local: {:?}", main_local);
            println!("next:  {:?}", main_next);
            panic!("failed at row {} of chip {}", i, chip.name());
        }
    });
}

/// Checks that all the interactions between the chips has been satisfied.
///
/// Note that this does not actually verify the proof.
pub fn debug_cumulative_sums<F: Field, EF: ExtensionField<F>>(perms: &[RowMajorMatrix<EF>]) {
    let sum: EF = perms
        .iter()
        .map(|perm| *perm.row_slice(perm.height() - 1).last().unwrap())
        .sum();
    assert_eq!(sum, EF::zero());
}

/// A builder for debugging constraints.
pub struct DebugConstraintBuilder<'a, F: Field, EF: ExtensionField<F>> {
    pub(crate) preprocessed: TwoRowMatrixView<'a, F>,
    pub(crate) main: TwoRowMatrixView<'a, F>,
    pub(crate) perm: TwoRowMatrixView<'a, EF>,
    pub(crate) cumulative_sum: EF,
    pub(crate) perm_challenges: &'a [EF],
    pub(crate) is_first_row: F,
    pub(crate) is_last_row: F,
    pub(crate) is_transition: F,
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
    type MP = TwoRowMatrixView<'a, EF>;

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
        let f: F = x.into();
        if f != F::zero() {
            let backtrace = std::backtrace::Backtrace::force_capture();
            panic!("constraint failed: {}", backtrace);
        }
    }
}

impl<'a, F, EF> MultiTableAirBuilder for DebugConstraintBuilder<'a, F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    type Sum = EF;

    fn cumulative_sum(&self) -> Self::Sum {
        self.cumulative_sum
    }
}

impl<'a, F: Field, EF: ExtensionField<F>> EmptyMessageBuilder
    for DebugConstraintBuilder<'a, F, EF>
{
}
