use p3_air::{Air, BaseAir, TwoRowMatrixView};
use p3_field::{ExtensionField, Field, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices};

mod config;
pub mod debug;
pub(crate) mod folder;
pub(crate) mod permutation;
mod prover;
pub mod runtime;
pub mod types;
pub mod util;
mod verifier;
pub mod zerofier_coset;

pub use config::*;
pub use debug::*;
pub use types::*;
pub use verifier::{VerificationError, Verifier};

#[cfg(test)]
pub use runtime::tests;

use crate::{stark::permutation::eval_permutation_constraints, utils::Chip};

/// Checks that the constraints of the given AIR are satisfied, including the permutation trace.
///
/// Note that this does not actually verify the proof.
pub fn debug_constraints<F: PrimeField, EF: ExtensionField<F>, A>(
    air: &A,
    main: &RowMajorMatrix<F>,
    perm: &RowMajorMatrix<EF>,
    perm_challenges: &[EF],
) where
    A: for<'a> Air<DebugConstraintBuilder<'a, F, EF>> + BaseAir<F> + Chip<F> + ?Sized,
{
    assert_eq!(main.height(), perm.height());
    let height = main.height();
    if height == 0 {
        return;
    }

    let preprocessed = air.preprocessed_trace();

    let cumulative_sum = *perm.row_slice(perm.height() - 1).last().unwrap();

    // Check that constraints are satisfied.
    (0..height).for_each(|i| {
        let i_next = (i + 1) % height;

        let main_local = main.row_slice(i);
        let main_next = main.row_slice(i_next);
        let preprocessed_local = if preprocessed.is_some() {
            preprocessed.as_ref().unwrap().row_slice(i)
        } else {
            &[]
        };
        let preprocessed_next = if preprocessed.is_some() {
            preprocessed.as_ref().unwrap().row_slice(i_next)
        } else {
            &[]
        };
        let perm_local = perm.row_slice(i);
        let perm_next = perm.row_slice(i_next);

        let mut builder = DebugConstraintBuilder {
            main: TwoRowMatrixView {
                local: main_local,
                next: main_next,
            },
            preprocessed: TwoRowMatrixView {
                local: preprocessed_local,
                next: preprocessed_next,
            },
            perm: TwoRowMatrixView {
                local: perm_local,
                next: perm_next,
            },
            perm_challenges,
            is_first_row: F::zero(),
            is_last_row: F::zero(),
            is_transition: F::one(),
        };
        if i == 0 {
            builder.is_first_row = F::one();
        }
        if i == height - 1 {
            builder.is_last_row = F::one();
            builder.is_transition = F::zero();
        }

        air.eval(&mut builder);
        eval_permutation_constraints(air, &mut builder, cumulative_sum);
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
