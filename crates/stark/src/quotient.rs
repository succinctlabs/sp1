use p3_air::Air;
use p3_commit::PolynomialSpace;
use p3_field::{AbstractExtensionField, AbstractField, PackedValue};
use p3_matrix::{dense::RowMajorMatrixView, stack::VerticalPair, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use crate::air::MachineAir;

use super::{
    folder::ProverConstraintFolder, Chip, Domain, PackedChallenge, PackedVal, StarkGenericConfig,
    Val,
};

/// Computes the quotient values.
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn quotient_values<SC, A, Mat>(
    chip: &Chip<Val<SC>, A>,
    cumulative_sums: &[SC::Challenge],
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    preprocessed_trace_on_quotient_domain: Option<Mat>,
    main_trace_on_quotient_domain: Mat,
    permutation_trace_on_quotient_domain: Mat,
    perm_challenges: &[PackedChallenge<SC>],
    alpha: SC::Challenge,
    public_values: &[Val<SC>],
) -> Vec<SC::Challenge>
where
    A: for<'a> Air<ProverConstraintFolder<'a, SC>> + MachineAir<Val<SC>>,
    SC: StarkGenericConfig,
    Mat: Matrix<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let prep_width =
        preprocessed_trace_on_quotient_domain.as_ref().map_or(1, p3_matrix::Matrix::width);
    let main_width = main_trace_on_quotient_domain.width();
    let perm_width = permutation_trace_on_quotient_domain.width();
    let sels = trace_domain.selectors_on_coset(quotient_domain);

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    let ext_degree = SC::Challenge::D;

    assert!(
        quotient_size >= PackedVal::<SC>::WIDTH,
        "quotient size is too small: got {}, expected at least {} for chip {}",
        quotient_size,
        PackedVal::<SC>::WIDTH,
        chip.name()
    );

    (0..quotient_size)
        .into_par_iter()
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map_iter(|i_start| {
            let wrap = |i| i % quotient_size;
            let i_range = i_start..i_start + PackedVal::<SC>::WIDTH;

            let is_first_row = *PackedVal::<SC>::from_slice(&sels.is_first_row[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&sels.is_last_row[i_range.clone()]);
            let is_transition = *PackedVal::<SC>::from_slice(&sels.is_transition[i_range.clone()]);
            let inv_zeroifier = *PackedVal::<SC>::from_slice(&sels.inv_zeroifier[i_range.clone()]);

            let prep_local: Vec<_> = (0..prep_width)
                .map(|col| {
                    PackedVal::<SC>::from_fn(|offset| {
                        preprocessed_trace_on_quotient_domain
                            .as_ref()
                            .map_or(Val::<SC>::zero(), |x| x.get(wrap(i_start + offset), col))
                    })
                })
                .collect();
            let prep_next: Vec<_> = (0..prep_width)
                .map(|col| {
                    PackedVal::<SC>::from_fn(|offset| {
                        preprocessed_trace_on_quotient_domain
                            .as_ref()
                            .map_or(Val::<SC>::zero(), |x| {
                                x.get(wrap(i_start + next_step + offset), col)
                            })
                    })
                })
                .collect();

            let local: Vec<_> = (0..main_width)
                .map(|col| {
                    PackedVal::<SC>::from_fn(|offset| {
                        main_trace_on_quotient_domain.get(wrap(i_start + offset), col)
                    })
                })
                .collect();
            let next: Vec<_> = (0..main_width)
                .map(|col| {
                    PackedVal::<SC>::from_fn(|offset| {
                        main_trace_on_quotient_domain.get(wrap(i_start + next_step + offset), col)
                    })
                })
                .collect();

            let perm_local: Vec<_> = (0..perm_width)
                .step_by(ext_degree)
                .map(|col| {
                    PackedChallenge::<SC>::from_base_fn(|i| {
                        PackedVal::<SC>::from_fn(|offset| {
                            permutation_trace_on_quotient_domain
                                .get(wrap(i_start + offset), col + i)
                        })
                    })
                })
                .collect();

            let perm_next: Vec<_> = (0..perm_width)
                .step_by(ext_degree)
                .map(|col| {
                    PackedChallenge::<SC>::from_base_fn(|i| {
                        PackedVal::<SC>::from_fn(|offset| {
                            permutation_trace_on_quotient_domain
                                .get(wrap(i_start + next_step + offset), col + i)
                        })
                    })
                })
                .collect();

            let accumulator = PackedChallenge::<SC>::zero();

            let packed_cumulative_sums = cumulative_sums
                .iter()
                .map(|c| PackedChallenge::<SC>::from_f(*c))
                .collect::<Vec<_>>();

            let mut folder = ProverConstraintFolder {
                preprocessed: VerticalPair::new(
                    RowMajorMatrixView::new_row(&prep_local),
                    RowMajorMatrixView::new_row(&prep_next),
                ),
                main: VerticalPair::new(
                    RowMajorMatrixView::new_row(&local),
                    RowMajorMatrixView::new_row(&next),
                ),
                perm: VerticalPair::new(
                    RowMajorMatrixView::new_row(&perm_local),
                    RowMajorMatrixView::new_row(&perm_next),
                ),
                perm_challenges,
                cumulative_sums: &packed_cumulative_sums,
                is_first_row,
                is_last_row,
                is_transition,
                alpha,
                accumulator,
                public_values,
            };
            chip.eval(&mut folder);

            // quotient(x) = constraints(x) / Z_H(x)
            let quotient = folder.accumulator * inv_zeroifier;

            // "Transpose" D packed base coefficients into WIDTH scalar extension coefficients.
            (0..PackedVal::<SC>::WIDTH).map(move |idx_in_packing| {
                let quotient_value = (0..<SC::Challenge as AbstractExtensionField<Val<SC>>>::D)
                    .map(|coeff_idx| quotient.as_base_slice()[coeff_idx].as_slice()[idx_in_packing])
                    .collect::<Vec<_>>();
                SC::Challenge::from_base_slice(&quotient_value)
            })
        })
        .collect()
}
