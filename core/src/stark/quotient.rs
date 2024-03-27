use super::folder::ProverConstraintFolder;
use super::Chip;
use super::Domain;
use super::PackedChallenge;
use super::PackedVal;
use super::StarkAir;
use super::Val;
use p3_air::Air;
use p3_air::TwoRowMatrixView;
use p3_commit::PolynomialSpace;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::PackedValue;
use p3_matrix::MatrixGet;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use super::StarkGenericConfig;

#[allow(clippy::too_many_arguments)]
pub fn quotient_values<SC, A, Mat>(
    chip: &Chip<Val<SC>, A>,
    cumulative_sum: SC::Challenge,
    trace_domain: Domain<SC>,
    quotient_domain: Domain<SC>,
    main_trace_on_quotient_domain: Mat,
    permutation_trace_on_quotient_domain: Mat,
    perm_challenges: &[SC::Challenge],
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    A: StarkAir<SC>,
    SC: StarkGenericConfig,
    Mat: MatrixGet<Val<SC>> + Sync,
{
    let quotient_size = quotient_domain.size();
    let main_width = main_trace_on_quotient_domain.width();
    let perm_width = permutation_trace_on_quotient_domain.width();
    let sels = trace_domain.selectors_on_coset(quotient_domain);

    let qdb = log2_strict_usize(quotient_domain.size()) - log2_strict_usize(trace_domain.size());
    let next_step = 1 << qdb;

    let ext_degree = SC::Challenge::D;

    assert!(quotient_size >= PackedVal::<SC>::WIDTH);

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
            let mut folder = ProverConstraintFolder {
                preprocessed: TwoRowMatrixView {
                    local: &[],
                    next: &[],
                },
                main: TwoRowMatrixView {
                    local: &local,
                    next: &next,
                },
                perm: TwoRowMatrixView {
                    local: &perm_local,
                    next: &perm_next,
                },
                perm_challenges,
                cumulative_sum,
                is_first_row,
                is_last_row,
                is_transition,
                alpha,
                accumulator,
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
