use super::folder::ProverConstraintFolder;
use super::Chip;
use super::PackedChallenge;
use super::PackedVal;
use super::StarkAir;
use p3_air::Air;
use p3_air::TwoRowMatrixView;
use p3_commit::UnivariatePcsWithLde;
use p3_field::AbstractExtensionField;
use p3_field::AbstractField;
use p3_field::PackedValue;
use p3_field::{cyclic_subgroup_coset_known_order, Field, TwoAdicField};
use p3_matrix::MatrixGet;
use p3_maybe_rayon::prelude::*;

use super::{zerofier_coset::ZerofierOnCoset, StarkGenericConfig};

#[allow(clippy::too_many_arguments)]
pub fn quotient_values<SC, A, MainLde, PermLde>(
    config: &SC,
    chip: &Chip<SC::Val, A>,
    cumulative_sum: SC::Challenge,
    degree_bits: usize,
    main_lde: &MainLde,
    permutation_lde: &PermLde,
    perm_challenges: &[SC::Challenge],
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    A: StarkAir<SC>,
    SC: StarkGenericConfig,
    SC::Val: TwoAdicField,
    MainLde: MatrixGet<SC::Val> + Sync,
    PermLde: MatrixGet<SC::Val> + Sync,
{
    let degree = 1 << degree_bits;
    let quotient_degree_bits = chip.log_quotient_degree();
    let quotient_size_bits = degree_bits + quotient_degree_bits;
    let quotient_size = 1 << quotient_size_bits;
    let g_subgroup = SC::Val::two_adic_generator(degree_bits);
    let g_extended = SC::Val::two_adic_generator(quotient_size_bits);
    let subgroup_last = g_subgroup.inverse();
    let coset_shift = config.pcs().coset_shift();
    let next_step = 1 << quotient_degree_bits;

    let coset: Vec<_> =
        cyclic_subgroup_coset_known_order(g_extended, coset_shift, quotient_size).collect();

    let zerofier_on_coset = ZerofierOnCoset::new(degree_bits, quotient_degree_bits, coset_shift);

    // Evaluations of L_first(x) = Z_H(x) / (x - 1) on our coset s H.
    let lagrange_first_evals = zerofier_on_coset.lagrange_basis_unnormalized(0);
    let lagrange_last_evals = zerofier_on_coset.lagrange_basis_unnormalized(degree - 1);

    let ext_degree = SC::Challenge::D;

    (0..quotient_size)
        .into_par_iter()
        .step_by(PackedVal::<SC>::WIDTH)
        .flat_map_iter(|i_local_start| {
            let wrap = |i| i % quotient_size;
            let i_next_start = wrap(i_local_start + next_step);
            let i_range = i_local_start..i_local_start + PackedVal::<SC>::WIDTH;

            let x = *PackedVal::<SC>::from_slice(&coset[i_range.clone()]);
            let is_transition = x - subgroup_last;
            let is_first_row = *PackedVal::<SC>::from_slice(&lagrange_first_evals[i_range.clone()]);
            let is_last_row = *PackedVal::<SC>::from_slice(&lagrange_last_evals[i_range]);

            let local: Vec<_> = (0..main_lde.width())
                .map(|col| {
                    PackedVal::<SC>::from_fn(|offset| {
                        let row = wrap(i_local_start + offset);
                        main_lde.get(row, col)
                    })
                })
                .collect();
            let next: Vec<_> = (0..main_lde.width())
                .map(|col| {
                    PackedVal::<SC>::from_fn(|offset| {
                        let row = wrap(i_next_start + offset);
                        main_lde.get(row, col)
                    })
                })
                .collect();

            let perm_local: Vec<_> = (0..permutation_lde.width())
                .step_by(ext_degree)
                .map(|col| {
                    PackedChallenge::<SC>::from_base_fn(|i| {
                        PackedVal::<SC>::from_fn(|offset| {
                            let row = wrap(i_local_start + offset);
                            permutation_lde.get(row, col + i)
                        })
                    })
                })
                .collect();

            let perm_next: Vec<_> = (0..permutation_lde.width())
                .step_by(ext_degree)
                .map(|col| {
                    PackedChallenge::<SC>::from_base_fn(|i| {
                        PackedVal::<SC>::from_fn(|offset| {
                            let row = wrap(i_next_start + offset);
                            permutation_lde.get(row, col + i)
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
            let zerofier_inv: PackedVal<SC> = zerofier_on_coset.eval_inverse_packed(i_local_start);
            let quotient = folder.accumulator * zerofier_inv;

            // "Transpose" D packed base coefficients into WIDTH scalar extension coefficients.
            (0..PackedVal::<SC>::WIDTH).map(move |idx_in_packing| {
                let quotient_value = (0..<SC::Challenge as AbstractExtensionField<SC::Val>>::D)
                    .map(|coeff_idx| quotient.as_base_slice()[coeff_idx].as_slice()[idx_in_packing])
                    .collect::<Vec<_>>();
                SC::Challenge::from_base_slice(&quotient_value)
            })
        })
        .collect()
}
