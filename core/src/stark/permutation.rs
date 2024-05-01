use std::borrow::Borrow;

use itertools::Itertools;
use p3_air::{ExtensionBuilder, PairBuilder};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, PackedValue, Powers};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use rayon_scan::ScanParallelIterator;

use crate::{air::MultiTableAirBuilder, lookup::Interaction};

use super::{
    util::batch_multiplicative_inverse_inplace, PackedChallenge, PackedVal, StarkGenericConfig,
};

/// Generates powers of a random element based on how many interactions there are in the chip.
///
/// These elements are used to uniquely fingerprint each interaction.
#[inline]
pub fn generate_interaction_rlc_elements<F: Field, AF: AbstractField>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    random_element: AF,
) -> Vec<AF> {
    let n = sends
        .iter()
        .chain(receives.iter())
        .map(|interaction| interaction.argument_index())
        .max()
        .unwrap_or(0)
        + 1;
    random_element.powers().skip(1).take(n).collect::<Vec<_>>()
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn populate_batch_and_mult<SC: StarkGenericConfig>(
    row: &[PackedChallenge<SC>],
    new_row: &mut [PackedChallenge<SC>],
    sends: &[Interaction<SC::Val>],
    receives: &[Interaction<SC::Val>],
    preprocessed_row: &[PackedVal<SC>],
    main_row: &[PackedVal<SC>],
    batch_size: usize,
) {
    let interaction_chunks = &sends
        .iter()
        .map(|int| (int, true))
        .chain(receives.iter().map(|int| (int, false)))
        .chunks(batch_size);
    let num_chunks = (sends.len() + receives.len() + 1) / batch_size;
    debug_assert_eq!(num_chunks + 1, new_row.len());
    // Compute the denominators \prod_{i\in B} row_fingerprint(alpha, beta).
    for ((value, row_chunk), interaction_chunk) in new_row
        .iter_mut()
        .zip(&row.iter().chunks(batch_size))
        .zip(interaction_chunks)
    {
        *value = row_chunk
            .into_iter()
            .zip(interaction_chunk.into_iter())
            .map(|(val, interaction_info)| {
                let (interaction, is_send) = interaction_info;
                let mut mult = interaction
                    .multiplicity
                    .apply::<PackedVal<SC>, PackedVal<SC>>(preprocessed_row, main_row);
                if !is_send {
                    mult = -mult;
                }
                PackedChallenge::<SC>::from_base(mult) * *val
            })
            .sum();
    }
}

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn populate_prepermutation_row<SC: StarkGenericConfig>(
    row: &mut [PackedChallenge<SC>],
    preprocessed_row: &[PackedVal<SC>],
    main_row: &[PackedVal<SC>],
    sends: &[Interaction<SC::Val>],
    receives: &[Interaction<SC::Val>],
    alphas: &[SC::Challenge],
    betas: Powers<SC::Challenge>,
) {
    let interaction_info = sends.iter().chain(receives.iter());
    // Compute the denominators \prod_{i\in B} row_fingerprint(alpha, beta).
    for (value, interaction) in row.iter_mut().zip(interaction_info) {
        *value = {
            let alpha = alphas[interaction.argument_index()];
            let packed_alpha = PackedChallenge::<SC>::from_f(alpha);
            let mut denominator = packed_alpha;
            for (columns, beta) in interaction.values.iter().zip(betas.clone()) {
                denominator += PackedChallenge::<SC>::from_f(beta)
                    * columns.apply::<PackedVal<SC>, PackedVal<SC>>(preprocessed_row, main_row)
            }

            denominator
        };
    }
}

#[inline]
pub const fn permutation_trace_width(num_interactions: usize, batch_size: usize) -> usize {
    num_interactions.div_ceil(batch_size) + 1
}

/// Generates the permutation trace for the given chip and main trace based on a variant of LogUp.
///
/// The permutation trace has (N+1)*EF::NUM_COLS columns, where N is the number of interactions in
/// the chip.
pub(crate) fn generate_permutation_trace<SC: StarkGenericConfig>(
    sends: &[Interaction<SC::Val>],
    receives: &[Interaction<SC::Val>],
    preprocessed: Option<&RowMajorMatrix<SC::Val>>,
    main: &mut RowMajorMatrix<SC::Val>,
    random_elements: &[SC::Challenge],
    batch_size: usize,
) -> RowMajorMatrix<SC::Challenge> {
    // Generate the RLC elements to uniquely identify each interaction.
    let alphas = generate_interaction_rlc_elements(sends, receives, random_elements[0]);
    let chunk_rate = 1 << 8;
    // Generate the RLC elements to uniquely identify each item in the looked up tuple.
    let betas = random_elements[1].powers();

    // Iterate over the rows of the main trace to compute the permutation trace values. In
    // particular, for each row i, interaction j, and columns c_0, ..., c_{k-1} we compute the sum:
    //
    // permutation_trace_values[i][j] = \alpha^j + \sum_k \beta^k * f_{i, c_k}
    //
    // where f_{i, c_k} is the value at row i for column c_k. The computed value is essentially a
    // fingerprint for the interaction.
    let permutation_trace_width = permutation_trace_width(sends.len() + receives.len(), batch_size);
    let height = main.height();

    let prepermutation_trace_width = sends.len() + receives.len();

    let mut prepermutation_trace = RowMajorMatrix::new(
        vec![
            PackedChallenge::<SC>::zero();
            prepermutation_trace_width * (height.div_ceil(PackedVal::<SC>::WIDTH))
        ],
        prepermutation_trace_width,
    );

    let mut permutation_trace: RowMajorMatrix<PackedChallenge<SC>> = RowMajorMatrix::new(
        vec![
            PackedChallenge::<SC>::zero();
            permutation_trace_width * (height.div_ceil(PackedVal::<SC>::WIDTH))
        ],
        permutation_trace_width,
    );

    // Compute the permutation trace values in parallel.

    match preprocessed {
        Some(prep) => {
            prepermutation_trace
                .par_rows_mut()
                .zip_eq(
                    (0..height)
                        .into_par_iter()
                        .step_by(PackedVal::<SC>::WIDTH)
                        .map(|r| prep.vertically_packed_row::<PackedVal<SC>>(r)),
                )
                .zip_eq(
                    (0..height)
                        .into_par_iter()
                        .step_by(PackedVal::<SC>::WIDTH)
                        .map(|r| main.vertically_packed_row::<PackedVal<SC>>(r)),
                )
                .for_each(|((row, prep_row), main_row)| {
                    populate_prepermutation_row::<SC>(
                        row,
                        prep_row.collect::<Vec<_>>().as_slice(),
                        main_row.collect::<Vec<_>>().as_slice(),
                        sends,
                        receives,
                        &alphas,
                        betas.clone(),
                    )
                });
        }
        None => {
            prepermutation_trace
                .par_rows_mut()
                .zip_eq(
                    (0..height)
                        .into_par_iter()
                        .step_by(PackedVal::<SC>::WIDTH)
                        .map(|r| main.vertically_packed_row(r)),
                )
                .for_each(|(row, main_row)| {
                    populate_prepermutation_row::<SC>(
                        row,
                        &[],
                        main_row.collect::<Vec<_>>().as_slice(),
                        sends,
                        receives,
                        &alphas,
                        betas.clone(),
                    )
                });
        }
    }
    // Unpack the prepermutation trace values. Since the elements of the trace are extension field elements over a PackedField, and we want to have unpacked extension field elements, we need to turn each extension field element into a vector of packed field elements, then unpack those field elements, and finally turn the unpacked field elements into an unpacked extension field element.
    let mut unpacked_prepermutation_trace = prepermutation_trace
        .par_rows()
        .map(|row| {
            row.map(|elem| {
                (0..PackedVal::<SC>::WIDTH)
                    .map(move |idx_in_packing| {
                        let unpacked_val =
                            (0..<SC::Challenge as AbstractExtensionField<SC::Val>>::D)
                                .map(|coeff_idx| {
                                    elem.as_base_slice()[coeff_idx].as_slice()[idx_in_packing]
                                })
                                .collect::<Vec<_>>();
                        SC::Challenge::from_base_slice(&unpacked_val)
                    })
                    .collect::<Vec<SC::Challenge>>()
            })
            .flatten()
            .collect::<Vec<SC::Challenge>>()
        })
        .flatten()
        .collect::<Vec<SC::Challenge>>();

    println!(
        "Unpacked length: {}; Needed Length: {}",
        unpacked_prepermutation_trace.len(),
        height * prepermutation_trace_width
    );

    // Compute the inverses of the denominators in the permutation trace.
    unpacked_prepermutation_trace
        .par_chunks_mut(chunk_rate)
        .for_each(|chunk| batch_multiplicative_inverse_inplace(chunk));

    // Repack the permutation trace values.
    prepermutation_trace = RowMajorMatrix::new(
        (0..unpacked_prepermutation_trace.clone().len())
            .step_by(PackedVal::<SC>::WIDTH)
            .map(|col| {
                PackedChallenge::<SC>::from_base_fn(|i| {
                    PackedVal::<SC>::from_fn(|offset| {
                        unpacked_prepermutation_trace[col + offset].as_base_slice()[i]
                    })
                })
            })
            .collect(),
        prepermutation_trace_width,
    );
    match preprocessed {
        Some(prep) => prepermutation_trace
            .par_rows_mut()
            .zip_eq(
                (0..height)
                    .into_par_iter()
                    .step_by(PackedVal::<SC>::WIDTH)
                    .map(|r| prep.vertically_packed_row::<PackedVal<SC>>(r)),
            )
            .zip_eq(
                (0..height)
                    .into_par_iter()
                    .step_by(PackedVal::<SC>::WIDTH)
                    .map(|r| main.vertically_packed_row::<PackedVal<SC>>(r)),
            )
            .zip_eq(permutation_trace.par_rows_mut())
            .for_each(|(((row, prep_row), main_row), new_row)| {
                populate_batch_and_mult::<SC>(
                    row,
                    new_row,
                    sends,
                    receives,
                    prep_row.collect::<Vec<_>>().as_slice(),
                    main_row.collect::<Vec<_>>().as_slice(),
                    batch_size,
                )
            }),
        None => prepermutation_trace
            .par_rows_mut()
            .zip_eq(
                (0..height)
                    .into_par_iter()
                    .step_by(PackedVal::<SC>::WIDTH)
                    .map(|r| main.vertically_packed_row::<PackedVal<SC>>(r)),
            )
            .zip_eq(permutation_trace.par_rows_mut())
            .for_each(|((row, main_row), new_row)| {
                populate_batch_and_mult::<SC>(
                    row,
                    new_row,
                    sends,
                    receives,
                    &[],
                    main_row.collect::<Vec<_>>().as_slice(),
                    batch_size,
                )
            }),
    }

    let zero = PackedChallenge::<SC>::zero();
    let cumulative_sums = permutation_trace
        .par_rows_mut()
        .map(|row| {
            row[0..permutation_trace_width - 1]
                .iter()
                .copied()
                .sum::<PackedChallenge<SC>>()
        })
        .collect::<Vec<_>>();

    let cumulative_sums = cumulative_sums
        .into_par_iter()
        .scan(|a, b| *a + *b, zero)
        .collect::<Vec<_>>();

    permutation_trace
        .par_rows_mut()
        .zip_eq(cumulative_sums.into_par_iter())
        .for_each(|(row, cumulative_sum)| {
            *row.last_mut().unwrap() = cumulative_sum;
        });

    println!(
        "Permutation trace length: {}, Needed Length: {}",
        permutation_trace.values.len(),
        height * permutation_trace_width
    );
    let unpacked_permutation_trace = permutation_trace
        .par_rows()
        .map(|row| {
            row.map(|elem| {
                (0..PackedVal::<SC>::WIDTH)
                    .map(move |idx_in_packing| {
                        let unpacked_val =
                            (0..<SC::Challenge as AbstractExtensionField<SC::Val>>::D)
                                .map(|coeff_idx| {
                                    elem.as_base_slice()[coeff_idx].as_slice()[idx_in_packing]
                                })
                                .collect::<Vec<_>>();
                        SC::Challenge::from_base_slice(&unpacked_val)
                    })
                    .collect::<Vec<SC::Challenge>>()
            })
            .flatten()
            .collect::<Vec<SC::Challenge>>()
        })
        .flatten()
        .collect::<Vec<SC::Challenge>>();
    println!(
        "Permutation trace size: {}, Needed Length: {}",
        unpacked_permutation_trace.len(),
        height * permutation_trace_width
    );
    RowMajorMatrix::new(unpacked_permutation_trace, permutation_trace_width)
}

/// Evaluates the permutation constraints for the given chip.
///
/// In particular, the constraints checked here are:
///     - The running sum column starts at zero.
///     - That the RLC per interaction is computed correctly.
///     - The running sum column ends at the (currently) given cumalitive sum.
pub fn eval_permutation_constraints<F, AB>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    batch_size: usize,
    builder: &mut AB,
) where
    F: Field,
    AB::EF: ExtensionField<F>,
    AB: MultiTableAirBuilder<F = F> + PairBuilder,
{
    let random_elements = builder.permutation_randomness();
    let (alpha, beta): (AB::ExprEF, AB::ExprEF) =
        (random_elements[0].into(), random_elements[1].into());

    let main = builder.main();
    let main_local = main.to_row_major_matrix();
    let main_local = main_local.row_slice(0);
    let main_local: &[AB::Var] = (*main_local).borrow();

    let preprocessed = builder.preprocessed();
    let preprocessed_local = preprocessed.row_slice(0);

    let perm = builder.permutation().to_row_major_matrix();
    let perm_width = perm.width();
    let perm_local = perm.row_slice(0);
    let perm_local: &[AB::VarEF] = (*perm_local).borrow();
    let perm_next = perm.row_slice(1);
    let perm_next: &[AB::VarEF] = (*perm_next).borrow();

    let alphas = generate_interaction_rlc_elements(sends, receives, alpha);
    let betas = beta.powers();

    // Ensure that each batch sum m_i/f_i is computed correctly.
    let interaction_chunks = &sends
        .iter()
        .map(|int| (int, true))
        .chain(receives.iter().map(|int| (int, false)))
        .chunks(batch_size);

    assert_eq!(
        interaction_chunks.into_iter().count(),
        perm_width - 1,
        "Number of sends: {}, receives: {}, batch size: {}, perm width: {}",
        sends.len(),
        receives.len(),
        batch_size,
        perm_width - 1
    );
    assert_eq!(
        perm_width,
        permutation_trace_width(sends.len() + receives.len(), batch_size)
    );

    for (entry, chunk) in perm_local[0..perm_local.len() - 1]
        .iter()
        .zip(interaction_chunks)
    {
        // Assert that the i-eth entry is equal to the sum_i m_i/rlc_i by constraints:
        // entry * \prod_i rlc_i = \sum_i m_i * \prod_{j!=i} rlc_j.

        // First, we calculate the random linear combinations and multiplicities with the correct
        // sign depending on wetther the interaction is a send or a recieve.
        let mut rlcs: Vec<AB::ExprEF> = Vec::with_capacity(batch_size);
        let mut multiplicities: Vec<AB::Expr> = Vec::with_capacity(batch_size);
        for (interaction, is_send) in chunk {
            let mut rlc = AB::ExprEF::zero();
            for (field, beta) in interaction.values.iter().zip(betas.clone()) {
                let elem = field.apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local);
                rlc += beta * elem;
            }
            rlc += alphas[interaction.argument_index()].clone();
            rlcs.push(rlc);

            let send_factor = if is_send { AB::F::one() } else { -AB::F::one() };
            multiplicities.push(
                interaction
                    .multiplicity
                    .apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local)
                    * send_factor,
            );
        }

        // Now we can calculate the numerator and denominator of the combined batch.
        let mut product = AB::ExprEF::one();
        let mut numerator = AB::ExprEF::zero();
        for (i, (m, rlc)) in multiplicities.into_iter().zip(rlcs.iter()).enumerate() {
            // Calculate the running product of all rlcs.
            product *= rlc.clone();
            // Calculate the product of all but the current rlc.
            let mut all_but_current = AB::ExprEF::one();
            for other_rlc in rlcs
                .iter()
                .enumerate()
                .filter(|(j, _)| i != *j)
                .map(|(_, rlc)| rlc)
            {
                all_but_current *= other_rlc.clone();
            }
            numerator += AB::ExprEF::from_base(m) * all_but_current;
        }

        // Finally, assert that the entry is equal to the numerator divided by the product.
        let entry: AB::ExprEF = (*entry).into();
        builder.assert_eq_ext(product.clone() * entry.clone(), numerator);
    }

    let sum_local = perm_local[..perm_width - 1]
        .iter()
        .map(|x| (*x).into())
        .sum::<AB::ExprEF>();

    let sum_next = perm_next[..perm_width - 1]
        .iter()
        .map(|x| (*x).into())
        .sum::<AB::ExprEF>();

    let phi_local: AB::ExprEF = (*perm_local.last().unwrap()).into();
    let phi_next: AB::ExprEF = (*perm_next.last().unwrap()).into();
    builder
        .when_transition()
        .assert_eq_ext(phi_next - phi_local.clone(), sum_next);

    builder.when_first_row().assert_eq_ext(phi_local, sum_local);

    let cumulative_sum = builder.cumulative_sum();
    builder
        .when_last_row()
        .assert_eq_ext(*perm_local.last().unwrap(), cumulative_sum);
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_field::PackedValue;

    use crate::stark::PackedVal;
    use crate::utils::BabyBearPoseidon2;

    #[test]
    fn test_packed() {
        let a = vec![BabyBear::one(); 4];
        let b = vec![BabyBear::two(); 4];
        let packed_a = PackedVal::<BabyBearPoseidon2>::from_slice(&a);
        let packed_b = PackedVal::<BabyBearPoseidon2>::from_slice(&b);
        let packed_c = *packed_a + *packed_b;
        println!("{:?}", packed_c);
    }
}
