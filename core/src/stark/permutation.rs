use std::borrow::Borrow;

use itertools::Itertools;
use p3_air::{ExtensionBuilder, PairBuilder};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Powers, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use rayon_scan::ScanParallelIterator;

use crate::{air::MultiTableAirBuilder, lookup::Interaction};

#[inline]
#[allow(clippy::too_many_arguments)]
pub fn populate_permutation_row<F: PrimeField, EF: ExtensionField<F>>(
    row: &mut [EF],
    preprocessed_row: &[F],
    main_row: &[F],
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    alpha: EF,
    betas: Powers<EF>,
    batch_size: usize,
) {
    let interaction_chunks = &sends
        .iter()
        .map(|int| (int, true))
        .chain(receives.iter().map(|int| (int, false)))
        .chunks(batch_size);
    // Compute the denominators \prod_{i\in B} row_fingerprint(alpha, beta).
    for (value, chunk) in row.iter_mut().zip(interaction_chunks) {
        *value = chunk
            .into_iter()
            .map(|(interaction, is_send)| {
                let mut denominator = alpha;
                let mut betas = betas.clone();
                denominator +=
                    betas.next().unwrap() * EF::from_canonical_usize(interaction.argument_index());
                for (columns, beta) in interaction.values.iter().zip(betas) {
                    denominator += beta * columns.apply::<F, F>(preprocessed_row, main_row)
                }
                let mut mult = interaction
                    .multiplicity
                    .apply::<F, F>(preprocessed_row, main_row);

                if !is_send {
                    mult = -mult;
                }

                EF::from_base(mult) / denominator
            })
            .sum();
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
pub(crate) fn generate_permutation_trace<F: PrimeField, EF: ExtensionField<F>>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    preprocessed: Option<&RowMajorMatrix<F>>,
    main: &RowMajorMatrix<F>,
    random_elements: &[EF],
    batch_size: usize,
) -> RowMajorMatrix<EF> {
    // Generate the RLC elements to uniquely identify each interaction.
    let alpha = random_elements[0];

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

    let mut permutation_trace = RowMajorMatrix::new(
        vec![EF::zero(); permutation_trace_width * height],
        permutation_trace_width,
    );

    // Compute the permutation trace values in parallel.

    match preprocessed {
        Some(prep) => {
            permutation_trace
                .par_rows_mut()
                .zip_eq(prep.par_row_slices())
                .zip_eq(main.par_row_slices())
                .for_each(|((row, prep_row), main_row)| {
                    populate_permutation_row(
                        row,
                        prep_row,
                        main_row,
                        sends,
                        receives,
                        alpha,
                        betas.clone(),
                        batch_size,
                    )
                });
        }
        None => {
            permutation_trace
                .par_rows_mut()
                .zip_eq(main.par_row_slices())
                .for_each(|(row, main_row)| {
                    populate_permutation_row(
                        row,
                        &[],
                        main_row,
                        sends,
                        receives,
                        alpha,
                        betas.clone(),
                        batch_size,
                    )
                });
        }
    }

    let zero = EF::zero();
    let cumulative_sums = permutation_trace
        .par_rows_mut()
        .map(|row| {
            row[0..permutation_trace_width - 1]
                .iter()
                .copied()
                .sum::<EF>()
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

    permutation_trace
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
            let mut rlc = alpha.clone();
            let mut betas = beta.powers();
            rlc += betas.next().unwrap()
                * AB::ExprEF::from_canonical_usize(interaction.argument_index());
            for (field, beta) in interaction.values.iter().zip(betas.clone()) {
                let elem = field.apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local);
                rlc += beta * elem;
            }
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
