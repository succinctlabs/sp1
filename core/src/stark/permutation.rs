use itertools::Itertools;
use p3_air::{ExtensionBuilder, PairBuilder};
use p3_field::{
    AbstractExtensionField, AbstractField, ExtensionField, Field, PackedValue, Powers, PrimeField,
};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use std::borrow::Borrow;

use crate::{air::MultiTableAirBuilder, lookup::Interaction};

/// Generates powers of a random element based on how many interactions there are in the chip.
///
/// These elements are used to uniquely fingerprint each interaction.
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

#[allow(clippy::too_many_arguments)]
pub fn populate_permutation_row<F: PrimeField, EF: ExtensionField<F>>(
    row: &mut [EF],
    preprocessed_row: &[F],
    main_row: &[F],
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    alphas: &[EF],
    betas: Powers<EF>,
    batch_size: usize,
) {
    let interaction_chunks = &sends
        .iter()
        .map(|int| (int, true))
        .chain(receives.iter().map(|int| (int, false)))
        .chunks(batch_size);
    let num_chunks = (sends.len() + receives.len() + 1) / batch_size;
    assert_eq!(num_chunks + 1, row.len());
    // Compute the denominators \prod_{i\in B} row_fingerprint(alpha, beta).
    for (value, chunk) in row.iter_mut().zip(interaction_chunks) {
        *value = chunk
            .into_iter()
            .map(|(interaction, is_send)| {
                let alpha = alphas[interaction.argument_index()];
                let mut denominator = alpha;
                for (columns, beta) in interaction.values.iter().zip(betas.clone()) {
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

/// Generates the permutation trace for the given chip and main trace based on a variant of LogUp.
///
/// The permutation trace has (N+1)*EF::NUM_COLS columns, where N is the number of interactions in
/// the chip.
pub(crate) fn generate_permutation_trace<F: PrimeField, EF: ExtensionField<F>>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    preprocessed: Option<&RowMajorMatrix<F>>,
    mut main: &mut RowMajorMatrix<F>,
    random_elements: &[EF],
    batch_size: usize,
) -> RowMajorMatrix<EF> {
    // Generate the RLC elements to uniquely identify each interaction.
    let alphas = generate_interaction_rlc_elements(sends, receives, random_elements[0]);

    // Generate the RLC elements to uniquely identify each item in the looked up tuple.
    let betas = random_elements[1].powers();

    // Iterate over the rows of the main trace to compute the permutation trace values. In
    // particular, for each row i, interaction j, and columns c_0, ..., c_{k-1} we compute the sum:
    //
    // permutation_trace_values[i][j] = \alpha^j + \sum_k \beta^k * f_{i, c_k}
    //
    // where f_{i, c_k} is the value at row i for column c_k. The computed value is essentially a
    // fingerprint for the interaction.
    let chunk_rate = 1 << 8;
    let permutation_trace_width = (sends.len() + receives.len() + 1) / batch_size + 1;
    let height = main.height();

    let mut permutation_trace = RowMajorMatrix::new(
        vec![EF::zero(); permutation_trace_width * height],
        permutation_trace_width,
    );

    // Compute the permutation trace values in parallel.

    match preprocessed {
        Some(prep) => {
            (&mut permutation_trace)
                .par_row_chunks_mut(chunk_rate)
                .zip_eq(prep.clone().par_row_chunks_mut(chunk_rate))
                .zip_eq((&mut main).par_row_chunks_mut(chunk_rate))
                .for_each(|((mut chunk, prep_rows_chunk), main_rows_chunk)| {
                    chunk
                        .rows_mut()
                        .zip(prep_rows_chunk.rows())
                        .zip(main_rows_chunk.rows())
                        .for_each(|((row, prep_row), main_row)| {
                            populate_permutation_row(
                                row,
                                prep_row.collect::<Vec<_>>().as_slice(),
                                main_row.collect::<Vec<_>>().as_slice(),
                                sends,
                                receives,
                                &alphas,
                                betas.clone(),
                                batch_size,
                            )
                        })
                });
            // Compute the permutation trace values for the remainder.
            let remainder = height % chunk_rate;
            for i in 0..remainder {
                let index = height - remainder + i;
                populate_permutation_row(
                    permutation_trace.row_mut(index),
                    &(*prep.row_slice(index)),
                    &(*main.row_slice(index)),
                    sends,
                    receives,
                    &alphas,
                    betas.clone(),
                    batch_size,
                );
            }
        }
        None => {
            permutation_trace
                .par_row_chunks_mut(chunk_rate)
                .zip_eq(main.par_row_chunks_mut(chunk_rate))
                .for_each(|(mut chunk, main_rows_chunk)| {
                    chunk
                        .rows_mut()
                        .zip(main_rows_chunk.rows())
                        .for_each(|(row, main_row)| {
                            populate_permutation_row(
                                row,
                                &[],
                                main_row.collect::<Vec<_>>().as_slice(),
                                sends,
                                receives,
                                &alphas,
                                betas.clone(),
                                batch_size,
                            )
                        })
                });
            // Compute the permutation trace values for the remainder.
            let remainder = height % chunk_rate;
            for i in 0..remainder {
                let index = height - remainder + i;
                populate_permutation_row(
                    permutation_trace.row_mut(index),
                    &[],
                    &(*main.row_slice(index)),
                    sends,
                    receives,
                    &alphas,
                    betas.clone(),
                    batch_size,
                );
            }
        }
    }

    // Write the cumultative sum.
    let mut cumulative_sum = EF::zero();
    for permutation_row in permutation_trace.as_view_mut().rows_mut() {
        cumulative_sum += permutation_row[0..permutation_trace_width - 1]
            .iter()
            .copied()
            .sum::<EF>();
        *permutation_row.last_mut().unwrap() = cumulative_sum;
    }

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
    let main_local = main.row_slice(0);
    let main_local: &[AB::Var] = (*main_local).borrow();

    let preprocessed = builder.preprocessed();
    let preprocessed_local = preprocessed.row_slice(0);

    let perm = builder.permutation();
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
    for (entry, chunk) in perm_local.iter().zip(interaction_chunks) {
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
