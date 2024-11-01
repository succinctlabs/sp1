use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::PairBuilder;
use p3_field::{ExtensionField, Field, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;

use crate::{
    air::{InteractionScope, MultiTableAirBuilder},
    lookup::Interaction,
};

/// Computes the width of the local permutation trace in terms of extension field elements.
#[must_use]
pub const fn local_permutation_trace_width(nb_interactions: usize, batch_size: usize) -> usize {
    if nb_interactions == 0 {
        return 0;
    }

    (nb_interactions.div_ceil(batch_size) + 1) * 4
}

/// Computes the width of the global permutation trace in terms of base field elements.
///
/// For every interaction:
/// `| X=am+b (7 cols) | Y=decompress(X) (7 cols) | Padding (1 col) | (AccX, AccY) (14 cols) |`
#[must_use]
pub const fn global_permutation_trace_width(nb_interactions: usize) -> usize {
    if nb_interactions == 0 {
        return 0;
    }

    nb_interactions * 29
}

/// Populates a permutation row.
#[inline]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
pub fn populate_local_permutation_row<F: PrimeField, EF: ExtensionField<F>>(
    row: &mut [EF],
    preprocessed_row: &[F],
    main_row: &[F],
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    random_elements: &[EF],
    batch_size: usize,
) {
    let alpha = random_elements[0];
    let betas = random_elements[1].powers(); // TODO: optimize

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
                    denominator += beta * columns.apply::<F, F>(preprocessed_row, main_row);
                }
                let mut mult = interaction.multiplicity.apply::<F, F>(preprocessed_row, main_row);

                if !is_send {
                    mult = -mult;
                }

                EF::from_base(mult) / denominator
            })
            .sum();
    }
}

/// Populates a permutation row.
#[inline]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::needless_pass_by_value)]
pub fn populate_global_permutation_row<F: PrimeField, EF: ExtensionField<F>>(
    row: &mut [F],
    preprocessed_row: &[F],
    main_row: &[F],
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
) {
    let mut global_cumulative_sum_x = EF::zero();
    let mut global_cumulative_sum_y = EF::zero();
    let interactions = sends
        .iter()
        .map(|int| (int, true))
        .chain(receives.iter().map(|int| (int, false)))
        .collect_vec();

    // Create a row to write to the global permutation trace.
    let mut data: Vec<F> = Vec::new();

    for (interaction, is_send) in interactions.iter() {
        // Construct the message as a Fp7 element.
        let mut elements = interaction
            .values
            .iter()
            .map(|pair| pair.apply::<F, F>(preprocessed_row, main_row))
            .collect::<Vec<_>>();
        if elements.len() < EF::D {
            let padding = EF::D - elements.len();
            elements.extend(std::iter::repeat(F::zero()).take(padding));
        }
        let message = EF::from_base_slice(&elements);

        // Mix the message with the random elements to get the x-coordinate.
        //
        // TODO: Use actually random elements.
        let x = EF::from_canonical_u32(2) * message + EF::from_canonical_u32(1);

        // Decompress the elliptic curve point to get the y-coordinate.
        //
        // TODO: Implement the decompression.
        let y = x;

        // Update the cumulative sums based on the elliptic curve addition formulas.
        //
        // TODO: Actually use the elliptic curve addition formulas instead of
        // vectorized addition/subtraction.
        if *is_send {
            global_cumulative_sum_x += x;
            global_cumulative_sum_y += y;
        } else {
            global_cumulative_sum_x -= x;
            global_cumulative_sum_y -= y;
        }

        // Write the x-coordinate.
        data.extend(x.as_base_slice());

        // Write the y-coordinate.
        data.extend(x.as_base_slice());

        // Write the padding.
        data.push(F::zero());

        // Write the accumulated x-coordinate.
        data.extend(global_cumulative_sum_x.as_base_slice());

        // Write the accumulated y-coordinate.
        data.extend(global_cumulative_sum_y.as_base_slice());
    }

    // Copy the row to the global permutation trace.
    assert_eq!(row.len(), data.len(), "number of interactions: {}", interactions.len());
    row.copy_from_slice(&data);
}

/// Returns the sends, receives, and permutation trace width grouped by scope.
#[allow(clippy::type_complexity)]
pub fn scoped_interactions<F: Field>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
) -> (HashMap<InteractionScope, Vec<Interaction<F>>>, HashMap<InteractionScope, Vec<Interaction<F>>>)
{
    // Create a hashmap of scope -> vec<send interactions>.
    let mut sends = sends.to_vec();
    sends.sort_by_key(|k| k.scope);
    let grouped_sends: HashMap<_, _> = sends
        .iter()
        .chunk_by(|int| int.scope)
        .into_iter()
        .map(|(k, values)| (k, values.cloned().collect_vec()))
        .collect();

    // Create a hashmap of scope -> vec<receive interactions>.
    let mut receives = receives.to_vec();
    receives.sort_by_key(|k| k.scope);
    let grouped_receives: HashMap<_, _> = receives
        .iter()
        .chunk_by(|int| int.scope)
        .into_iter()
        .map(|(k, values)| (k, values.cloned().collect_vec()))
        .collect();

    (grouped_sends, grouped_receives)
}

/// Generates the permutation trace for the given chip and main trace based on a variant of `LogUp`.
///
/// The permutation trace has `(N+1)*EF::NUM_COLS` columns, where N is the number of interactions in
/// the chip.
#[allow(clippy::too_many_lines)]
pub fn generate_permutation_trace<F: PrimeField, EF4: ExtensionField<F>, EF7: ExtensionField<F>>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    preprocessed: Option<&RowMajorMatrix<F>>,
    main: &RowMajorMatrix<F>,
    random_elements: &[EF4],
    batch_size: usize,
) -> (RowMajorMatrix<F>, EF4, EF7) {
    let empty = vec![];
    let (scoped_sends, scoped_receives) = scoped_interactions(sends, receives);
    let local_sends = scoped_sends.get(&InteractionScope::Local).unwrap_or(&empty);
    let local_receives = scoped_receives.get(&InteractionScope::Local).unwrap_or(&empty);
    let global_sends = scoped_sends.get(&InteractionScope::Global).unwrap_or(&empty);
    let global_receives = scoped_receives.get(&InteractionScope::Global).unwrap_or(&empty);

    let local_permutation_width =
        local_permutation_trace_width(local_sends.len() + local_receives.len(), batch_size);
    let global_permutation_width =
        global_permutation_trace_width(global_sends.len() + global_receives.len());

    let height = main.height();
    let permutation_trace_width = local_permutation_width + global_permutation_width;
    let mut permutation_trace = RowMajorMatrix::new(
        vec![F::zero(); permutation_trace_width * height],
        permutation_trace_width,
    );

    let random_elements = &random_elements[0..2];
    let local_row_range = 0..local_permutation_width;
    let global_row_range = local_permutation_width..permutation_trace_width;

    match preprocessed {
        Some(prep) => {
            permutation_trace
                .par_rows_mut()
                .zip_eq(prep.par_row_slices())
                .zip_eq(main.par_row_slices())
                .for_each(|((row, prep_row), main_row)| {
                    let local_row: &mut [F] = &mut row[local_row_range.start..local_row_range.end];
                    let local_row: &mut [EF4] = unsafe { std::mem::transmute(local_row) };
                    populate_local_permutation_row::<F, EF4>(
                        local_row,
                        prep_row,
                        main_row,
                        local_sends,
                        local_receives,
                        random_elements,
                        batch_size,
                    );
                    let global_row: &mut [F] =
                        &mut row[global_row_range.start..global_row_range.end];
                    populate_global_permutation_row::<F, EF7>(
                        global_row,
                        prep_row,
                        main_row,
                        global_sends,
                        global_receives,
                    );
                });
        }
        None => {
            permutation_trace.par_rows_mut().zip_eq(main.par_row_slices()).for_each(
                |(row, main_row)| {
                    let global_row: &mut [F] = &mut row[local_row_range.start..local_row_range.end];
                    let global_row: &mut [EF4] = unsafe { std::mem::transmute(global_row) };
                    populate_local_permutation_row(
                        global_row,
                        &[],
                        main_row,
                        local_sends,
                        local_receives,
                        random_elements,
                        batch_size,
                    );

                    let global_row: &mut [F] =
                        &mut row[global_row_range.start..global_row_range.end];
                    populate_global_permutation_row::<F, EF7>(
                        global_row,
                        &[],
                        main_row,
                        global_sends,
                        global_receives,
                    );
                },
            );
        }
    }

    // let zero = EF4::zero();
    // let local_cumulative_sums = permutation_trace
    //     .par_rows_mut()
    //     .map(|row| {
    //         let row: &mut [EF4] = unsafe { std::mem::transmute(row) };
    //         if local_row_range.end == 0 {
    //             EF4::zero()
    //         } else {
    //             row[local_row_range.start..local_row_range.end - 1].iter().copied().sum::<EF4>()
    //         }
    //     })
    //     .into_par_iter()
    //     .scan(|a, b| *a + *b, zero)
    //     .collect::<Vec<_>>();

    // let global_cumulative_sums = permutation_trace
    //     .par_rows_mut()
    //     .map(|row| {
    //         if global_row_range.end - global_row_range.start == 0 {
    //             EF7::zero()
    //         } else {
    //             let row = &row[(global_row_range.end - EF7::D * 2)..global_row_range.end];
    //             EF7::from_base_slice(row)
    //         }
    //     })
    //     .collect::<Vec<_>>();
    // let local_cumulative_sum = *local_cumulative_sums.last().unwrap();
    // let global_cumulative_sum = *global_cumulative_sums.last().unwrap();

    // permutation_trace.par_rows_mut().zip_eq(local_cumulative_sums.into_par_iter()).for_each(
    //     |(row, local_cumulative_sum)| {
    //         let row: &mut [EF4] = unsafe { std::mem::transmute(row) };
    //         row[local_row_range.end - 1] = local_cumulative_sum;
    //     },
    // );

    (permutation_trace, EF4::zero(), EF7::zero())
}

/// Evaluates the permutation constraints for the given chip.
///
/// In particular, the constraints checked here are:
///     - The running sum column starts at zero.
///     - That the RLC per interaction is computed correctly.
///     - The running sum column ends at the (currently) given cumalitive sum.
#[allow(clippy::too_many_lines)]
pub fn eval_permutation_constraints<'a, F, AB>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    batch_size: usize,
    builder: &mut AB,
) where
    F: Field,
    AB::EF: ExtensionField<F>,
    AB: MultiTableAirBuilder<'a, F = F> + PairBuilder,
    AB: 'a,
{
    // let (grouped_sends, grouped_receives, grouped_widths) =
    //     get_grouped_maps(sends, receives, batch_size);

    // // Get the permutation challenges.
    // let permutation_challenges = builder.permutation_randomness();
    // let random_elements: Vec<AB::ExprEF> =
    //     permutation_challenges.iter().map(|x| (*x).into()).collect();
    // let cumulative_sums: Vec<AB::ExprEF> =
    //     builder.cumulative_sums().iter().map(|x| (*x).into()).collect();
    // let preprocessed = builder.preprocessed();
    // let main = builder.main();
    // let perm = builder.permutation().to_row_major_matrix();

    // let preprocessed_local = preprocessed.row_slice(0);
    // let main_local = main.to_row_major_matrix();
    // let main_local = main_local.row_slice(0);
    // let main_local: &[AB::Var] = (*main_local).borrow();
    // let perm_width = perm.width();
    // let perm_local = perm.row_slice(0);
    // let perm_local: &[AB::VarEF] = (*perm_local).borrow();
    // let perm_next = perm.row_slice(1);
    // let perm_next: &[AB::VarEF] = (*perm_next).borrow();

    // // Assert that the permutation trace width is correct.
    // let expected_perm_width = grouped_widths.values().sum::<usize>();
    // if perm_width != expected_perm_width {
    //     panic!(
    //         "permutation trace width is incorrect: expected {expected_perm_width}, got {perm_width}",
    //     );
    // }

    // for scope in InteractionScope::iter() {
    //     let random_elements = match scope {
    //         InteractionScope::Global => &[AB::ExprEF::zero(), AB::ExprEF::zero()], // TODO: Remove
    //         InteractionScope::Local => &random_elements[0..2],
    //     };

    //     let (alpha, beta) = (&random_elements[0], &random_elements[1]);

    //     let perm_local = match scope {
    //         InteractionScope::Global => &perm_local[0..*grouped_widths.get(&scope).unwrap()],
    //         InteractionScope::Local => {
    //             let global_perm_width = *grouped_widths.get(&InteractionScope::Global).unwrap();
    //             &perm_local
    //                 [global_perm_width..global_perm_width + *grouped_widths.get(&scope).unwrap()]
    //         }
    //     };

    //     let perm_next = match scope {
    //         InteractionScope::Global => &perm_next[0..*grouped_widths.get(&scope).unwrap()],
    //         InteractionScope::Local => {
    //             let global_perm_width = *grouped_widths.get(&InteractionScope::Global).unwrap();
    //             &perm_next
    //                 [global_perm_width..global_perm_width + *grouped_widths.get(&scope).unwrap()]
    //         }
    //     };

    //     let empty_vec = vec![];
    //     let sends = grouped_sends.get(&scope).unwrap_or(&empty_vec);
    //     let receives = grouped_receives.get(&scope).unwrap_or(&empty_vec);

    //     if sends.is_empty() && receives.is_empty() {
    //         continue;
    //     }

    //     // Ensure that each batch sum m_i/f_i is computed correctly.
    //     let interaction_chunks = &sends
    //         .iter()
    //         .map(|int| (int, true))
    //         .chain(receives.iter().map(|int| (int, false)))
    //         .chunks(batch_size);

    //     // Assert that the i-eth entry is equal to the sum_i m_i/rlc_i by constraints:
    //     // entry * \prod_i rlc_i = \sum_i m_i * \prod_{j!=i} rlc_j over all columns of the permutation
    //     // trace except the last column.
    //     for (entry, chunk) in perm_local[0..perm_local.len() - 1].iter().zip(interaction_chunks) {
    //         // First, we calculate the random linear combinations and multiplicities with the correct
    //         // sign depending on wetther the interaction is a send or a receive.
    //         let mut rlcs: Vec<AB::ExprEF> = Vec::with_capacity(batch_size);
    //         let mut multiplicities: Vec<AB::Expr> = Vec::with_capacity(batch_size);
    //         for (interaction, is_send) in chunk {
    //             let mut rlc = alpha.clone();
    //             let mut betas = beta.powers();

    //             rlc = rlc.clone()
    //                 + betas.next().unwrap()
    //                     * AB::ExprEF::from_canonical_usize(interaction.argument_index());
    //             for (field, beta) in interaction.values.iter().zip(betas.clone()) {
    //                 let elem = field.apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local);
    //                 rlc = rlc.clone() + beta * elem;
    //             }
    //             rlcs.push(rlc);

    //             let send_factor = if is_send { AB::F::one() } else { -AB::F::one() };
    //             multiplicities.push(
    //                 interaction
    //                     .multiplicity
    //                     .apply::<AB::Expr, AB::Var>(&preprocessed_local, main_local)
    //                     * send_factor,
    //             );
    //         }

    //         // Now we can calculate the numerator and denominator of the combined batch.
    //         let mut product = AB::ExprEF::one();
    //         let mut numerator = AB::ExprEF::zero();
    //         for (i, (m, rlc)) in multiplicities.into_iter().zip(rlcs.iter()).enumerate() {
    //             // Calculate the running product of all rlcs.
    //             product = product.clone() * rlc.clone();

    //             // Calculate the product of all but the current rlc.
    //             let mut all_but_current = AB::ExprEF::one();
    //             for other_rlc in
    //                 rlcs.iter().enumerate().filter(|(j, _)| i != *j).map(|(_, rlc)| rlc)
    //             {
    //                 all_but_current = all_but_current.clone() * other_rlc.clone();
    //             }
    //             numerator = numerator.clone() + AB::ExprEF::from_base(m) * all_but_current;
    //         }

    //         // Finally, assert that the entry is equal to the numerator divided by the product.
    //         let entry: AB::ExprEF = (*entry).into();
    //         builder.assert_eq_ext(product.clone() * entry.clone(), numerator);
    //     }

    //     // Compute the running local and next permutation sums.
    //     let perm_width = grouped_widths.get(&scope).unwrap();
    //     let sum_local =
    //         perm_local[..perm_width - 1].iter().map(|x| (*x).into()).sum::<AB::ExprEF>();
    //     let sum_next = perm_next[..perm_width - 1].iter().map(|x| (*x).into()).sum::<AB::ExprEF>();
    //     let phi_local: AB::ExprEF = (*perm_local.last().unwrap()).into();
    //     let phi_next: AB::ExprEF = (*perm_next.last().unwrap()).into();

    //     // Assert that cumulative sum is initialized to `phi_local` on the first row.
    //     builder.when_first_row().assert_eq_ext(phi_local.clone(), sum_local);

    //     // Assert that the cumulative sum is constrained to `phi_next - phi_local` on the transition
    //     // rows.
    //     builder.when_transition().assert_eq_ext(phi_next - phi_local.clone(), sum_next);

    //     // Assert that the cumulative sum is constrained to `phi_local` on the last row.
    //     let cumulative_sum = match scope {
    //         InteractionScope::Global => &cumulative_sums[0],
    //         InteractionScope::Local => &cumulative_sums[1],
    //     };

    //     builder.when_last_row().assert_eq_ext(*perm_local.last().unwrap(), cumulative_sum.clone());
    // }
}
