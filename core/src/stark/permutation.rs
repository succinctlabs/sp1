use p3_air::{ExtensionBuilder, PairBuilder};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Powers, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices};
use p3_maybe_rayon::prelude::*;

use super::util::batch_multiplicative_inverse_inplace;
use crate::{air::MultiTableAirBuilder, lookup::Interaction};

/// Generates powers of a random element based on how many interactions there are in the chip.
///
/// These elements are used to uniquely fingerprint each interaction.
pub fn generate_interaction_rlc_elements<F: Field, EF: AbstractExtensionField<F>>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    random_element: EF,
) -> Vec<EF> {
    let n = sends
        .iter()
        .chain(receives.iter())
        .map(|interaction| interaction.argument_index())
        .max()
        .unwrap_or(0)
        + 1;
    random_element.powers().skip(1).take(n).collect::<Vec<_>>()
}

/// Generates the permutation trace for the given chip and main trace based on a variant of LogUp.
///
/// The permutation trace has (N+1)*EF::NUM_COLS columns, where N is the number of interactions in
/// the chip.
pub(crate) fn generate_permutation_trace<F: PrimeField, EF: ExtensionField<F>>(
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    preprocessed: &Option<RowMajorMatrix<F>>,
    main: &RowMajorMatrix<F>,
    random_elements: &[EF],
) -> RowMajorMatrix<EF> {
    // Generate the RLC elements to uniquely identify each interaction.
    let alphas = generate_interaction_rlc_elements(sends, receives, random_elements[0]);

    // Generate the RLC elements to uniquely identify each item in the looked up tuple.
    let betas = random_elements[1].powers();

    // TODO: Get the preprocessed trace and handle it properly.
    // let preprocessed = chip.preprocessed_trace();

    // Iterate over the rows of the main trace to compute the permutation trace values. In
    // particular, for each row i, interaction j, and columns c_0, ..., c_{k-1} we compute the sum:
    //
    // permutation_trace_values[i][j] = \alpha^j + \sum_k \beta^k * f_{i, c_k}
    //
    // where f_{i, c_k} is the value at row i for column c_k. The computed value is essentially a
    // fingerprint for the interaction.
    let chunk_rate = 1 << 8;
    let permutation_trace_width = sends.len() + receives.len() + 3;
    let mut permutation_trace_values: Vec<EF> = {
        // Compute the permutation trace values in parallel.

        let mut parallel = match preprocessed {
            Some(_) => unimplemented!(),
            None => main
                .par_row_chunks(chunk_rate)
                .flat_map(|main_rows_chunk| {
                    main_rows_chunk
                        .rows()
                        .flat_map(|main_row| {
                            compute_permutation_row(
                                main_row,
                                &[],
                                sends,
                                receives,
                                &alphas,
                                betas.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        };

        // Compute the permutation trace values for the remainder.
        let remainder = main.height() % chunk_rate;
        for i in 0..remainder {
            let perm_row = compute_permutation_row(
                main.row_slice(main.height() - remainder + i),
                &[],
                sends,
                receives,
                &alphas,
                betas.clone(),
            );
            parallel.extend(perm_row);
        }
        parallel
    };

    // The permutation trace is actually the multiplicative inverse of the RLC's we computed above.
    permutation_trace_values
        .chunks_mut(chunk_rate)
        .par_bridge()
        .for_each(|chunk| batch_multiplicative_inverse_inplace(chunk));

    //chunk each row of permutation_trace_values into two, and do a weighted sum with their multiplicities
    assert_eq!(permutation_trace_values.len() % permutation_trace_width, 0);
    let permutation_trace_height = permutation_trace_values.len() / permutation_trace_width;

    let mut batched_rows = Vec::new();
    for row_ind in 0..permutation_trace_height {
        let row = &permutation_trace_values
            [row_ind * permutation_trace_width..(row_ind + 1) * permutation_trace_width];
        let main_row = main.rows().collect::<Vec<_>>()[row_ind];
        let mut batched_perm_values = row
            .par_chunks(2)
            .enumerate()
            .map(|(i, chunk)| {
                let mult0 = match sends.get(2 * i) {
                    Some(x) => x.multiplicity.apply::<F, F>(&[], main_row),
                    None => match receives.get(2 * i) {
                        Some(y) => -y.multiplicity.apply::<F, F>(&[], main_row),
                        None => F::zero(),
                    },
                };
                let mult1 = match sends.get(2 * i + 1) {
                    Some(x) => x.multiplicity.apply::<F, F>(&[], main_row),
                    None => match receives.get(2 * i + 1) {
                        Some(y) => -y.multiplicity.apply::<F, F>(&[], main_row),
                        None => F::zero(),
                    },
                };
                let mut products = vec![mult0, mult1];
                let mut sum = EF::zero();
                for i in 0..chunk.len() {
                    sum += EF::from_base(products[i]) * chunk[i];
                }
                sum
            })
            .collect::<Vec<_>>();
        batched_perm_values.push(EF::zero());
        batched_perm_values.push(EF::zero());
        batched_perm_values.push(EF::zero());
        batched_rows.push(batched_perm_values);
    }

    //for each row in batched_rows, sum up all the columns
    let num_rlcs = sends.len() + receives.len();
    for row in 0..batched_rows.len() {
        let mut sum = EF::zero();
        for col in 0..num_rlcs {
            sum += batched_rows[row][col];
        }
        batched_rows[row][num_rlcs] = sum;
    }

    //calculate running sum of column sums
    batched_rows[0][num_rlcs + 1] = batched_rows[0][num_rlcs];

    for i in 1..batched_rows.len() {
        batched_rows[i][num_rlcs + 1] =
            batched_rows[i][num_rlcs] + batched_rows[i - 1][num_rlcs + 1];
    }

    //calculate total sum of column sums and add it to the end of each row

    for i in 0..batched_rows.len() {
        batched_rows[i][num_rlcs + 2] = batched_rows[batched_rows.len() - 1][num_rlcs + 1];
    }

    let mut permutation_trace = RowMajorMatrix::new(
        batched_rows
            .iter()
            .flatten()
            .map(|x| *x)
            .collect::<Vec<_>>(),
        permutation_trace_width,
    );

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
    builder: &mut AB,
) where
    F: Field,
    AB::EF: ExtensionField<F>,
    AB: MultiTableAirBuilder<F = F> + PairBuilder,
{
    let random_elements = builder.permutation_randomness();
    let (alpha, beta) = (random_elements[0], random_elements[1]);

    let main = builder.main();
    let main_local: &[AB::Var] = main.row_slice(0);
    let main_next: &[AB::Var] = main.row_slice(1);

    let preprocessed = builder.preprocessed();
    let preprocessed_local = preprocessed.row_slice(0);
    let preprocessed_next = preprocessed.row_slice(1);

    let perm = builder.permutation();
    let perm_width = perm.width();
    let perm_local: &[AB::VarEF] = perm.row_slice(0);
    let perm_next: &[AB::VarEF] = perm.row_slice(1);

    let phi_local = perm_local[perm_width - 1];
    let phi_next = perm_next[perm_width - 1];

    let alphas = generate_interaction_rlc_elements(sends, receives, alpha);
    let betas = beta.powers();

    let lhs: AB::ExprEF = phi_next.into() - phi_local.into();
    let mut rhs = AB::ExprEF::zero();
    let mut phi_0 = AB::ExprEF::zero();

    let nb_sends = sends.len();
    for (m, interaction) in sends.iter().chain(receives.iter()).enumerate() {
        // Ensure that the recipricals of the RLC's were properly calculated.
        let mut rlc = AB::ExprEF::zero();
        for (field, beta) in interaction.values.iter().zip(betas.clone()) {
            let elem = field.apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
            rlc += AB::ExprEF::from_f(beta) * elem;
        }
        rlc += AB::ExprEF::from_f(alphas[interaction.argument_index()]);
        builder.assert_one_ext(rlc * perm_local[m].into());

        let mult_local = interaction
            .multiplicity
            .apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
        let mult_next = interaction
            .multiplicity
            .apply::<AB::Expr, AB::Var>(preprocessed_next, main_next);

        // Ensure that the running sum is computed correctly.
        if m < nb_sends {
            phi_0 += perm_local[m].into() * mult_local;
            rhs += perm_next[m].into() * mult_next;
        } else {
            phi_0 -= perm_local[m].into() * mult_local;
            rhs -= perm_next[m].into() * mult_next;
        }
    }

    // Running sum constraints.
    builder.when_transition().assert_eq_ext(lhs, rhs);
    builder
        .when_first_row()
        .assert_eq_ext(*perm_local.last().unwrap(), phi_0);

    let cumulative_sum = builder.cumulative_sum();
    builder
        .when_last_row()
        .assert_eq_ext(*perm_local.last().unwrap(), cumulative_sum);
}

/// Computes the permutation fingerprint of a row.
pub fn compute_permutation_row<F: PrimeField, EF: ExtensionField<F>>(
    main_row: &[F],
    preprocessed_row: &[F],
    sends: &[Interaction<F>],
    receives: &[Interaction<F>],
    alphas: &[EF],
    betas: Powers<EF>,
) -> Vec<EF> {
    let width = sends.len() + receives.len() + 1;
    let mut row = vec![EF::zero(); width];
    for (i, interaction) in sends.iter().chain(receives.iter()).enumerate() {
        let alpha = alphas[interaction.argument_index()];
        row[i] = alpha;
        for (columns, beta) in interaction.values.iter().zip(betas.clone()) {
            row[i] += beta * columns.apply::<F, F>(preprocessed_row, main_row)
        }
    }
    row
}
