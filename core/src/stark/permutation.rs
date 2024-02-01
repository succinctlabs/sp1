use std::ops::{Add, Mul};

use p3_air::{Air, AirBuilder, PairBuilder, PermutationAirBuilder};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Powers, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices};
use p3_maybe_rayon::prelude::*;

use crate::{lookup::Interaction, utils::Chip};

/// Generates powers of a random element based on how many interactions there are in the chip.
///
/// These elements are used to uniquely fingerprint each interaction.
pub fn generate_interaction_rlc_elements<F: Field, EF: AbstractExtensionField<F>>(
    interactions: &[Interaction<F>],
    random_element: EF,
) -> Vec<EF> {
    let n = interactions
        .iter()
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
pub fn generate_permutation_trace<F: PrimeField, EF: ExtensionField<F>>(
    chip: &dyn Chip<F>,
    main: &RowMajorMatrix<F>,
    random_elements: &[EF],
) -> RowMajorMatrix<EF> {
    // Get all the interactions related to this chip.
    let all_interactions = chip.all_interactions();

    // Generate the RLC elements to uniquely identify each interaction.
    let alphas = generate_interaction_rlc_elements(&all_interactions, random_elements[0]);

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
    let permutation_trace_width = all_interactions.len() + 1;
    let mut permutation_trace_values =
        tracing::debug_span!("permutation trace values").in_scope(|| {
            // Compute the permutation trace values in parallel.
            let mut parallel = main
                .par_row_chunks(chunk_rate)
                .flat_map(|rows_chunk| {
                    rows_chunk
                        .rows()
                        .flat_map(|main_row| {
                            compute_permutation_row(
                                main_row,
                                &[],
                                &all_interactions,
                                &alphas,
                                betas.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            // Compute the permutation trace values for the remainder.
            let remainder = main.height() % chunk_rate;
            for i in 0..remainder {
                let perm_row = compute_permutation_row(
                    main.row_slice(main.height() - remainder + i),
                    &[],
                    &all_interactions,
                    &alphas,
                    betas.clone(),
                );
                parallel.extend(perm_row);
            }
            parallel
        });

    // The permutation trace is actually the multiplicative inverse of the RLC's we computed above.
    permutation_trace_values
        .chunks_mut(chunk_rate)
        .par_bridge()
        .for_each(|chunk| batch_multiplicative_inverse_inplace(chunk));
    let mut permutation_trace =
        RowMajorMatrix::new(permutation_trace_values, permutation_trace_width);

    // Weight each row of the permutation trace by the respective multiplicities.
    let mut phi = vec![EF::zero(); permutation_trace.height()];
    let nb_send_iteractions = chip.sends().len();

    for (i, (main_row, permutation_row)) in main
        .rows()
        .zip(permutation_trace.as_view_mut().rows_mut())
        .enumerate()
    {
        if i > 0 {
            phi[i] = phi[i - 1];
        }
        for (j, interaction) in all_interactions.iter().enumerate() {
            let mult = interaction.multiplicity.apply::<F, F>(&[], main_row);
            if j < nb_send_iteractions {
                phi[i] += EF::from_base(mult) * permutation_row[j];
            } else {
                phi[i] -= EF::from_base(mult) * permutation_row[j];
            }
        }
        *permutation_row.last_mut().unwrap() = phi[i];
    }

    permutation_trace
}

/// Evaluates the permutation constraints for the given chip.
///
/// In particular, the constraints checked here are:
///     - The running sum column starts at zero.
///     - That the RLC per interaction is computed correctly.
///     - The running sum column ends at the (currently) given cumalitive sum.
pub fn eval_permutation_constraints<F, C, AB>(chip: &C, builder: &mut AB, cumulative_sum: AB::EF)
where
    F: Field,
    C: Chip<F> + Air<AB> + ?Sized,
    AB::EF: ExtensionField<F>,
    AB::Expr: Mul<F, Output = AB::Expr> + Add<F, Output = AB::Expr>,
    AB: PermutationAirBuilder + PairBuilder,
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

    let all_interactions = chip.all_interactions();

    let alphas = generate_interaction_rlc_elements(&all_interactions, alpha);
    let betas = beta.powers();

    let lhs: AB::ExprEF = phi_next.into() - phi_local.into();
    let mut rhs = AB::ExprEF::zero();
    let mut phi_0 = AB::ExprEF::zero();

    let nb_send_iteractions = chip.sends().len();
    for (m, interaction) in all_interactions.iter().enumerate() {
        // Ensure that the recipricals of the RLC's were properly calculated.
        let mut rlc = AB::ExprEF::zero();
        for (field, beta) in interaction.values.iter().zip(betas.clone()) {
            let elem = field.apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
            rlc += AB::ExprEF::from_f(beta) * elem;
        }
        rlc += AB::ExprEF::from_f(alphas[interaction.argument_index()]);
        builder.assert_one_ext::<AB::ExprEF, AB::ExprEF>(rlc * perm_local[m].into());

        let mult_local = interaction
            .multiplicity
            .apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
        let mult_next = interaction
            .multiplicity
            .apply::<AB::Expr, AB::Var>(preprocessed_next, main_next);

        // Ensure that the running sum is computed correctly.
        if m < nb_send_iteractions {
            phi_0 += perm_local[m].into() * mult_local;
            rhs += perm_next[m].into() * mult_next;
        } else {
            phi_0 -= perm_local[m].into() * mult_local;
            rhs -= perm_next[m].into() * mult_next;
        }
    }

    // Running sum constraints.
    builder
        .when_transition()
        .assert_eq_ext::<AB::ExprEF, _, _>(lhs, rhs);
    builder
        .when_first_row()
        .assert_eq_ext(*perm_local.last().unwrap(), phi_0);
    builder.when_last_row().assert_eq_ext(
        *perm_local.last().unwrap(),
        AB::ExprEF::from_f(cumulative_sum),
    );
}

#[inline]
pub fn compute_permutation_row<F: PrimeField, EF: ExtensionField<F>>(
    main_row: &[F],
    preprocessed_row: &[F],
    interactions: &[Interaction<F>],
    alphas: &[EF],
    betas: Powers<EF>,
) -> Vec<EF> {
    let width = interactions.len() + 1;
    let mut row = vec![EF::zero(); width];
    for (i, interaction) in interactions.iter().enumerate() {
        let alpha = alphas[interaction.argument_index()];
        row[i] = alpha;
        for (columns, beta) in interaction.values.iter().zip(betas.clone()) {
            row[i] += beta * columns.apply::<F, F>(preprocessed_row, main_row)
        }
    }
    row
}

/// A forked verison of the batch_multiplicative_inverse function from Plonky3 to avoid cloning
/// the input values.
pub fn batch_multiplicative_inverse_inplace<F: Field>(values: &mut [F]) {
    // Check if values are zero and construct a new vector with only nonzero values.
    let mut nonzero_values = Vec::with_capacity(values.len());
    let mut indices = Vec::with_capacity(values.len());
    for (i, value) in values.iter().cloned().enumerate() {
        if value.is_zero() {
            continue;
        }
        nonzero_values.push(value);
        indices.push(i);
    }

    // Compute the multiplicative inverse of nonzero values.
    let inverse_nonzero_values = p3_field::batch_multiplicative_inverse(&nonzero_values);

    // Reconstruct the original vector.
    for (i, index) in indices.into_iter().enumerate() {
        values[index] = inverse_nonzero_values[i];
    }
}
