use p3_air::{
    Air, AirBuilder, BaseAir, PairBuilder, PermutationAirBuilder, TwoRowMatrixView, VirtualPairCol,
};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field, Powers, PrimeField};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

mod debug;
pub use debug::*;

use crate::utils::Chip;

/// Computes the multiplicative inverse of each element in the given vector.
///
/// In other words, given elements e_1, ..., e_n returns 1/e_i if e_i != 0 and 0 otherwise.
pub fn batch_multiplicative_inverse<F: Field>(values: Vec<F>) -> Vec<F> {
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
    let mut result = values.clone();
    for (i, index) in indices.into_iter().enumerate() {
        result[index] = inverse_nonzero_values[i];
    }

    result
}

/// Generates powers of a random element based on how many interactions there are in the chip.
///
/// These elements are used to uniquely fingerprint each interaction.
fn generate_interaction_rlc_elements<F: PrimeField, EF: AbstractExtensionField<F>>(
    chip: &dyn Chip<F>,
    random_element: EF,
) -> Vec<EF> {
    let alphas = random_element
        .powers()
        .skip(1)
        .take(
            chip.sends()
                .into_iter()
                .chain(chip.receives())
                .into_iter()
                .map(|interaction| interaction.argument_index())
                .max()
                .unwrap_or(0)
                + 1,
        )
        .collect::<Vec<_>>();
    alphas
}

/// Generates the permutation trace for the given chip and main trace based on a variant of LogUp.
///
/// The permutation trace has (N+1)*EF::NUM_COLS columns, where N is the number of interactions in
/// the chip.
pub fn generate_permutation_trace<F: PrimeField, EF: ExtensionField<F>>(
    chip: &dyn Chip<F>,
    main: &RowMajorMatrix<F>,
    random_elements: Vec<EF>,
) -> RowMajorMatrix<EF> {
    // Get all the interactions related to this chip.
    let all_interactions = chip.all_interactions();

    // Generate the RLC elements to uniquely identify each interaction.
    let alphas = generate_interaction_rlc_elements(chip, random_elements[0]);

    // Generate the RLC elements to uniquely identify each item in the looked up tuple.
    let betas = random_elements[1].powers();

    // Get the preprocessed trace.
    let preprocessed = chip.preprocessed_trace();

    // Iterate over the rows of the main trace to compute the permutation trace values. In
    // particular, for each row i, interaction j, and columns c_0, ..., c_{k-1} we compute the sum:
    //
    // permutation_trace_values[i][j] = \alpha^j + \sum_k \beta^k * f_{i, c_k}
    //
    // where f_{i, c_k} is the value at row i for column c_k. The computed value is essentially a
    // fingerprint for the interaction.
    let permutation_trace_width = all_interactions.len() + 1;
    let mut permutation_trace_values = Vec::with_capacity(main.height() * permutation_trace_width);
    for (i, main_row) in main.rows().enumerate() {
        let mut row = vec![EF::zero(); permutation_trace_width];
        let preprocessed_row = if preprocessed.is_some() {
            preprocessed.as_ref().unwrap().row_slice(i)
        } else {
            &[]
        };
        for (j, interaction) in all_interactions.iter().enumerate() {
            let alpha = alphas[interaction.argument_index()];
            row[j] = fingerprint_row(
                main_row,
                preprocessed_row,
                &interaction.values,
                alpha,
                betas.clone(),
            );
        }
        permutation_trace_values.extend(row);
    }

    // The permutation trace is actually the multiplicative inverse of the RLC's we computed above.
    let permutation_trace_values = batch_multiplicative_inverse(permutation_trace_values);
    let mut permutation_trace =
        RowMajorMatrix::new(permutation_trace_values, permutation_trace_width);

    // Weight each row of the permutation trace by the respective multiplicities.
    let mut phi = vec![EF::zero(); permutation_trace.height()];
    for (i, (main_row, permutation_row)) in main.rows().zip(permutation_trace.rows()).enumerate() {
        if i > 0 {
            phi[i] = phi[i - 1];
        }
        let preprocessed_row = if preprocessed.is_some() {
            preprocessed.as_ref().unwrap().row_slice(i)
        } else {
            &[]
        };
        for (j, interaction) in all_interactions.iter().enumerate() {
            let mult = interaction
                .multiplicity
                .apply::<F, F>(preprocessed_row, main_row);
            phi[i] += EF::from_base(mult) * permutation_row[j];
        }
    }

    // For each row, set the last column to be phi.
    for (n, row) in permutation_trace.as_view_mut().rows_mut().enumerate() {
        *row.last_mut().unwrap() = phi[n];
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
    F: PrimeField,
    C: Chip<F> + Air<AB>,
    AB: PermutationAirBuilder<F = F> + PairBuilder,
{
    let random_elements = builder.permutation_randomness().to_vec();

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

    let phi_local = perm_local[perm_width - 1].clone();
    let phi_next = perm_next[perm_width - 1].clone();

    let all_interactions = chip.all_interactions();

    let alphas = generate_interaction_rlc_elements(chip, random_elements[0]);
    let betas = random_elements[1].powers();

    let lhs = phi_next - phi_local.clone();
    let mut rhs = AB::ExprEF::from_base(AB::Expr::zero());
    let mut phi_0 = AB::ExprEF::from_base(AB::Expr::zero());

    let nb_send_iteractions = chip.sends().len();
    for (m, interaction) in all_interactions.iter().enumerate() {
        // Ensure that the recipricals of the RLC's were properly calculated.
        let mut rlc = AB::ExprEF::from_base(AB::Expr::zero());
        for (field, beta) in interaction.values.iter().zip(betas.clone()) {
            let elem = field.apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
            rlc += AB::ExprEF::from(beta) * elem;
        }
        rlc = rlc + alphas[interaction.argument_index()];
        builder.assert_one_ext::<AB::ExprEF, AB::ExprEF>(rlc * perm_local[m]);

        let mult_local = interaction
            .multiplicity
            .apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
        let mult_next = interaction
            .multiplicity
            .apply::<AB::Expr, AB::Var>(preprocessed_next, main_next);

        // Ensure that the running sum is computed correctly.
        if m < nb_send_iteractions {
            phi_0 += AB::ExprEF::from_base(mult_local) * perm_local[m];
            rhs += AB::ExprEF::from_base(mult_next) * perm_next[m];
        } else {
            phi_0 -= AB::ExprEF::from_base(mult_local) * perm_local[m];
            rhs -= AB::ExprEF::from_base(mult_next) * perm_next[m];
        }
    }

    // Running sum constraints.
    builder
        .when_transition()
        .assert_eq_ext::<AB::ExprEF, _, _>(lhs, rhs);
    builder
        .when_first_row()
        .assert_eq_ext(perm_local.last().unwrap().clone(), phi_0);
    builder.when_last_row().assert_eq_ext(
        perm_local.last().unwrap().clone(),
        AB::ExprEF::from(cumulative_sum),
    );
}

/// Fingerprints the given virtual columns using the randomness in alpha and beta.
///
/// Useful for constructing lookup arguments based on logarithmic derivatives.
fn fingerprint_row<F, EF>(
    main_row: &[F],
    preprocessed_row: &[F],
    fields: &[VirtualPairCol<F>],
    alpha: EF,
    betas: Powers<EF>,
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let mut rlc = EF::zero();
    for (columns, beta) in fields.iter().zip(betas) {
        rlc += beta * columns.apply::<F, F>(preprocessed_row, main_row)
    }
    rlc += alpha;
    rlc
}

/// Checks that the constraints of the given AIR are satisfied, including the permutation trace.
///
/// Note that this does not actually verify the proof.
pub fn debug_constraints<F: PrimeField, EF: ExtensionField<F>, A>(
    air: &A,
    main: &RowMajorMatrix<F>,
    perm: &RowMajorMatrix<EF>,
    perm_challenges: &[EF],
) where
    A: for<'a> Air<DebugConstraintBuilder<'a, F, EF>> + BaseAir<F> + Chip<F>,
{
    assert_eq!(main.height(), perm.height());
    let height = main.height();
    if height == 0 {
        return;
    }

    let preprocessed = air.preprocessed_trace();

    let cumulative_sum = *perm.row_slice(perm.height() - 1).last().unwrap();

    // Check that constraints are satisfied.
    (0..height).into_par_iter().for_each(|i| {
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
                local: &main_local,
                next: &main_next,
            },
            preprocessed: TwoRowMatrixView {
                local: &preprocessed_local,
                next: &preprocessed_next,
            },
            perm: TwoRowMatrixView {
                local: &perm_local,
                next: &perm_next,
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
