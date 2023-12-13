use p3_air::{Air, AirBuilder, PairBuilder, PermutationAirBuilder, VirtualPairCol};
use p3_field::{
    batch_multiplicative_inverse, AbstractExtensionField, AbstractField, ExtensionField, Field,
    Powers, PrimeField,
};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixRowSlices};

use crate::utils::Chip;

/// Generate the permutation trace for a chip with the provided machine.
/// This is called only after `generate_trace` has been called on all chips.
pub fn generate_permutation_trace<F: Field, EF: ExtensionField<F>>(
    chip: &dyn Chip<F>,
    main: &RowMajorMatrix<F>,
    random_elements: Vec<EF>,
) -> RowMajorMatrix<EF> {
    let all_interactions = chip.sends();
    let (alphas_local, alphas_global) = generate_rlc_elements(chip, &random_elements);
    let betas = random_elements[2].powers();

    let preprocessed = chip.preprocessed_trace();

    // Compute the reciprocal columns
    //
    // Row: | q_1 | q_2 | q_3 | ... | q_n | \phi |
    // * q_i = \frac{1}{\alpha^i + \sum_j \beta^j * f_{i,j}}
    // * f_{i,j} is the jth main trace column for the ith interaction
    // * \phi is the running sum
    //
    // Note: We can optimize this by combining several reciprocal columns into one (the
    // number is subject to a target constraint degree).
    let perm_width = all_interactions.len() + 1;
    let mut perm_values = Vec::with_capacity(main.height() * perm_width);

    for (n, main_row) in main.rows().enumerate() {
        let mut row = vec![EF::zero(); perm_width];
        for (m, (interaction, _)) in all_interactions.iter().enumerate() {
            let alpha_m = if interaction.is_local() {
                alphas_local[interaction.argument_index()]
            } else {
                alphas_global[interaction.argument_index()]
            };
            let preprocessed_row = if preprocessed.is_some() {
                preprocessed.as_ref().unwrap().row_slice(n)
            } else {
                &[]
            };
            row[m] = reduce_row(
                main_row,
                preprocessed_row,
                &interaction.fields,
                alpha_m,
                betas.clone(),
            );
        }
        perm_values.extend(row);
    }
    let perm_values = batch_multiplicative_inverse(&perm_values);
    let mut perm = RowMajorMatrix::new(perm_values, perm_width);

    // Compute the running sum column
    let mut phi = vec![EF::zero(); perm.height()];
    for (n, (main_row, perm_row)) in main.rows().zip(perm.rows()).enumerate() {
        if n > 0 {
            phi[n] = phi[n - 1];
        }
        let preprocessed_row = if preprocessed.is_some() {
            preprocessed.as_ref().unwrap().row_slice(n)
        } else {
            &[]
        };
        // for (m, (interaction, interaction_type)) in all_interactions.iter().enumerate() {
        //     let mult = interaction
        //         .count
        //         .apply::<M::F, M::F>(preprocessed_row, main_row);
        //     match interaction_type {
        //         InteractionType::LocalSend | InteractionType::GlobalSend => {
        //             phi[n] += M::EF::from_base(mult) * perm_row[m];
        //         }
        //         InteractionType::LocalReceive | InteractionType::GlobalReceive => {
        //             phi[n] -= M::EF::from_base(mult) * perm_row[m];
        //         }
        //     }
        // }
    }

    for (n, row) in perm.as_view_mut().rows_mut().enumerate() {
        *row.last_mut().unwrap() = phi[n];
    }

    perm
}

pub fn eval_permutation_constraints<F, M, C, AB>(chip: &C, builder: &mut AB, cumulative_sum: AB::EF)
where
    F: PrimeField,
    C: Chip<F> + Air<AB>,
    AB: PermutationAirBuilder<F = F> + PairBuilder,
{
    let rand_elems = builder.permutation_randomness().to_vec();

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

    let (alphas_local, alphas_global) = generate_rlc_elements(chip, &rand_elems);
    let betas = rand_elems[2].powers();

    let lhs = phi_next - phi_local.clone();
    let mut rhs = AB::ExprEF::from_base(AB::Expr::zero());
    let mut phi_0 = AB::ExprEF::from_base(AB::Expr::zero());
    for (m, (interaction, interaction_type)) in all_interactions.iter().enumerate() {
        // Reciprocal constraints
        let mut rlc = AB::ExprEF::from_base(AB::Expr::zero());
        for (field, beta) in interaction.fields.iter().zip(betas.clone()) {
            let elem = field.apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
            rlc += AB::ExprEF::from(beta) * elem;
        }
        if interaction.is_local() {
            rlc = rlc + alphas_local[interaction.argument_index()];
        } else {
            rlc = rlc + alphas_global[interaction.argument_index()];
        }
        builder.assert_one_ext::<AB::ExprEF, AB::ExprEF>(rlc * perm_local[m]);

        let mult_local = interaction
            .count
            .apply::<AB::Expr, AB::Var>(preprocessed_local, main_local);
        let mult_next = interaction
            .count
            .apply::<AB::Expr, AB::Var>(preprocessed_next, main_next);

        // // Build the RHS of the permutation constraint
        // match interaction_type {
        //     InteractionType::LocalSend | InteractionType::GlobalSend => {
        //         phi_0 += AB::ExprEF::from_base(mult_local) * perm_local[m];
        //         rhs += AB::ExprEF::from_base(mult_next) * perm_next[m];
        //     }
        //     InteractionType::LocalReceive | InteractionType::GlobalReceive => {
        //         phi_0 -= AB::ExprEF::from_base(mult_local) * perm_local[m];
        //         rhs -= AB::ExprEF::from_base(mult_next) * perm_next[m];
        //     }
        // }
    }

    // Running sum constraints
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

fn generate_rlc_elements<F: AbstractField, EF: AbstractExtensionField<F>>(
    chip: &dyn Chip<F>,
    random_elements: &[EF],
) -> (Vec<EF>, Vec<EF>) {
    let alphas_local = random_elements[0]
        .powers()
        .skip(1)
        .take(
            chip.local_sends()
                .into_iter()
                .chain(chip.local_receives())
                .into_iter()
                .map(|interaction| interaction.argument_index())
                .max()
                .unwrap_or(0)
                + 1,
        )
        .collect::<Vec<_>>();

    let alphas_global = random_elements[1]
        .powers()
        .skip(1)
        .take(
            chip.global_sends()
                .into_iter()
                .chain(chip.global_receives())
                .into_iter()
                .map(|interaction| interaction.argument_index())
                .max()
                .unwrap_or(0)
                + 1,
        )
        .collect::<Vec<_>>();

    (alphas_local, alphas_global)
}

// TODO: Use Var and Expr type bounds in place of concrete fields so that
// this function can be used in `eval_permutation_constraints`.
fn reduce_row<F, EF>(
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

#[macro_export]
macro_rules! instructions {
    ($($t:ident),*) => {
        $(
            #[derive(Default)]
            pub struct $t {}
        )*
    }
}
