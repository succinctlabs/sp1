use itertools::izip;
use p3_air::{
    Air, AirBuilder, BaseAir, PairBuilder, PermutationAirBuilder, TwoRowMatrixView, VirtualPairCol,
};
use p3_commit::UnivariatePcsWithLde;
use p3_field::{
    cyclic_subgroup_coset_known_order, AbstractExtensionField, AbstractField, ExtensionField,
    Field, PackedField, Powers, PrimeField, TwoAdicField,
};
use p3_matrix::{dense::RowMajorMatrix, Matrix, MatrixGet, MatrixRowSlices};
use p3_uni_stark::{ProverConstraintFolder, StarkConfig};
use p3_util::log2_strict_usize;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub mod debug;
pub mod runtime;

pub use debug::*;

#[cfg(test)]
pub use runtime::tests;

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
fn generate_interaction_rlc_elements<C, F: PrimeField, EF: AbstractExtensionField<F>>(
    chip: &C,
    random_element: EF,
) -> Vec<EF>
where
    C: Chip<F> + ?Sized,
{
    let alphas = random_element
        .powers()
        .skip(1)
        .take(
            chip.all_interactions()
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
    let nb_send_iteractions = chip.sends().len();
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
            if j < nb_send_iteractions {
                phi[i] += EF::from_base(mult) * permutation_row[j];
            } else {
                phi[i] -= EF::from_base(mult) * permutation_row[j];
            }
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
    C: Chip<F> + Air<AB> + ?Sized,
    AB: PermutationAirBuilder<F = F> + PairBuilder,
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

    let phi_local = perm_local[perm_width - 1].clone();
    let phi_next = perm_next[perm_width - 1].clone();

    let all_interactions = chip.all_interactions();

    let alphas = generate_interaction_rlc_elements(chip, alpha);
    let betas = beta.powers();

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
    A: for<'a> Air<DebugConstraintBuilder<'a, F, EF>> + BaseAir<F> + Chip<F> + ?Sized,
{
    assert_eq!(main.height(), perm.height());
    let height = main.height();
    if height == 0 {
        return;
    }

    let preprocessed = air.preprocessed_trace();

    let cumulative_sum = *perm.row_slice(perm.height() - 1).last().unwrap();

    // Check that constraints are satisfied.
    (0..height).into_iter().for_each(|i| {
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

pub fn quotient_values<SC, A, Mat>(
    config: &SC,
    air: &A,
    degree_bits: usize,
    quotient_degree_bits: usize,
    trace_lde: &Mat,
    alpha: SC::Challenge,
) -> Vec<SC::Challenge>
where
    SC: StarkConfig,
    A: for<'a> Air<ProverConstraintFolder<'a, SC>> + ?Sized,
    Mat: MatrixGet<SC::Val> + Sync,
{
    let degree = 1 << degree_bits;
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

    (0..quotient_size)
        .into_iter()
        .step_by(SC::PackedVal::WIDTH)
        .flat_map(|i_local_start| {
            let wrap = |i| i % quotient_size;
            let i_next_start = wrap(i_local_start + next_step);
            let i_range = i_local_start..i_local_start + SC::PackedVal::WIDTH;

            let x = *SC::PackedVal::from_slice(&coset[i_range.clone()]);
            let is_transition = x - subgroup_last;
            let is_first_row = *SC::PackedVal::from_slice(&lagrange_first_evals[i_range.clone()]);
            let is_last_row = *SC::PackedVal::from_slice(&lagrange_last_evals[i_range]);

            let local: Vec<_> = (0..trace_lde.width())
                .map(|col| {
                    SC::PackedVal::from_fn(|offset| {
                        let row = wrap(i_local_start + offset);
                        trace_lde.get(row, col)
                    })
                })
                .collect();
            let next: Vec<_> = (0..trace_lde.width())
                .map(|col| {
                    SC::PackedVal::from_fn(|offset| {
                        let row = wrap(i_next_start + offset);
                        trace_lde.get(row, col)
                    })
                })
                .collect();

            let accumulator = SC::PackedChallenge::zero();
            let mut folder = ProverConstraintFolder {
                main: TwoRowMatrixView {
                    local: &local,
                    next: &next,
                },
                is_first_row,
                is_last_row,
                is_transition,
                alpha,
                accumulator,
            };
            air.eval(&mut folder);

            // quotient(x) = constraints(x) / Z_H(x)
            let zerofier_inv: SC::PackedVal = zerofier_on_coset.eval_inverse_packed(i_local_start);
            let quotient = folder.accumulator * zerofier_inv;

            // "Transpose" D packed base coefficients into WIDTH scalar extension coefficients.
            (0..SC::PackedVal::WIDTH).map(move |idx_in_packing| {
                let quotient_value = (0..<SC::Challenge as AbstractExtensionField<SC::Val>>::D)
                    .map(|coeff_idx| quotient.as_base_slice()[coeff_idx].as_slice()[idx_in_packing])
                    .collect::<Vec<_>>();
                SC::Challenge::from_base_slice(&quotient_value)
            })
        })
        .collect()
}

/// Precomputations of the evaluation of `Z_H(X) = X^n - 1` on a coset `s K` with `H <= K`.
pub struct ZerofierOnCoset<F: Field> {
    /// `n = |H|`.
    log_n: usize,
    /// `rate = |K|/|H|`.
    rate_bits: usize,
    coset_shift: F,
    /// Holds `g^n * (w^n)^i - 1 = g^n * v^i - 1` for `i in 0..rate`, with `w` a generator of `K` and `v` a
    /// `rate`-primitive root of unity.
    evals: Vec<F>,
    /// Holds the multiplicative inverses of `evals`.
    inverses: Vec<F>,
}

impl<F: TwoAdicField> ZerofierOnCoset<F> {
    pub fn new(log_n: usize, rate_bits: usize, coset_shift: F) -> Self {
        let s_pow_n = coset_shift.exp_power_of_2(log_n);
        let evals = F::two_adic_generator(rate_bits)
            .powers()
            .take(1 << rate_bits)
            .map(|x| s_pow_n * x - F::one())
            .collect::<Vec<_>>();
        let inverses = batch_multiplicative_inverse(evals.clone());
        Self {
            log_n,
            rate_bits,
            coset_shift,
            evals,
            inverses,
        }
    }

    /// Returns `Z_H(g * w^i)`.
    pub fn eval(&self, i: usize) -> F {
        self.evals[i & ((1 << self.rate_bits) - 1)]
    }

    /// Returns `1 / Z_H(g * w^i)`.
    pub fn eval_inverse(&self, i: usize) -> F {
        self.inverses[i & ((1 << self.rate_bits) - 1)]
    }

    /// Like `eval_inverse`, but for a range of indices starting with `i_start`.
    pub fn eval_inverse_packed<P: PackedField<Scalar = F>>(&self, i_start: usize) -> P {
        let mut packed = P::zero();
        packed
            .as_slice_mut()
            .iter_mut()
            .enumerate()
            .for_each(|(j, packed_j)| *packed_j = self.eval_inverse(i_start + j));
        packed
    }

    /// Evaluate the Langrange basis polynomial, `L_i(x) = Z_H(x) / (x - g_H^i)`, on our coset `s K`.
    /// Here `L_i(x)` is unnormalized in the sense that it evaluates to some nonzero value at `g_H^i`,
    /// not necessarily 1.
    pub(crate) fn lagrange_basis_unnormalized(&self, i: usize) -> Vec<F> {
        let log_coset_size = self.log_n + self.rate_bits;
        let coset_size = 1 << log_coset_size;
        let g_h = F::two_adic_generator(self.log_n);
        let g_k = F::two_adic_generator(log_coset_size);

        let target_point = g_h.exp_u64(i as u64);
        let denominators = cyclic_subgroup_coset_known_order(g_k, self.coset_shift, coset_size)
            .map(|x| x - target_point)
            .collect::<Vec<_>>();
        let inverses = batch_multiplicative_inverse(denominators);

        self.evals
            .iter()
            .cycle()
            .zip(inverses)
            .map(|(&z_h, inv)| z_h * inv)
            .collect()
    }
}

// A generalization of even-odd decomposition.
fn decompose<F: TwoAdicField>(poly: Vec<F>, shift: F, log_chunks: usize) -> Vec<Vec<F>> {
    // For now, we use a naive recursive method.
    // A more optimized method might look similar to a decimation-in-time FFT,
    // but only the first `log_chunks` layers. It should also be parallelized.

    if log_chunks == 0 {
        return vec![poly];
    }

    let n = poly.len();
    debug_assert!(n > 1);
    let log_n = log2_strict_usize(n);
    let half_n = poly.len() / 2;
    let g_inv = F::two_adic_generator(log_n).inverse();

    let mut even = Vec::with_capacity(half_n);
    let mut odd = Vec::with_capacity(half_n);

    // Note that
    //     p_e(g^(2i)) = (p(g^i) + p(g^(n/2 + i))) / 2
    //     p_o(g^(2i)) = (p(g^i) - p(g^(n/2 + i))) / (2 s g^i)

    //     p_e(g^(2i)) = (a + b) / 2
    //     p_o(g^(2i)) = (a - b) / (2 s g^i)
    let one_half = F::two().inverse();
    let (first, second) = poly.split_at(half_n);
    for (g_inv_power, &a, &b) in izip!(g_inv.shifted_powers(shift.inverse()), first, second) {
        let sum = a + b;
        let diff = a - b;
        even.push(sum * one_half);
        odd.push(diff * one_half * g_inv_power);
    }

    let mut combined = decompose(even, shift.square(), log_chunks - 1);
    combined.extend(decompose(odd, shift.square(), log_chunks - 1));
    combined
}

/// Decompose the quotient polynomial into chunks using a generalization of even-odd decomposition.
/// Then, arrange the results in a row-major matrix, so that each chunk of the decomposed polynomial
/// becomes `D` columns of the resulting matrix, where `D` is the field extension degree.
pub fn decompose_and_flatten<SC: StarkConfig>(
    quotient_poly: Vec<SC::Challenge>,
    shift: SC::Challenge,
    log_chunks: usize,
) -> RowMajorMatrix<SC::Val> {
    let chunks: Vec<Vec<SC::Challenge>> = decompose(quotient_poly, shift, log_chunks);
    let degree = chunks[0].len();
    let quotient_chunks_flattened: Vec<SC::Val> = (0..degree)
        .into_par_iter()
        .flat_map_iter(|row| {
            chunks
                .iter()
                .flat_map(move |chunk| chunk[row].as_base_slice().iter().copied())
        })
        .collect();
    let challenge_ext_degree = <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
    RowMajorMatrix::new(
        quotient_chunks_flattened,
        challenge_ext_degree << log_chunks,
    )
}
