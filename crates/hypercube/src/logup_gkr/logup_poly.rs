use std::sync::Arc;

use rayon::prelude::*;
use slop_algebra::{
    interpolate_univariate_polynomial, ExtensionField, Field, UnivariatePolynomial,
};
use slop_multilinear::{Mle, Point};
use slop_sumcheck::{ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound};

use super::{InteractionLayer, LogUpGkrCpuLayer};

/// Polynomial representing a round of the GKR circuit.
pub struct LogupRoundPolynomial<F, EF> {
    /// The values of the numerator and denominator polynomials
    pub layer: PolynomialLayer<F, EF>,
    /// The partial lagrange evaluation for the row variables
    pub eq_row: Arc<Mle<EF>>,
    /// The partial lagrange evaluation for the interaction variables
    pub eq_interaction: Arc<Mle<EF>>,
    /// The correction term for the eq polynomial.
    pub eq_adjustment: EF,
    /// The correction term for padding
    pub padding_adjustment: EF,
    /// The batching factor for the numerator and denominator claims.
    pub lambda: EF,
    /// The random point for the current GKR round.
    pub point: Point<EF>,
}

/// A layer of the GKR circuit for the `LogupRoundPolynomial`.
pub enum PolynomialLayer<F, EF> {
    /// A layer of the GKR circuit.
    CircuitLayer(LogUpGkrCpuLayer<F, EF>),
    /// An interaction layer of the GKR circuit (`num_row_variables` == 1).
    InteractionLayer(InteractionLayer<F, EF>),
}

impl<F: Field, EF: ExtensionField<F>> SumcheckPolyBase for LogupRoundPolynomial<F, EF> {
    fn num_variables(&self) -> u32 {
        self.eq_row.num_variables() + self.eq_interaction.num_variables()
    }
}

impl<K: Field> ComponentPoly<K> for LogupRoundPolynomial<K, K> {
    fn get_component_poly_evals(&self) -> Vec<K> {
        match &self.layer {
            PolynomialLayer::InteractionLayer(layer) => {
                assert_eq!(layer.numerator_0.guts().as_slice().len(), 1);
                let numerator_0 = layer.numerator_0.guts().as_slice()[0];
                let denominator_0 = layer.denominator_0.guts().as_slice()[0];
                let numerator_1 = layer.numerator_1.guts().as_slice()[0];
                let denominator_1 = layer.denominator_1.guts().as_slice()[0];
                vec![numerator_0, denominator_0, numerator_1, denominator_1]
            }
            PolynomialLayer::CircuitLayer(_) => unreachable!(),
        }
    }
}

impl<K: Field> SumcheckPoly<K> for LogupRoundPolynomial<K, K> {
    fn fix_last_variable(self, alpha: K) -> Self {
        self.fix_t_variables(alpha, 1)
    }

    fn sum_as_poly_in_last_variable(&self, claim: Option<K>) -> UnivariatePolynomial<K> {
        self.sum_as_poly_in_last_t_variables(claim, 1)
    }
}

impl<K: ExtensionField<F>, F: Field> SumcheckPolyFirstRound<K> for LogupRoundPolynomial<F, K> {
    type NextRoundPoly = LogupRoundPolynomial<K, K>;
    #[allow(clippy::too_many_lines)]
    fn fix_t_variables(mut self, alpha: K, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1);
        // Remove the last coordinate from the point
        let last_coordinate = self.point.remove_last_coordinate();
        let padding_adjustment = self.padding_adjustment
            * (last_coordinate * alpha + (K::one() - last_coordinate) * (K::one() - alpha));
        match self.layer {
            PolynomialLayer::InteractionLayer(layer) => {
                let numerator_0 =
                    Arc::new(layer.numerator_0.as_ref().fix_last_variable::<K>(alpha));
                let denominator_0 =
                    Arc::new(layer.denominator_0.as_ref().fix_last_variable::<K>(alpha));
                let numerator_1 =
                    Arc::new(layer.numerator_1.as_ref().fix_last_variable::<K>(alpha));
                let denominator_1 =
                    Arc::new(layer.denominator_1.as_ref().fix_last_variable::<K>(alpha));

                let new_layer =
                    InteractionLayer { numerator_0, denominator_0, numerator_1, denominator_1 };

                let eq_interaction =
                    Arc::new(self.eq_interaction.as_ref().fix_last_variable(alpha));

                LogupRoundPolynomial {
                    layer: PolynomialLayer::InteractionLayer(new_layer),
                    eq_row: self.eq_row,
                    eq_interaction,
                    eq_adjustment: self.eq_adjustment,
                    padding_adjustment,
                    lambda: self.lambda,
                    point: self.point,
                }
            }
            PolynomialLayer::CircuitLayer(layer) => {
                if layer.num_row_variables == 1 {
                    let numerator_0: Vec<_> = layer
                        .numerator_0
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();
                    let denominator_0: Vec<_> = layer
                        .denominator_0
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();
                    let numerator_1: Vec<_> = layer
                        .numerator_1
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();
                    let denominator_1: Vec<_> = layer
                        .denominator_1
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();

                    let mut numerator_0_interactions: Vec<_> = numerator_0
                        .into_iter()
                        .flat_map(|mle| mle.eval_at::<K>(&Point::from(vec![])).to_vec())
                        .collect();
                    numerator_0_interactions
                        .resize(1 << layer.num_interaction_variables, K::zero());

                    let mut numerator_1_interactions: Vec<_> = numerator_1
                        .into_iter()
                        .flat_map(|mle| mle.eval_at::<K>(&Point::from(vec![])).to_vec())
                        .collect();
                    numerator_1_interactions
                        .resize(1 << layer.num_interaction_variables, K::zero());

                    let mut denominator_0_interactions: Vec<_> = denominator_0
                        .into_iter()
                        .flat_map(|mle| mle.eval_at::<K>(&Point::from(vec![])).to_vec())
                        .collect();
                    denominator_0_interactions
                        .resize(1 << layer.num_interaction_variables, K::one());

                    let mut denominator_1_interactions: Vec<_> = denominator_1
                        .into_iter()
                        .flat_map(|mle| mle.eval_at::<K>(&Point::from(vec![])).to_vec())
                        .collect();
                    denominator_1_interactions
                        .resize(1 << layer.num_interaction_variables, K::one());

                    let numerator_0_mle = Arc::new(Mle::from(numerator_0_interactions));
                    let denominator_0_mle = Arc::new(Mle::from(denominator_0_interactions));
                    let numerator_1_mle = Arc::new(Mle::from(numerator_1_interactions));
                    let denominator_1_mle = Arc::new(Mle::from(denominator_1_interactions));

                    let new_layer = InteractionLayer {
                        numerator_0: numerator_0_mle,
                        denominator_0: denominator_0_mle,
                        numerator_1: numerator_1_mle,
                        denominator_1: denominator_1_mle,
                    };

                    let eq_row = Arc::new(self.eq_row.as_ref().fix_last_variable(alpha));

                    LogupRoundPolynomial {
                        layer: PolynomialLayer::InteractionLayer(new_layer),
                        eq_row,
                        eq_interaction: self.eq_interaction,
                        eq_adjustment: padding_adjustment,
                        padding_adjustment: K::one(),
                        lambda: self.lambda,
                        point: self.point,
                    }
                } else {
                    let numerator_0: Vec<_> = layer
                        .numerator_0
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();

                    let denominator_0: Vec<_> = layer
                        .denominator_0
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();

                    let numerator_1: Vec<_> = layer
                        .numerator_1
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();

                    let denominator_1: Vec<_> = layer
                        .denominator_1
                        .into_iter()
                        .map(|mle| mle.fix_last_variable(alpha))
                        .collect();

                    let eq_row = Arc::new(self.eq_row.as_ref().fix_last_variable(alpha));

                    let new_layer = LogUpGkrCpuLayer {
                        numerator_0,
                        denominator_0,
                        numerator_1,
                        denominator_1,
                        num_row_variables: layer.num_row_variables - 1,
                        num_interaction_variables: layer.num_interaction_variables,
                    };

                    LogupRoundPolynomial {
                        layer: PolynomialLayer::CircuitLayer(new_layer),
                        eq_row,
                        eq_interaction: self.eq_interaction,
                        eq_adjustment: self.eq_adjustment,
                        padding_adjustment,
                        lambda: self.lambda,
                        point: self.point,
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<K>,
        t: usize,
    ) -> UnivariatePolynomial<K> {
        assert_eq!(t, 1);
        let claim = claim.unwrap();

        let (mut eval_zero, mut eval_half, eq_sum) = match &self.layer {
            PolynomialLayer::InteractionLayer(layer) => {
                let numerator_0 = layer.numerator_0.clone();
                let numerator_1 = layer.numerator_1.clone();
                let denominator_0 = layer.denominator_0.clone();
                let denominator_1 = layer.denominator_1.clone();
                let eq_interaction = self.eq_interaction.clone();
                let lambda = self.lambda;
                let numerator_eval_0 = numerator_0
                    .guts()
                    .as_slice()
                    .par_iter()
                    .step_by(2)
                    .zip_eq(numerator_1.guts().as_slice().par_iter().step_by(2))
                    .zip_eq(denominator_0.guts().as_slice().par_iter().step_by(2))
                    .zip_eq(denominator_1.guts().as_slice().par_iter().step_by(2))
                    .zip_eq(eq_interaction.guts().as_slice().par_iter().step_by(2))
                    .map(|((((n0, n1), d0), d1), e)| *e * (*d0 * *n1 + *d1 * *n0))
                    .sum::<K>();

                let numerator_eval_half = numerator_0
                    .guts()
                    .as_slice()
                    .par_chunks(2)
                    .zip_eq(numerator_1.guts().as_slice().par_chunks(2))
                    .zip_eq(denominator_0.guts().as_slice().par_chunks(2))
                    .zip_eq(denominator_1.guts().as_slice().par_chunks(2))
                    .zip_eq(eq_interaction.guts().as_slice().par_chunks(2))
                    .map(|((((n0_chunk, n1_chunk), d0_chunk), d1_chunk), e_chunk)| {
                        let n0_half = n0_chunk[0] + n0_chunk[1];
                        let n1_half = n1_chunk[0] + n1_chunk[1];
                        let d0_half = d0_chunk[0] + d0_chunk[1];
                        let d1_half = d1_chunk[0] + d1_chunk[1];
                        let e_half = e_chunk[0] + e_chunk[1];
                        e_half * (d0_half * n1_half + d1_half * n0_half)
                    })
                    .sum::<K>();

                let denominator_eval_0 = denominator_0
                    .guts()
                    .as_slice()
                    .par_iter()
                    .step_by(2)
                    .zip_eq(denominator_1.guts().as_slice().par_iter().step_by(2))
                    .zip_eq(eq_interaction.guts().as_slice().par_iter().step_by(2))
                    .map(|((d0, d1), e)| *e * (*d0 * *d1))
                    .sum::<K>();

                let denominator_eval_half = denominator_0
                    .guts()
                    .as_slice()
                    .par_chunks(2)
                    .zip_eq(denominator_1.guts().as_slice().par_chunks(2))
                    .zip_eq(eq_interaction.guts().as_slice().par_chunks(2))
                    .map(|((d0_chunk, d1_chunk), e_chunk)| {
                        let d0_half = d0_chunk[0] + d0_chunk[1];
                        let d1_half = d1_chunk[0] + d1_chunk[1];
                        let e_half = e_chunk[0] + e_chunk[1];
                        e_half * (d0_half * d1_half)
                    })
                    .sum::<K>();

                let eq_half_sum = eq_interaction
                    .guts()
                    .as_slice()
                    .par_chunks(2)
                    .map(|e_chunk| e_chunk[0] + e_chunk[1])
                    .sum::<K>();

                (
                    lambda * numerator_eval_0 + denominator_eval_0,
                    lambda * numerator_eval_half + denominator_eval_half,
                    eq_half_sum,
                )
            }
            PolynomialLayer::CircuitLayer(layer) => {
                let numerator_0 = layer.numerator_0.clone();
                let numerator_1 = layer.numerator_1.clone();
                let denominator_0 = layer.denominator_0.clone();
                let denominator_1 = layer.denominator_1.clone();
                let eq_row = self.eq_row.clone();
                // println!("eq_row.num_non_zero_entries(): {:?}", eq_row.num_non_zero_entries());
                assert!(eq_row.num_non_zero_entries().is_multiple_of(2));
                let eq_interaction = self.eq_interaction.clone();
                let lambda = self.lambda;

                let mut interaction_offset = 0;
                let mut eval_0 = K::zero();
                let mut eval_half = K::zero();
                let mut eq_sum = K::zero();
                for (numerator_0, numerator_1, denominator_0, denominator_1) in
                    itertools::izip!(numerator_0, numerator_1, denominator_0, denominator_1)
                {
                    if let Some(inner) = numerator_0.inner() {
                        assert!(numerator_0.num_variables() > 0);
                        let numerator_1_inner = numerator_1.inner().as_ref().unwrap();
                        // println!(
                        //     "numerator_1_inner.num_variables(): {:?}",
                        //     numerator_1_inner.num_variables()
                        // );
                        let denominator_0_inner = denominator_0.inner().as_ref().unwrap();
                        let denominator_1_inner = denominator_1.inner().as_ref().unwrap();
                        let (eval_0_chip, eval_half_chip, eq_sum_chip) =
                            inner
                                .guts()
                                .as_slice()
                                .par_chunks(2 * numerator_0.num_polynomials())
                                .zip_eq(
                                    numerator_1_inner
                                        .guts()
                                        .as_slice()
                                        .par_chunks(2 * numerator_1_inner.num_polynomials()),
                                )
                                .zip_eq(
                                    denominator_0_inner
                                        .guts()
                                        .as_slice()
                                        .par_chunks(2 * denominator_0_inner.num_polynomials()),
                                )
                                .zip_eq(
                                    denominator_1_inner
                                        .guts()
                                        .as_slice()
                                        .par_chunks(2 * denominator_1_inner.num_polynomials()),
                                )
                                .zip(eq_row.guts().as_slice().par_chunks(2))
                                .map(
                                    |(
                                        (((numer_0_row, numer_1_row), denom_0_row), denom_1_row),
                                        eq_row_chunk,
                                    )| {
                                        let eq_interactions_chip = eq_interaction.guts().as_slice()
                                            [interaction_offset
                                                ..interaction_offset
                                                    + numerator_0.num_polynomials()]
                                            .par_iter();

                                        let (numer_0_row_0, numer_0_row_1) =
                                            numer_0_row.split_at(numerator_0.num_polynomials());
                                        let (denom_0_row_0, denom_0_row_1) =
                                            denom_0_row.split_at(denominator_0.num_polynomials());
                                        let (denom_1_row_0, denom_1_row_1) =
                                            denom_1_row.split_at(denominator_1.num_polynomials());
                                        let (numer_1_row_0, numer_1_row_1) =
                                            numer_1_row.split_at(numerator_1.num_polynomials());
                                        let eq_row_0 = eq_row_chunk[0];
                                        let eq_row_1 = eq_row_chunk[1];
                                        if numer_0_row.len() == 2 * numerator_0.num_polynomials() {
                                            let numerator_0_eval = numer_0_row_0
                                                .par_iter()
                                                .zip_eq(numer_1_row_0.par_iter())
                                                .zip_eq(denom_0_row_0.par_iter())
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((((n0, n1), d0), d1), e)| {
                                                    // assert_eq!(*e, K::one());
                                                    *e * (*d0 * *n1 + *d1 * *n0)
                                                })
                                                .sum::<K>();
                                            let denominator_0_eval = denom_0_row_0
                                                .par_iter()
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((d0, d1), e)| *e * (*d0 * *d1))
                                                .sum::<K>();
                                            let numerator_half_eval = numer_0_row_0
                                            .par_iter()
                                            .zip_eq(numer_1_row_0.par_iter())
                                            .zip_eq(denom_0_row_0.par_iter())
                                            .zip_eq(denom_1_row_0.par_iter())
                                            .zip_eq(numer_0_row_1.par_iter())
                                            .zip_eq(numer_1_row_1.par_iter())
                                            .zip_eq(denom_0_row_1.par_iter())
                                            .zip_eq(denom_1_row_1.par_iter())
                                            .zip_eq(eq_interactions_chip.clone())
                                            .map(
                                                |(((
                                                    (
                                                        (
                                                            (((n0_0, n1_0), d0_0), d1_0),
                                                            n0_1,
                                                        ),
                                                        n1_1,
                                                    ),
                                                    d0_1), d1_1),
                                                    e,
                                                )| {
                                                    *e * ((*d0_0 + *d0_1) * (*n1_0 + *n1_1)
                                                        + (*d1_0 + *d1_1) * (*n0_0 + *n0_1))
                                                },
                                            )
                                            .sum::<K>();
                                            let denominator_half_eval = denom_0_row_0
                                                .par_iter()
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(denom_0_row_1.par_iter())
                                                .zip_eq(denom_1_row_1.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((((d0_0, d1_0), d0_1), d1_1), e)| {
                                                    *e * ((*d0_0 + *d0_1) * (*d1_0 + *d1_1))
                                                })
                                                .sum::<K>();
                                            let eq_interactions_chip_half = eq_interactions_chip
                                                .map(|e| *e * (eq_row_0 + eq_row_1))
                                                .sum::<K>();
                                            (
                                                (lambda * numerator_0_eval + denominator_0_eval)
                                                    * eq_row_0,
                                                (lambda * numerator_half_eval
                                                    + denominator_half_eval)
                                                    * (eq_row_0 + eq_row_1),
                                                eq_interactions_chip_half,
                                            )
                                        } else {
                                            let numerator_0_eval = numer_0_row_0
                                                .par_iter()
                                                .zip_eq(numer_1_row_0.par_iter())
                                                .zip_eq(denom_0_row_0.par_iter())
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((((n0, n1), d0), d1), e)| {
                                                    *e * (*d0 * *n1 + *d1 * *n0)
                                                })
                                                .sum::<K>();
                                            let denominator_0_eval = denom_0_row_0
                                                .par_iter()
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((d0, d1), e)| *e * (*d0 * *d1))
                                                .sum::<K>();
                                            let numerator_half_eval = numer_0_row_0
                                                .par_iter()
                                                .zip_eq(numer_1_row_0.par_iter())
                                                .zip_eq(denom_0_row_0.par_iter())
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((((n0, n1), d0), d1), e)| {
                                                    *e * ((*d0 + K::one()) * *n1
                                                        + (*d1 + K::one()) * *n0)
                                                })
                                                .sum::<K>();
                                            let denominator_half_eval = denom_0_row_0
                                                .par_iter()
                                                .zip_eq(denom_1_row_0.par_iter())
                                                .zip_eq(eq_interactions_chip.clone())
                                                .map(|((d0, d1), e)| {
                                                    *e * ((*d0 + K::one()) * (*d1 + K::one()))
                                                })
                                                .sum::<K>();
                                            let eq_interactions_chip_half = eq_interactions_chip
                                                .map(|e| *e * (eq_row_0 + eq_row_1))
                                                .sum::<K>();
                                            (
                                                (lambda * numerator_0_eval + denominator_0_eval)
                                                    * eq_row_0,
                                                (lambda * numerator_half_eval
                                                    + denominator_half_eval)
                                                    * (eq_row_0 + eq_row_1),
                                                eq_interactions_chip_half,
                                            )
                                        }
                                    },
                                )
                                .reduce(
                                    || (K::zero(), K::zero(), K::zero()),
                                    |(y_0_acc, y_half_acc, eq_sum_acc), (y_0, y_half, eq_sum)| {
                                        (y_0_acc + y_0, y_half_acc + y_half, eq_sum_acc + eq_sum)
                                    },
                                );
                        eval_0 += eval_0_chip;
                        eval_half += eval_half_chip;
                        eq_sum += eq_sum_chip;
                    }
                    interaction_offset += numerator_0.num_polynomials();
                    // println!("interaction_offset: {:?}", interaction_offset);
                }

                (eval_0, eval_half, eq_sum)
            }
        };

        // Correct the evaluations by the sum of the eq polynomial, which accounts for the
        // contribution of padded row for the denominator expression
        // `\Sum_i eq * denominator_0 * denominator_1`.
        let eq_correction_term = self.padding_adjustment - eq_sum;
        // println!("eq_correction_term: {:?}", eq_correction_term);
        // The evaluation at zero just gets the eq correction term.
        eval_zero += eq_correction_term * (K::one() - *self.point.last().unwrap());
        // The evaluation at 1/2 gets the eq correction term times 4, since the denominators
        // have a 1/2 in them for the rest of the evaluations (so we multiply by 2 twice).
        eval_half += eq_correction_term * K::from_canonical_u16(4);

        // Since the sumcheck polynomial is homogeneous of degree 3, we need to divide by
        // 8 = 2^3 to account for the evaluations at 1/2 to be double their true value.
        let eval_half = eval_half * K::from_canonical_u16(8).inverse();

        let eval_zero = eval_zero * self.eq_adjustment;
        let eval_half = eval_half * self.eq_adjustment;

        // Get the root of the eq polynomial which gives an evaluation of zero.
        let point_last = self.point.last().unwrap();
        let b_const = (K::one() - *point_last) / (K::one() - point_last.double());

        let eval_one = claim - eval_zero;

        interpolate_univariate_polynomial(
            &[
                K::from_canonical_u16(0),
                K::from_canonical_u16(1),
                K::from_canonical_u16(2).inverse(),
                b_const,
            ],
            &[eval_zero, eval_one, eval_half, K::zero()],
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{prove_gkr_round, GkrCircuitLayer, LogupGkrCpuTraceGenerator};

    use super::*;
    use itertools::Itertools;
    use rand::{thread_rng, Rng};
    use slop_algebra::{extension::BinomialExtensionField, AbstractField};
    use slop_alloc::CpuBackend;

    use slop_challenger::{FieldChallenger, IopCtx};
    use slop_matrix::dense::RowMajorMatrix;
    use slop_multilinear::{PaddedMle, Padding};
    use slop_sumcheck::{partially_verify_sumcheck_proof, reduce_sumcheck_to_evaluation};
    use slop_tensor::Tensor;
    use sp1_primitives::SP1Field;

    type EF = BinomialExtensionField<SP1Field, 4>;
    type F = SP1Field;

    fn random_layer(
        rng: &mut impl Rng,
        interaction_counts: &[usize],
        num_rows: usize,
        num_row_variables: usize,
        num_interaction_variables: usize,
    ) -> LogUpGkrCpuLayer<F, EF> {
        let numerator_0 = interaction_counts
            .iter()
            .map(|count| {
                let guts = Tensor::<F>::rand(rng, [num_rows, *count]);
                Mle::new(guts)
            })
            .collect::<Vec<_>>();
        let denominator_0 = interaction_counts
            .iter()
            .map(|count| {
                let guts = Tensor::<EF>::rand(rng, [num_rows, *count]);
                Mle::new(guts)
            })
            .collect::<Vec<_>>();
        let numerator_1 = interaction_counts
            .iter()
            .map(|count| {
                let guts = Tensor::<F>::rand(rng, [num_rows, *count]);
                Mle::new(guts)
            })
            .collect::<Vec<_>>();
        let denominator_1 = interaction_counts
            .iter()
            .map(|count| {
                let guts = Tensor::<EF>::rand(rng, [num_rows, *count]);
                Mle::new(guts)
            })
            .collect::<Vec<_>>();

        let padded_numerator_0 = numerator_0
            .iter()
            .map(|mle| {
                PaddedMle::padded_with_zeros(Arc::new(mle.clone()), num_row_variables as u32)
            })
            .collect::<Vec<_>>();

        let padded_denominator_0 = denominator_0
            .iter()
            .map(|mle| {
                let num_polys = mle.num_polynomials();
                PaddedMle::padded(
                    Arc::new(mle.clone()),
                    num_row_variables as u32,
                    Padding::Constant((EF::one(), num_polys, CpuBackend)),
                )
            })
            .collect::<Vec<_>>();

        let padded_numerator_1 = numerator_1
            .iter()
            .map(|mle| {
                PaddedMle::padded_with_zeros(Arc::new(mle.clone()), num_row_variables as u32)
            })
            .collect::<Vec<_>>();
        let padded_denominator_1 = denominator_1
            .iter()
            .map(|mle| {
                let num_polys = mle.num_polynomials();
                PaddedMle::padded(
                    Arc::new(mle.clone()),
                    num_row_variables as u32,
                    Padding::Constant((EF::one(), num_polys, CpuBackend)),
                )
            })
            .collect::<Vec<_>>();

        LogUpGkrCpuLayer {
            numerator_0: padded_numerator_0,
            denominator_0: padded_denominator_0,
            numerator_1: padded_numerator_1,
            denominator_1: padded_denominator_1,
            num_row_variables,
            num_interaction_variables,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_logup_poly_fix_last_variable() {
        let mut rng = thread_rng();
        let interaction_counts = vec![1];
        let num_rows: usize = 4;
        let num_row_variables = 2;
        let num_interaction_variables =
            interaction_counts.iter().sum::<usize>().next_power_of_two().ilog2();
        let layer = random_layer(
            &mut rng,
            &interaction_counts,
            num_rows,
            num_row_variables as usize,
            num_interaction_variables as usize,
        );

        let poly_point = Point::<EF>::rand(&mut rng, num_row_variables + num_interaction_variables);
        let (interaction_point, row_point) =
            poly_point.split_at(num_interaction_variables as usize);

        let random_point =
            Point::<EF>::rand(&mut rng, num_row_variables + num_interaction_variables);
        let (interaction_random_point, row_random_point) =
            random_point.split_at(num_interaction_variables as usize);

        let lambda = rng.gen::<EF>();
        let eq_row = Mle::partial_lagrange(&row_point);
        let eq_interaction = Mle::partial_lagrange(&interaction_point);

        let first_polynomial = LogupRoundPolynomial {
            layer: PolynomialLayer::CircuitLayer(layer),
            eq_row: Arc::new(eq_row),
            eq_interaction: Arc::new(eq_interaction),
            eq_adjustment: EF::one(),
            padding_adjustment: EF::one(),
            lambda,
            point: poly_point,
        };

        let PolynomialLayer::CircuitLayer(layer) = &first_polynomial.layer else {
            panic!("first polynomial is not a circuit layer");
        };

        let mut numerator_0_interactions: Vec<EF> = layer
            .numerator_0
            .iter()
            .flat_map(|mle| mle.eval_at::<EF>(&row_random_point).to_vec())
            .collect();
        numerator_0_interactions.resize(1 << layer.num_interaction_variables, EF::zero());

        let mut numerator_1_interactions: Vec<EF> = layer
            .numerator_1
            .iter()
            .flat_map(|mle| mle.eval_at::<EF>(&row_random_point).to_vec())
            .collect();
        numerator_1_interactions.resize(1 << layer.num_interaction_variables, EF::zero());

        let mut denominator_0_interactions: Vec<EF> = layer
            .denominator_0
            .iter()
            .flat_map(|mle| mle.eval_at::<EF>(&row_random_point).to_vec())
            .collect();
        denominator_0_interactions.resize(1 << layer.num_interaction_variables, EF::one());

        let mut denominator_1_interactions: Vec<EF> = layer
            .denominator_1
            .iter()
            .flat_map(|mle| mle.eval_at::<EF>(&row_random_point).to_vec())
            .collect();
        denominator_1_interactions.resize(1 << layer.num_interaction_variables, EF::one());

        // Fix last variable until we get to interaction layer
        let mut round_polynomial =
            first_polynomial.fix_t_variables(*row_random_point.last().unwrap(), 1);

        for alpha in row_random_point.iter().rev().skip(1) {
            round_polynomial = round_polynomial.fix_t_variables(*alpha, 1);
        }

        let PolynomialLayer::InteractionLayer(interaction_layer) = &round_polynomial.layer else {
            panic!("round polynomial is not an interaction layer");
        };

        // Check expected mle against actual mle for first interaction layer
        for (i, numerator_0_interaction) in numerator_0_interactions.iter().enumerate() {
            assert_eq!(
                *numerator_0_interaction,
                interaction_layer.numerator_0.guts().as_slice()[i]
            );
        }
        for (i, numerator_1_interaction) in numerator_1_interactions.iter().enumerate() {
            assert_eq!(
                *numerator_1_interaction,
                interaction_layer.numerator_1.guts().as_slice()[i]
            );
        }
        for (i, denominator_0_interaction) in denominator_0_interactions.iter().enumerate() {
            assert_eq!(
                *denominator_0_interaction,
                interaction_layer.denominator_0.guts().as_slice()[i]
            );
        }
        for (i, denominator_1_interaction) in denominator_1_interactions.iter().enumerate() {
            assert_eq!(
                *denominator_1_interaction,
                interaction_layer.denominator_1.guts().as_slice()[i]
            );
        }

        // Get the expected evaluations
        let numerator_0_eval = interaction_layer.numerator_0.eval_at(&interaction_random_point)[0];
        let numerator_1_eval = interaction_layer.numerator_1.eval_at(&interaction_random_point)[0];
        let denominator_0_eval =
            interaction_layer.denominator_0.eval_at(&interaction_random_point)[0];
        let denominator_1_eval =
            interaction_layer.denominator_1.eval_at(&interaction_random_point)[0];

        // Proceed with rest of interaction layers.
        for alpha in interaction_random_point.iter().rev() {
            round_polynomial = round_polynomial.fix_t_variables(*alpha, 1);
        }

        let [n0, d0, n1, d1] = round_polynomial.get_component_poly_evals().try_into().unwrap();

        assert_eq!(numerator_0_eval, n0);
        assert_eq!(numerator_1_eval, n1);
        assert_eq!(denominator_0_eval, d0);
        assert_eq!(denominator_1_eval, d1);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_logup_poly_sumcheck_circuit_layer() {
        type GC = sp1_primitives::SP1GlobalContext;
        let mut rng = thread_rng();

        let get_challenger = move || GC::default_challenger();

        let interaction_counts = vec![4, 5, 6];
        let num_rows: usize = 8;
        let num_row_variables = 4;

        let num_interaction_variables =
            interaction_counts.iter().sum::<usize>().next_power_of_two().ilog2();
        let layer = random_layer(
            &mut rng,
            &interaction_counts,
            num_rows,
            num_row_variables as usize,
            num_interaction_variables as usize,
        );

        let poly_point = Point::<EF>::rand(&mut rng, num_row_variables + num_interaction_variables);
        let (interaction_point, row_point) =
            poly_point.split_at(num_interaction_variables as usize);

        let eq_row = Mle::partial_lagrange(&row_point);
        let eq_interaction = Mle::partial_lagrange(&interaction_point);

        let numerator_0 = layer.numerator_0.clone();
        let numerator_1 = layer.numerator_1.clone();
        let denominator_0 = layer.denominator_0.clone();
        let denominator_1 = layer.denominator_1.clone();
        let lambda = rng.gen::<EF>();

        let round_polynomial = LogupRoundPolynomial {
            layer: PolynomialLayer::CircuitLayer(layer),
            eq_row: Arc::new(eq_row),
            eq_interaction: Arc::new(eq_interaction),
            eq_adjustment: EF::one(),
            padding_adjustment: EF::one(),
            lambda,
            point: poly_point.clone(),
        };

        let total_eq = Mle::partial_lagrange(&poly_point);

        let total_eq_guts = total_eq.guts().as_slice().to_vec().clone();

        let claim = {
            let mut offset = 0;
            let real_claim = numerator_0
                .iter()
                .zip_eq(numerator_1.iter())
                .zip_eq(denominator_0.iter())
                .zip_eq(denominator_1.iter())
                .map(|(((n_0, n_1), d_0), d_1)| {
                    // Add padded rows to n0 so that num_rows is next power of 2
                    let num_padding = vec![
                        F::zero();
                        ((1 << num_row_variables) - num_rows)
                            * n_0.num_polynomials()
                    ];
                    let den_padding = vec![
                        EF::one();
                        ((1 << num_row_variables) - num_rows)
                            * d_0.num_polynomials()
                    ];

                    let padded_n0 = n_0
                        .inner()
                        .as_ref()
                        .unwrap()
                        .guts()
                        .as_slice()
                        .iter()
                        .copied()
                        .chain(num_padding.iter().copied())
                        .collect::<Vec<_>>();
                    let padded_n1 = n_1
                        .inner()
                        .as_ref()
                        .unwrap()
                        .guts()
                        .as_slice()
                        .iter()
                        .copied()
                        .chain(num_padding.iter().copied())
                        .collect::<Vec<_>>();
                    let padded_d0 = d_0
                        .inner()
                        .as_ref()
                        .unwrap()
                        .guts()
                        .as_slice()
                        .iter()
                        .copied()
                        .chain(den_padding.iter().copied())
                        .collect::<Vec<_>>();
                    let padded_d1 = d_1
                        .inner()
                        .as_ref()
                        .unwrap()
                        .guts()
                        .as_slice()
                        .iter()
                        .copied()
                        .chain(den_padding.iter().copied())
                        .collect::<Vec<_>>();
                    let padded_d0 =
                        Mle::from(RowMajorMatrix::new(padded_d0, d_0.num_polynomials()));
                    let padded_d1 =
                        Mle::from(RowMajorMatrix::new(padded_d1, d_1.num_polynomials()));
                    let padded_n0 =
                        Mle::from(RowMajorMatrix::new(padded_n0, n_0.num_polynomials()));
                    let padded_n1 =
                        Mle::from(RowMajorMatrix::new(padded_n1, n_1.num_polynomials()));

                    let result = padded_n0
                        .guts()
                        .transpose()
                        .as_slice()
                        .iter()
                        .zip_eq(padded_n1.guts().transpose().as_slice().iter())
                        .zip_eq(padded_d0.guts().transpose().as_slice().iter())
                        .zip_eq(padded_d1.guts().transpose().as_slice().iter())
                        .zip(total_eq_guts.iter().skip(offset))
                        .map(|((((n_0, n_1), d_0), d_1), e)| {
                            let numerator_eval = *d_1 * *n_0 + *d_0 * *n_1;
                            let denominator_eval = *d_0 * *d_1;
                            *e * (numerator_eval * lambda + denominator_eval)
                        })
                        .sum::<EF>();

                    offset += padded_n0.guts().as_slice().len();
                    result
                })
                .sum::<EF>();
            let remaining_eq = total_eq_guts.iter().copied().skip(offset).sum::<EF>();
            real_claim + remaining_eq
        };

        let mut challenger = get_challenger();
        let (proof, evals) = reduce_sumcheck_to_evaluation(
            vec![round_polynomial],
            &mut challenger,
            vec![claim],
            1,
            EF::one(),
        );

        let mut challenger = get_challenger();
        partially_verify_sumcheck_proof(
            &proof,
            &mut challenger,
            (num_row_variables + num_interaction_variables) as usize,
            3,
        )
        .unwrap();

        let (point, expected_final_eval) = proof.point_and_eval;

        // Assert that the point has the expected dimension.
        assert_eq!(point.dimension() as u32, num_row_variables + num_interaction_variables);

        // Calculate the expected evaluations at the point.
        let [evals] = evals.try_into().unwrap();
        assert_eq!(evals.len(), 4);
        let [n_0, d_0, n_1, d_1] = evals.try_into().unwrap();

        let eq_eval = Mle::full_lagrange_eval(&poly_point, &point);

        let expected_numerator_eval = n_0 * d_1 + n_1 * d_0;
        let expected_denominator_eval = d_0 * d_1;
        let eval = expected_numerator_eval * lambda + expected_denominator_eval;
        let final_eval = eq_eval * eval;

        // Assert that the final eval is correct.
        assert_eq!(final_eval, expected_final_eval);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_logup_gkr_circuit_transition() {
        type TraceGenerator = LogupGkrCpuTraceGenerator<SP1Field, EF, ()>;
        let mut rng = thread_rng();

        let trace_generator = TraceGenerator::default();

        let interaction_counts = vec![4, 5, 6];
        let num_rows: usize = 8;
        let num_row_variables = 4;
        let num_interaction_variables =
            interaction_counts.iter().sum::<usize>().next_power_of_two().ilog2();
        let layer = random_layer(
            &mut rng,
            &interaction_counts,
            num_rows,
            num_row_variables as usize,
            num_interaction_variables as usize,
        );
        let next_layer = trace_generator.layer_transition(&layer);

        let curr_numerator_0 = layer.numerator_0;
        let curr_numerator_1 = layer.numerator_1;
        let curr_denominator_0 = layer.denominator_0;
        let curr_denominator_1 = layer.denominator_1;

        let next_numerator_0 = next_layer.numerator_0;
        let next_numerator_1 = next_layer.numerator_1;
        let next_denominator_0 = next_layer.denominator_0;
        let next_denominator_1 = next_layer.denominator_1;

        for (next_n0, next_n1, next_d0, next_d1, curr_n0, curr_n1, curr_d0, curr_d1) in itertools::izip!(
            next_numerator_0.iter(),
            next_numerator_1.iter(),
            next_denominator_0.iter(),
            next_denominator_1.iter(),
            curr_numerator_0.iter(),
            curr_numerator_1.iter(),
            curr_denominator_0.iter(),
            curr_denominator_1.iter()
        ) {
            let next_n1_inner = next_n1.inner().as_ref().unwrap();
            let next_n0_inner = next_n0.inner().as_ref().unwrap();
            let next_d0_inner = next_d0.inner().as_ref().unwrap();
            let next_d1_inner = next_d1.inner().as_ref().unwrap();
            let curr_n0_inner = curr_n0.inner().as_ref().unwrap();
            let curr_n1_inner = curr_n1.inner().as_ref().unwrap();
            let curr_d0_inner = curr_d0.inner().as_ref().unwrap();
            let curr_d1_inner = curr_d1.inner().as_ref().unwrap();
            let _ = next_n0_inner
                .guts()
                .transpose()
                .as_slice()
                .chunks(next_n0.num_real_entries())
                .zip_eq(
                    next_n1_inner.guts().transpose().as_slice().chunks(next_n1.num_real_entries()),
                )
                .zip_eq(
                    curr_n0_inner
                        .guts()
                        .transpose()
                        .as_slice()
                        .chunks(curr_n0.num_real_entries())
                        .zip_eq(
                            curr_n1_inner
                                .guts()
                                .transpose()
                                .as_slice()
                                .chunks(curr_n1.num_real_entries()),
                        ),
                )
                .zip_eq(
                    curr_d0_inner
                        .guts()
                        .transpose()
                        .as_slice()
                        .chunks(curr_d0.num_real_entries())
                        .zip_eq(
                            curr_d1_inner
                                .guts()
                                .transpose()
                                .as_slice()
                                .chunks(curr_d1.num_real_entries()),
                        ),
                )
                .map(
                    |(
                        ((n0_col, n1_col), (curr_n0_col, curr_n1_col)),
                        (curr_d0_col, curr_d1_col),
                    )| {
                        let next_n = n0_col.iter().interleave(n1_col.iter()).collect::<Vec<_>>();
                        for (
                            i,
                            ((((next_n_val, curr_n0_val), curr_n1_val), curr_d0_val), curr_d1_val),
                        ) in next_n
                            .iter()
                            .copied()
                            .zip_eq(curr_n0_col.iter())
                            .zip_eq(curr_n1_col.iter())
                            .zip_eq(curr_d0_col.iter())
                            .zip_eq(curr_d1_col.iter())
                            .enumerate()
                        {
                            assert_eq!(
                                *next_n_val,
                                *curr_d1_val * *curr_n0_val + *curr_d0_val * *curr_n1_val,
                                "failed at index {i}"
                            );
                        }
                    },
                );
            let _ = next_d0_inner
                .guts()
                .transpose()
                .as_slice()
                .chunks(next_d0.num_real_entries())
                .zip_eq(
                    next_d1_inner.guts().transpose().as_slice().chunks(next_d1.num_real_entries()),
                )
                .zip_eq(
                    curr_d0_inner
                        .guts()
                        .transpose()
                        .as_slice()
                        .chunks(curr_d0.num_real_entries())
                        .zip_eq(
                            curr_d1_inner
                                .guts()
                                .transpose()
                                .as_slice()
                                .chunks(curr_d1.num_real_entries()),
                        ),
                )
                .map(|((next_d0_col, next_d1_col), (curr_d0_col, curr_d1_col))| {
                    let next_d =
                        next_d0_col.iter().interleave(next_d1_col.iter()).collect::<Vec<_>>();
                    for (i, ((next_d_val, curr_d0_val), curr_d1_val)) in next_d
                        .iter()
                        .copied()
                        .zip_eq(curr_d0_col.iter())
                        .zip_eq(curr_d1_col.iter())
                        .enumerate()
                    {
                        assert_eq!(*next_d_val, *curr_d0_val * *curr_d1_val, "failed at index {i}");
                    }
                });
        }
    }

    #[test]
    fn test_logup_gkr_round_prover() {
        type GC = sp1_primitives::SP1GlobalContext;
        type TraceGenerator = LogupGkrCpuTraceGenerator<SP1Field, EF, ()>;
        let get_challenger = move || GC::default_challenger();
        let trace_generator = TraceGenerator::default();

        let mut rng = thread_rng();

        let interaction_counts = vec![4, 5, 6];
        let num_interaction_variables =
            interaction_counts.iter().sum::<usize>().next_power_of_two().ilog2();
        let num_rows: usize = 32;
        let num_row_variables = 7;
        let input_layer = random_layer(
            &mut rng,
            &interaction_counts,
            num_rows,
            num_row_variables as usize,
            num_interaction_variables as usize,
        );

        let first_eval_point = Point::<EF>::rand(&mut rng, num_interaction_variables + 1);

        let layer = GkrCircuitLayer::FirstLayer(input_layer);

        let mut layers = vec![layer];
        for _ in 0..num_row_variables - 1 {
            let next_layer = match layers.last().unwrap() {
                GkrCircuitLayer::Layer(layer) => trace_generator.layer_transition(layer),
                GkrCircuitLayer::FirstLayer(layer) => trace_generator.layer_transition(layer),
            };
            layers.push(GkrCircuitLayer::Layer(next_layer));
        }
        layers.reverse();

        let GkrCircuitLayer::Layer(first_layer) = layers.first().unwrap() else {
            panic!("first layer not correct");
        };

        let output = trace_generator.extract_outputs(first_layer);
        assert_eq!(output.numerator.num_variables(), num_interaction_variables + 1);
        assert_eq!(output.denominator.num_variables(), num_interaction_variables + 1);

        let first_numerator_eval = output.numerator.eval_at(&first_eval_point)[0];
        let first_denominator_eval = output.denominator.eval_at(&first_eval_point)[0];

        let mut challenger = get_challenger();
        let mut round_proofs = Vec::new();
        let mut numerator_eval = first_numerator_eval;
        let mut denominator_eval = first_denominator_eval;
        let mut eval_point = first_eval_point.clone();

        for layer in layers {
            let round_proof = prove_gkr_round(
                layer,
                &eval_point,
                numerator_eval,
                denominator_eval,
                &mut challenger,
            );
            // Observe the prover message.
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_1);
            // Get the evaluation point for the claims.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();
            // Sample the last coordinate.
            let last_coordinate = challenger.sample_ext_element::<EF>();

            // Compute the evaluation of the numerator and denominator at the last coordinate.
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
            eval_point.add_dimension_back(last_coordinate);
            // Add the round proof to the total
            round_proofs.push(round_proof);
        }

        // Follow the GKR protocol layer by layer.
        let mut challenger = get_challenger();
        let mut numerator_eval = first_numerator_eval;
        let mut denominator_eval = first_denominator_eval;
        let mut eval_point = first_eval_point;
        for (i, round_proof) in round_proofs.iter().enumerate() {
            // Get the batching challenge for combining the claims.
            let lambda = challenger.sample_ext_element::<EF>();
            // Check that the claimed sum is consistent with the previous round values.
            let expected_claim = numerator_eval * lambda + denominator_eval;
            assert_eq!(round_proof.sumcheck_proof.claimed_sum, expected_claim);

            // Verify the sumcheck proof.
            partially_verify_sumcheck_proof(
                &round_proof.sumcheck_proof,
                &mut challenger,
                i + num_interaction_variables as usize + 1,
                3,
            )
            .unwrap();

            // Verify that the evaluation claim is consistent with the prover messages.
            let (point, final_eval) = round_proof.sumcheck_proof.point_and_eval.clone();
            let eq_eval = Mle::full_lagrange_eval(&point, &eval_point);
            let numerator_sumcheck_eval = round_proof.numerator_0 * round_proof.denominator_1
                + round_proof.numerator_1 * round_proof.denominator_0;
            let denominator_sumcheck_eval = round_proof.denominator_0 * round_proof.denominator_1;
            let expected_final_eval =
                eq_eval * (numerator_sumcheck_eval * lambda + denominator_sumcheck_eval);

            assert_eq!(final_eval, expected_final_eval, "failed at index {i}");

            // Observe the prover message.
            challenger.observe_ext_element(round_proof.numerator_0);
            challenger.observe_ext_element(round_proof.denominator_0);
            challenger.observe_ext_element(round_proof.numerator_1);
            challenger.observe_ext_element(round_proof.denominator_1);

            // Get the evaluation point for the claims.
            eval_point = round_proof.sumcheck_proof.point_and_eval.0.clone();

            // Sample the last coordinate and add to the point.
            let last_coordinate = challenger.sample_ext_element::<EF>();
            eval_point.add_dimension_back(last_coordinate);
            // Update the evaluation of the numerator and denominator at the last coordinate.
            numerator_eval = round_proof.numerator_0
                + (round_proof.numerator_1 - round_proof.numerator_0) * last_coordinate;
            denominator_eval = round_proof.denominator_0
                + (round_proof.denominator_1 - round_proof.denominator_0) * last_coordinate;
        }
    }
}
