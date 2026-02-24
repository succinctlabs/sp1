use itertools::Itertools;
use rayon::prelude::*;
use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{Mle, PaddedMle, Padding, Point};
use std::{collections::BTreeMap, sync::Arc};

use crate::{prover::Traces, Interaction};

use super::{LogUpGkrCpuLayer, LogUpGkrOutput, LogupGkrCpuTraceGenerator};

pub(crate) fn generate_interaction_vals<F: Field, EF: ExtensionField<F>>(
    interaction: &Interaction<F>,
    preprocessed_row: &[F],
    main_row: &[F],
    is_send: bool,
    alpha: EF,
    betas: &[EF],
) -> (F, EF) {
    let mut denominator = alpha;
    let mut betas = betas.iter();
    denominator += *betas.next().unwrap() * EF::from_canonical_usize(interaction.argument_index());
    for (columns, beta) in interaction.values.iter().zip(betas) {
        let apply = columns.apply::<F, F>(preprocessed_row, main_row);
        denominator += *beta * apply;
    }
    let mut mult = interaction.multiplicity.apply::<F, F>(preprocessed_row, main_row);

    if !is_send {
        mult = -mult;
    }

    (mult, denominator)
}

impl<F: Field, EF: ExtensionField<F>, A> LogupGkrCpuTraceGenerator<F, EF, A> {
    #[allow(clippy::unused_self)]
    pub(crate) fn extract_outputs(
        &self,
        last_layer: &LogUpGkrCpuLayer<EF, EF>,
    ) -> LogUpGkrOutput<EF> {
        let numerator_0 = last_layer.numerator_0.clone();
        let numerator_1 = last_layer.numerator_1.clone();
        let denominator_0 = last_layer.denominator_0.clone();
        let denominator_1 = last_layer.denominator_1.clone();

        let mut numerator_0_interactions: Vec<EF> = numerator_0
            .into_iter()
            .flat_map(|mle| {
                let n00 = mle.fix_last_variable(EF::zero());
                let n01 = mle.fix_last_variable(EF::one());
                let n00_int = n00.eval_at::<EF>(&Point::from(vec![])).to_vec();
                let n01_int = n01.eval_at::<EF>(&Point::from(vec![])).to_vec();
                n00_int.iter().interleave(n01_int.iter()).copied().collect::<Vec<_>>()
            })
            .collect();
        numerator_0_interactions
            .resize(1 << (last_layer.num_interaction_variables + 1), EF::zero());
        let mut numerator_1_interactions: Vec<EF> = numerator_1
            .into_iter()
            .flat_map(|mle| {
                let n10 = mle.fix_last_variable(EF::zero());
                let n11 = mle.fix_last_variable(EF::one());
                let n10_int = n10.eval_at::<EF>(&Point::from(vec![])).to_vec();
                let n11_int = n11.eval_at::<EF>(&Point::from(vec![])).to_vec();
                n10_int.iter().interleave(n11_int.iter()).copied().collect::<Vec<_>>()
            })
            .collect();
        numerator_1_interactions
            .resize(1 << (last_layer.num_interaction_variables + 1), EF::zero());
        let mut denominator_0_interactions: Vec<EF> = denominator_0
            .into_iter()
            .flat_map(|mle| {
                let d00 = mle.fix_last_variable(EF::zero());
                let d01 = mle.fix_last_variable(EF::one());
                let d00_int = d00.eval_at::<EF>(&Point::from(vec![])).to_vec();
                let d01_int = d01.eval_at::<EF>(&Point::from(vec![])).to_vec();
                d00_int.iter().interleave(d01_int.iter()).copied().collect::<Vec<_>>()
            })
            .collect();
        denominator_0_interactions
            .resize(1 << (last_layer.num_interaction_variables + 1), EF::one());
        let mut denominator_1_interactions: Vec<EF> = denominator_1
            .into_iter()
            .flat_map(|mle| {
                let d10 = mle.fix_last_variable(EF::zero());
                let d11 = mle.fix_last_variable(EF::one());
                let d10_int = d10.eval_at::<EF>(&Point::from(vec![])).to_vec();
                let d11_int = d11.eval_at::<EF>(&Point::from(vec![])).to_vec();
                d10_int.iter().interleave(d11_int.iter()).copied().collect::<Vec<_>>()
            })
            .collect();
        denominator_1_interactions
            .resize(1 << (last_layer.num_interaction_variables + 1), EF::one());

        let (numerator, denominator): (Vec<_>, Vec<_>) = numerator_0_interactions
            .iter()
            .zip_eq(numerator_1_interactions.iter())
            .zip_eq(denominator_0_interactions.iter().zip_eq(denominator_1_interactions.iter()))
            .map(|((n_0, n_1), (d_0, d_1))| (*n_0 * *d_1 + *n_1 * *d_0, *d_0 * *d_1))
            .unzip();

        let numerator = Mle::from(numerator);
        let denominator = Mle::from(denominator);

        LogUpGkrOutput { numerator, denominator }
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::unused_self)]
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn generate_first_layer(
        &self,
        interactions: &BTreeMap<String, Vec<(&Interaction<F>, bool)>>,
        main_traces: &Traces<F, CpuBackend>,
        preprocessed_traces: &Traces<F, CpuBackend>,
        alpha: EF,
        beta_seed: Point<EF>,
    ) -> LogUpGkrCpuLayer<F, EF> {
        let first_trace = main_traces.values().next().unwrap();
        let num_row_variables = first_trace.num_variables();

        let mut numerator_0 = Vec::new();
        let mut denominator_0 = Vec::new();
        let mut numerator_1 = Vec::new();
        let mut denominator_1 = Vec::new();
        let betas = Mle::partial_lagrange(&beta_seed).guts().as_slice().to_vec();
        let mut total_interactions = 0;
        for (name, interactions) in interactions.iter() {
            let main_trace = main_traces.get(name.as_str()).unwrap().clone();
            let height = main_trace.num_real_entries();

            let preprocessed_trace = preprocessed_traces.get(name.as_str()).cloned();
            let num_interactions = interactions.len();
            total_interactions += num_interactions;
            let mut numer_evals = vec![F::zero(); height * num_interactions];
            let mut denom_evals = vec![EF::one(); height * num_interactions];

            if height > 0 {
                match preprocessed_trace {
                    Some(prep) => {
                        numer_evals
                            .par_chunks_exact_mut(num_interactions)
                            .zip_eq(denom_evals.par_chunks_exact_mut(num_interactions))
                            .zip_eq(
                                prep.inner()
                                    .as_ref()
                                    .unwrap()
                                    .guts()
                                    .as_slice()
                                    .par_chunks(prep.num_polynomials())
                                    .zip(
                                        main_trace
                                            .inner()
                                            .as_ref()
                                            .unwrap()
                                            .guts()
                                            .as_slice()
                                            .par_chunks(main_trace.num_polynomials()),
                                    ),
                            )
                            .for_each(|((numer_evals, denom_evals), (prep_row, main_row))| {
                                interactions
                                    .iter()
                                    .zip(numer_evals.iter_mut())
                                    .zip(denom_evals.iter_mut())
                                    .for_each(
                                        |(((interaction, is_send), numer_eval), denom_eval)| {
                                            let (numer, denom) = generate_interaction_vals(
                                                interaction,
                                                prep_row,
                                                main_row,
                                                *is_send,
                                                alpha,
                                                &betas,
                                            );
                                            *numer_eval = numer;
                                            *denom_eval = denom;
                                        },
                                    );
                            });
                    }
                    None => {
                        numer_evals
                            .par_chunks_exact_mut(num_interactions)
                            .zip_eq(denom_evals.par_chunks_exact_mut(num_interactions))
                            .zip_eq(
                                main_trace
                                    .inner()
                                    .as_ref()
                                    .unwrap()
                                    .guts()
                                    .as_slice()
                                    .par_chunks(main_trace.num_polynomials()),
                            )
                            .for_each(|((numer_evals, denom_evals), main_row)| {
                                interactions
                                    .iter()
                                    .zip(numer_evals.iter_mut())
                                    .zip(denom_evals.iter_mut())
                                    .for_each(
                                        |(((interaction, is_send), numer_eval), denom_eval)| {
                                            let (numer, denom) = generate_interaction_vals(
                                                interaction,
                                                &[],
                                                main_row,
                                                *is_send,
                                                alpha,
                                                &betas,
                                            );
                                            *numer_eval = numer;
                                            *denom_eval = denom;
                                        },
                                    );
                            });
                    }
                }
            }

            let numerator = RowMajorMatrix::new(numer_evals, num_interactions);
            let denominator = RowMajorMatrix::new(denom_evals, num_interactions);
            let numer_mle = Mle::from(numerator);
            let denom_mle = Mle::from(denominator);
            let numer_padded = PaddedMle::padded_with_zeros(Arc::new(numer_mle), num_row_variables);
            let num_polys = denom_mle.num_polynomials();
            let denom_padded = PaddedMle::padded(
                Arc::new(denom_mle),
                num_row_variables,
                Padding::Constant((EF::one(), num_polys, CpuBackend)),
            );
            let numer_0 = numer_padded.fix_last_variable(F::zero());
            let denom_0 = denom_padded.fix_last_variable(EF::zero());
            let numer_1 = numer_padded.fix_last_variable(F::one());
            let denom_1 = denom_padded.fix_last_variable(EF::one());
            numerator_0.push(numer_0);
            denominator_0.push(denom_0);
            numerator_1.push(numer_1);
            denominator_1.push(denom_1);
        }
        let num_interaction_variables = total_interactions.next_power_of_two().ilog2();

        LogUpGkrCpuLayer {
            numerator_0,
            denominator_0,
            numerator_1,
            denominator_1,
            num_interaction_variables: num_interaction_variables as usize,
            num_row_variables: (num_row_variables - 1) as usize,
        }
    }

    #[allow(clippy::too_many_lines)]
    #[allow(clippy::unused_self)]
    pub(crate) fn layer_transition<K>(
        &self,
        layer: &LogUpGkrCpuLayer<K, EF>,
    ) -> LogUpGkrCpuLayer<EF, EF>
    where
        K: Field + Into<EF> + Copy,
    {
        // let row_count = layer.numerator_0.first().unwrap().num_real_entries().div_ceil(2);
        let num_row_variables = layer.numerator_0.first().unwrap().num_variables();
        assert_eq!(num_row_variables, layer.num_row_variables as u32);
        let mut numerator_0 = Vec::new();
        let mut denominator_0 = Vec::new();
        let mut numerator_1 = Vec::new();
        let mut denominator_1 = Vec::new();
        for (n0_padded, d0_padded, n1_padded, d1_padded) in itertools::izip!(
            layer.numerator_0.clone(),
            layer.denominator_0.clone(),
            layer.numerator_1.clone(),
            layer.denominator_1.clone()
        ) {
            let num_interactions = n0_padded.num_polynomials();
            let row_count = n0_padded.num_real_entries().div_ceil(2);
            let mut next_n0 = vec![EF::zero(); row_count * num_interactions];
            let mut next_d0 = vec![EF::one(); row_count * num_interactions];
            let mut next_n1 = vec![EF::zero(); row_count * num_interactions];
            let mut next_d1 = vec![EF::one(); row_count * num_interactions];
            if let Some(n0_mle) = n0_padded.inner().as_ref() {
                let d0_mle = d0_padded.inner().as_ref().unwrap();
                let n1_mle = n1_padded.inner().as_ref().unwrap();
                let d1_mle = d1_padded.inner().as_ref().unwrap();
                n0_mle
                    .guts()
                    .as_slice()
                    .par_chunks(2 * num_interactions)
                    .zip_eq(d0_mle.guts().as_slice().par_chunks(2 * num_interactions))
                    .zip_eq(n1_mle.guts().as_slice().par_chunks(2 * num_interactions))
                    .zip_eq(d1_mle.guts().as_slice().par_chunks(2 * num_interactions))
                    .zip_eq(next_n0.par_chunks_exact_mut(num_interactions))
                    .zip_eq(next_d0.par_chunks_exact_mut(num_interactions))
                    .zip_eq(next_n1.par_chunks_exact_mut(num_interactions))
                    .zip_eq(next_d1.par_chunks_exact_mut(num_interactions))
                    .for_each(
                        |(
                            (
                                (
                                    ((((n0_chunk, d0_chunk), n1_chunk), d1_chunk), next_n0_row),
                                    next_d0_row,
                                ),
                                next_n1_row,
                            ),
                            next_d1_row,
                        )| {
                            let (n_00_row, n_10_row) = n0_chunk.split_at(num_interactions);
                            let (d_00_row, d_10_row) = d0_chunk.split_at(num_interactions);
                            let (n_01_row, n_11_row) = n1_chunk.split_at(num_interactions);
                            let (d_01_row, d_11_row) = d1_chunk.split_at(num_interactions);

                            n_00_row
                                .par_iter()
                                .zip_eq(d_00_row.par_iter())
                                .zip_eq(n_01_row.par_iter())
                                .zip_eq(d_01_row.par_iter())
                                .zip_eq(next_n0_row.par_iter_mut())
                                .zip_eq(next_d0_row.par_iter_mut())
                                .for_each(|(((((n_00, d_00), n_01), d_01), next_n0), next_d0)| {
                                    let n00: EF = (*n_00).into();
                                    let n01: EF = (*n_01).into();
                                    let n0 = *d_01 * n00 + *d_00 * n01;
                                    let d0 = *d_00 * *d_01;
                                    *next_n0 = n0;
                                    *next_d0 = d0;
                                });
                            if n0_chunk.len() == 2 * num_interactions {
                                n_10_row
                                    .par_iter()
                                    .zip_eq(d_10_row.par_iter())
                                    .zip_eq(n_11_row.par_iter())
                                    .zip_eq(d_11_row.par_iter())
                                    .zip_eq(next_n1_row.par_iter_mut())
                                    .zip_eq(next_d1_row.par_iter_mut())
                                    .for_each(
                                        |(((((n_10, d_10), n_11), d_11), next_n1), next_d1)| {
                                            let n10: EF = (*n_10).into();
                                            let n11: EF = (*n_11).into();
                                            let n1 = *d_11 * n10 + *d_10 * n11;
                                            let d1 = *d_10 * *d_11;
                                            *next_n1 = n1;
                                            *next_d1 = d1;
                                        },
                                    );
                            }
                        },
                    );
            }
            let next_n0_padded = PaddedMle::padded_with_zeros(
                Arc::new(Mle::from(RowMajorMatrix::new(next_n0, num_interactions))),
                num_row_variables - 1,
            );
            let next_d0_padded = PaddedMle::padded(
                Arc::new(Mle::from(RowMajorMatrix::new(next_d0, num_interactions))),
                num_row_variables - 1,
                Padding::Constant((EF::one(), num_interactions, CpuBackend)),
            );
            let next_n1_padded = PaddedMle::padded_with_zeros(
                Arc::new(Mle::from(RowMajorMatrix::new(next_n1, num_interactions))),
                num_row_variables - 1,
            );
            let next_d1_padded = PaddedMle::padded(
                Arc::new(Mle::from(RowMajorMatrix::new(next_d1, num_interactions))),
                num_row_variables - 1,
                Padding::Constant((EF::one(), num_interactions, CpuBackend)),
            );
            numerator_0.push(next_n0_padded);
            denominator_0.push(next_d0_padded);
            numerator_1.push(next_n1_padded);
            denominator_1.push(next_d1_padded);
        }
        LogUpGkrCpuLayer {
            numerator_0,
            denominator_0,
            numerator_1,
            denominator_1,
            num_interaction_variables: layer.num_interaction_variables,
            num_row_variables: layer.num_row_variables - 1,
        }
    }
}
