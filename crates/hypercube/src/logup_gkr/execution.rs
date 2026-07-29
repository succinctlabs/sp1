use itertools::Itertools;
use rayon::prelude::*;
use slop_algebra::{ExtensionField, Field};
use slop_alloc::CpuBackend;
use slop_matrix::dense::RowMajorMatrix;
use slop_multilinear::{Mle, PaddedMle, Padding, Point};
use std::{collections::BTreeMap, sync::Arc};

use crate::{air::InteractionScope, prover::Traces, Interaction};

use super::{ChipInteractions, LogUpGkrCpuLayer, LogUpGkrOutput, LogupGkrCpuTraceGenerator};

pub(crate) fn generate_interaction_vals<F: Field, EF: ExtensionField<F>>(
    interaction: &Interaction<F>,
    preprocessed_row: &[F],
    global_row: &[F],
    main_row: &[F],
    is_send: bool,
    alpha: EF,
    betas: &[EF],
) -> (F, EF) {
    let mut denominator = alpha;
    let mut betas = betas.iter();
    denominator += *betas.next().unwrap() * EF::from_canonical_usize(interaction.argument_index());
    for (columns, beta) in interaction.values.iter().zip(betas) {
        let apply = columns.apply::<F, F>(preprocessed_row, global_row, main_row);
        denominator += *beta * apply;
    }
    let mut mult = interaction.multiplicity.apply::<F, F>(preprocessed_row, global_row, main_row);

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
        // Scatter each table's per-column values into the grouped interaction order: column `c`'s
        // two interleaved slots land at `(2g, 2g + 1)` where `g` is the column's grouped index
        // (the table's local block range chained with its global block range). Uncovered slots
        // (the gap below `2^k_local` and the tail) keep the padding values.
        let size = 1 << (last_layer.num_interaction_variables + 1);
        let mut numerator_0_interactions = vec![EF::zero(); size];
        let mut numerator_1_interactions = vec![EF::zero(); size];
        let mut denominator_0_interactions = vec![EF::one(); size];
        let mut denominator_1_interactions = vec![EF::one(); size];
        for (numerator_0, numerator_1, denominator_0, denominator_1, (local_range, global_range)) in itertools::izip!(
            &last_layer.numerator_0,
            &last_layer.numerator_1,
            &last_layer.denominator_0,
            &last_layer.denominator_1,
            &last_layer.interaction_ranges
        ) {
            let scatter = |mle: &PaddedMle<EF>, out: &mut [EF]| {
                let at_0 =
                    mle.fix_last_variable(EF::zero()).eval_at::<EF>(&Point::from(vec![])).to_vec();
                let at_1 =
                    mle.fix_last_variable(EF::one()).eval_at::<EF>(&Point::from(vec![])).to_vec();
                for (column, grouped) in local_range.clone().chain(global_range.clone()).enumerate()
                {
                    out[2 * grouped] = at_0[column];
                    out[2 * grouped + 1] = at_1[column];
                }
            };
            scatter(numerator_0, &mut numerator_0_interactions);
            scatter(numerator_1, &mut numerator_1_interactions);
            scatter(denominator_0, &mut denominator_0_interactions);
            scatter(denominator_1, &mut denominator_1_interactions);
        }

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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn generate_first_layer(
        &self,
        interactions: &BTreeMap<String, ChipInteractions<F>>,
        main_traces: &Traces<F, CpuBackend>,
        global_traces: &Traces<F, CpuBackend>,
        preprocessed_traces: &Traces<F, CpuBackend>,
        local_challenges: (EF, Point<EF>),
        global_challenges: Option<(EF, Point<EF>)>,
        num_interaction_variables: usize,
    ) -> LogUpGkrCpuLayer<F, EF> {
        let first_trace = main_traces
            .values()
            .next()
            .or_else(|| global_traces.values().next())
            .expect("no traces in the shard");
        let num_row_variables = first_trace.num_variables();

        let mut numerator_0 = Vec::new();
        let mut denominator_0 = Vec::new();
        let mut numerator_1 = Vec::new();
        let mut denominator_1 = Vec::new();
        let mut interaction_ranges = Vec::new();
        let (alpha, beta_seed) = local_challenges;
        let betas = Mle::partial_lagrange(&beta_seed).guts().as_slice().to_vec();
        // The global challenge pair, expanded; present iff the machine has a global round.
        let global_alpha_betas = global_challenges.map(|(global_alpha, global_beta_seed)| {
            (global_alpha, Mle::partial_lagrange(&global_beta_seed).guts().as_slice().to_vec())
        });
        for (name, (interactions, ranges)) in interactions.iter() {
            let main_trace = main_traces.get(name.as_str()).cloned();
            let global_trace = global_traces.get(name.as_str()).cloned();
            let height = main_trace
                .as_ref()
                .or(global_trace.as_ref())
                .expect("chip has neither main nor global columns")
                .num_real_entries();

            let preprocessed_trace = preprocessed_traces.get(name.as_str()).cloned();
            let num_interactions = interactions.len();
            assert!(num_interactions > 0, "interaction-free chips must be filtered by the caller");
            interaction_ranges.push(ranges.clone());
            let mut numer_evals = vec![F::zero(); height * num_interactions];
            let mut denom_evals = vec![EF::one(); height * num_interactions];

            if height > 0 {
                // The values and width of present trace groups, each with `height` real rows.
                let prep_parts = preprocessed_trace
                    .as_ref()
                    .map(|p| (p.inner().as_ref().unwrap().guts().as_slice(), p.num_polynomials()));
                let main_parts = main_trace
                    .as_ref()
                    .map(|m| (m.inner().as_ref().unwrap().guts().as_slice(), m.num_polynomials()));
                let global_parts = global_trace
                    .as_ref()
                    .map(|g| (g.inner().as_ref().unwrap().guts().as_slice(), g.num_polynomials()));

                numer_evals
                    .par_chunks_exact_mut(num_interactions)
                    .zip_eq(denom_evals.par_chunks_exact_mut(num_interactions))
                    .enumerate()
                    .for_each(|(row, (numer_evals, denom_evals))| {
                        let prep_row =
                            prep_parts.map_or(&[][..], |(s, w)| &s[row * w..(row + 1) * w]);
                        let global_row =
                            global_parts.map_or(&[][..], |(s, w)| &s[row * w..(row + 1) * w]);
                        let main_row =
                            main_parts.map_or(&[][..], |(s, w)| &s[row * w..(row + 1) * w]);
                        interactions
                            .iter()
                            .zip(numer_evals.iter_mut())
                            .zip(denom_evals.iter_mut())
                            .for_each(|(((interaction, is_send), numer_eval), denom_eval)| {
                                // Select the challenge pair by the interaction's scope.
                                let (alpha, betas) = match interaction.scope {
                                    InteractionScope::Local => (alpha, betas.as_slice()),
                                    InteractionScope::Global => global_alpha_betas
                                        .as_ref()
                                        .map(|(a, b)| (*a, b.as_slice()))
                                        .unwrap(),
                                };
                                let (numer, denom) = generate_interaction_vals(
                                    interaction,
                                    prep_row,
                                    global_row,
                                    main_row,
                                    *is_send,
                                    alpha,
                                    betas,
                                );
                                *numer_eval = numer;
                                *denom_eval = denom;
                            });
                    });
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

        LogUpGkrCpuLayer {
            numerator_0,
            denominator_0,
            numerator_1,
            denominator_1,
            interaction_ranges,
            num_interaction_variables,
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
            interaction_ranges: layer.interaction_ranges.clone(),
            num_interaction_variables: layer.num_interaction_variables,
            num_row_variables: layer.num_row_variables - 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use slop_air::{PairCol, VirtualPairCol};
    use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
    use sp1_primitives::SP1Field;

    use crate::{air::InteractionScope, GkrCircuitLayer, InteractionKind};

    use super::*;

    type F = SP1Field;
    type EF = BinomialExtensionField<SP1Field, 4>;

    fn padded_trace(rows: Vec<Vec<u32>>, width: usize, num_variables: u32) -> PaddedMle<F> {
        let values = rows
            .into_iter()
            .flat_map(|row| {
                assert_eq!(row.len(), width);
                row.into_iter().map(F::from_canonical_u32)
            })
            .collect::<Vec<_>>();
        let mle = Mle::from(RowMajorMatrix::new(values, width));
        PaddedMle::padded_with_zeros(Arc::new(mle), num_variables)
    }

    /// Pins the grouped slot layout of the base (row-tree output) layer: slots `2g, 2g + 1`
    /// belong to grouped interaction `g` — the local-scope interactions at `[0, num_local)`
    /// (chips in name order, within a chip locals in sends-then-receives order), the slots
    /// `[num_local, 2^k_local)` padding, the global-scope interactions from `2^k_local` — and
    /// each interaction's two slots sum to its total fraction over the trace rows, fingerprinted
    /// with the challenge pair of its scope. Interaction-free chips are filtered out.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_output_layer_scope_split() {
        let num_variables = 3;

        // Chip "A": preprocessed width 1, global width 1, main width 2, 3 real rows.
        let a_main = padded_trace(vec![vec![1, 2], vec![3, 4], vec![5, 6]], 2, num_variables);
        let a_global = padded_trace(vec![vec![7], vec![8], vec![9]], 1, num_variables);
        let a_prep = padded_trace(vec![vec![10], vec![11], vec![12]], 1, num_variables);
        // Chip "B": global-only (no main trace), global width 2, 5 real rows.
        let b_global = padded_trace(
            vec![vec![1, 1], vec![2, 3], vec![4, 5], vec![6, 7], vec![8, 9]],
            2,
            num_variables,
        );
        // Chip "C": main width 1, no interactions — contributes no output slots.
        let c_main = padded_trace(vec![vec![17]], 1, num_variables);

        let main_traces = Traces {
            named_traces: BTreeMap::from([("A".to_string(), a_main), ("C".to_string(), c_main)]),
        };
        let global_traces = Traces {
            named_traces: BTreeMap::from([
                ("A".to_string(), a_global),
                ("B".to_string(), b_global),
            ]),
        };
        let preprocessed_traces =
            Traces { named_traces: BTreeMap::from([("A".to_string(), a_prep)]) };

        // Chip "A" sends: one Local, one Global; receives: one Local.
        let a_send_local = Interaction::new(
            vec![VirtualPairCol::single_main(0)],
            VirtualPairCol::single_main(1),
            InteractionKind::Byte,
            InteractionScope::Local,
        );
        let a_send_global = Interaction::new(
            vec![VirtualPairCol::single(PairCol::Global(0))],
            VirtualPairCol::single(PairCol::Global(0)),
            InteractionKind::Memory,
            InteractionScope::Global,
        );
        let a_receive_local = Interaction::new(
            vec![VirtualPairCol::new(
                vec![(PairCol::Preprocessed(0), F::one()), (PairCol::Main(1), F::one())],
                F::zero(),
            )],
            VirtualPairCol::one(),
            InteractionKind::Byte,
            InteractionScope::Local,
        );
        // Chip "B" sends: one Local-scope interaction referencing global columns (the
        // `MemoryLocal` pattern); receives: one Global.
        let b_send_local = Interaction::new(
            vec![VirtualPairCol::single(PairCol::Global(1))],
            VirtualPairCol::one(),
            InteractionKind::Byte,
            InteractionScope::Local,
        );
        let b_receive_global = Interaction::new(
            vec![VirtualPairCol::single(PairCol::Global(0))],
            VirtualPairCol::single(PairCol::Global(1)),
            InteractionKind::Memory,
            InteractionScope::Global,
        );

        // The grouped shape: `num_local = 3`, `num_global = 2`, `k_local = 2`, and the global
        // block starts at `2^k_local = 4`, so `k_full = ceil(log2(4 + 2)) = 3`. Within a chip the
        // interactions are grouped locals-first: A's columns are
        // `[a_send_local, a_receive_local, a_send_global]` at grouped indices `{0, 1, 4}`, B's
        // are `[b_send_local, b_receive_global]` at `{2, 5}`. Chip "C" is interaction-free and
        // filtered out.
        let k_local = 2;
        let k_full = 3;
        let global_block_start = 1 << k_local;
        let interactions = BTreeMap::from([
            (
                "A".to_string(),
                (
                    vec![(&a_send_local, true), (&a_receive_local, false), (&a_send_global, true)],
                    (0..2, 4..5),
                ),
            ),
            (
                "B".to_string(),
                (vec![(&b_send_local, true), (&b_receive_global, false)], (2..3, 5..6)),
            ),
        ]);
        // The grouped index of every real interaction, in map iteration order.
        let grouped_indices = [0usize, 1, 4, 2, 5];

        let alpha = EF::from_canonical_u32(3);
        let beta_seed = Point::from(vec![EF::from_canonical_u32(5)]);
        let global_alpha = EF::from_canonical_u32(11);
        let global_beta_seed = Point::from(vec![EF::from_canonical_u32(13)]);

        // Build the circuit output through the production path: first layer, transitions down
        // to one row variable, output extraction.
        let generator = LogupGkrCpuTraceGenerator::<F, EF, ()>::default();
        let first_layer = generator.generate_first_layer(
            &interactions,
            &main_traces,
            &global_traces,
            &preprocessed_traces,
            (alpha, beta_seed.clone()),
            Some((global_alpha, global_beta_seed.clone())),
            k_full,
        );
        let mut layer = GkrCircuitLayer::FirstLayer(first_layer);
        let last_layer = loop {
            let next = match &layer {
                GkrCircuitLayer::FirstLayer(layer) => generator.layer_transition(layer),
                GkrCircuitLayer::Layer(layer) => generator.layer_transition(layer),
                GkrCircuitLayer::InteractionLayer(_) => unreachable!(),
            };
            if next.num_row_variables == 1 {
                break next;
            }
            layer = GkrCircuitLayer::Layer(next);
        };
        let base = generator.extract_outputs(&last_layer);
        let base_numerator = base.numerator.guts().as_slice();
        let base_denominator = base.denominator.guts().as_slice();
        assert_eq!(base_numerator.len(), 1 << (k_full + 1));

        // Compute each interaction's expected total fraction directly from the trace rows,
        // selecting the challenge pair by scope, and check it against the interaction's two
        // grouped base slots.
        let betas = Mle::partial_lagrange(&beta_seed).guts().as_slice().to_vec();
        let global_betas = Mle::partial_lagrange(&global_beta_seed).guts().as_slice().to_vec();
        let row = |trace: &Traces<F, CpuBackend>, name: &str, r: usize| -> Vec<F> {
            trace.get(name).map_or_else(Vec::new, |t| {
                let width = t.num_polynomials();
                t.inner().as_ref().unwrap().guts().as_slice()[r * width..(r + 1) * width].to_vec()
            })
        };
        let mut expected_local = EF::zero();
        let mut expected_global = EF::zero();
        let mut grouped = grouped_indices.iter();
        for (name, (interactions, _)) in &interactions {
            let height = main_traces
                .get(name)
                .or_else(|| global_traces.get(name))
                .unwrap()
                .num_real_entries();
            for (interaction, is_send) in interactions {
                let g = *grouped.next().unwrap();
                let (alpha, betas) = match interaction.scope {
                    InteractionScope::Local => {
                        assert!(g < 3);
                        (alpha, betas.as_slice())
                    }
                    InteractionScope::Global => {
                        assert!(g >= global_block_start);
                        (global_alpha, global_betas.as_slice())
                    }
                };
                let mut total = EF::zero();
                for r in 0..height {
                    let (numer, denom) = generate_interaction_vals(
                        interaction,
                        &row(&preprocessed_traces, name, r),
                        &row(&global_traces, name, r),
                        &row(&main_traces, name, r),
                        *is_send,
                        alpha,
                        betas,
                    );
                    total += EF::from_base(numer) / denom;
                }
                // The interaction's two grouped slots sum to its total fraction.
                let slot_sum = base_numerator[2 * g] / base_denominator[2 * g]
                    + base_numerator[2 * g + 1] / base_denominator[2 * g + 1];
                assert_eq!(slot_sum, total, "interaction at grouped index {g}");
                match interaction.scope {
                    InteractionScope::Local => expected_local += total,
                    InteractionScope::Global => expected_global += total,
                }
            }
        }
        assert!(grouped.next().is_none());
        assert!(!expected_local.is_zero());
        assert!(!expected_global.is_zero());

        // The uncovered slots — the gap `[num_local, 2^k_local)` and the tail — hold exactly the
        // padding values (numerator zero, denominator one).
        for g in [3, 6, 7] {
            assert_eq!(base_numerator[2 * g], EF::zero());
            assert_eq!(base_numerator[2 * g + 1], EF::zero());
            assert_eq!(base_denominator[2 * g], EF::one());
            assert_eq!(base_denominator[2 * g + 1], EF::one());
        }

        // The whole layer's fraction sum splits into the local and global stream sums.
        let total_sum =
            base_numerator.iter().zip(base_denominator.iter()).map(|(n, d)| *n / *d).sum::<EF>();
        assert_eq!(total_sum, expected_local + expected_global);
    }
}
