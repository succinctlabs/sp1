use std::marker::PhantomData;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_constraints;

use crate::runtime::Segment;
use crate::stark::permutation::generate_permutation_trace;
use crate::utils::AirChip;
use p3_air::TwoRowMatrixView;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::PackedField;
use p3_field::{cyclic_subgroup_coset_known_order, AbstractExtensionField, AbstractField, Field};
use p3_field::{PrimeField32, TwoAdicField};
use p3_matrix::MatrixRows;
use p3_matrix::{Matrix, MatrixGet, MatrixRowSlices};
use p3_maybe_rayon::prelude::*;

use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;

use super::folder::ProverConstraintFolder;
use super::permutation::eval_permutation_constraints;
use super::util::decompose_and_flatten;
use super::zerofier_coset::ZerofierOnCoset;
use super::{types::*, StarkConfig};

pub(crate) struct Prover<SC>(PhantomData<SC>);

impl<SC: StarkConfig> Prover<SC> {
    /// Commit to the main data
    pub fn commit_main(
        config: &SC,
        chips: &[Box<dyn AirChip<SC>>],
        segment: &mut Segment,
    ) -> MainData<SC>
    where
        SC::Val: PrimeField32,
    {
        // For each chip, generate the trace.
        let traces = chips
            .iter()
            .map(|chip| chip.generate_trace(segment))
            .collect::<Vec<_>>();

        // Commit to the batch of traces.
        let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());

        MainData {
            traces,
            main_commit,
            main_data,
        }
    }

    /// Prove the program for the given segment and given a commitment to the main data.
    pub fn prove(
        config: &SC,
        challenger: &mut SC::Challenger,
        chips: &[Box<dyn AirChip<SC>>],
        main_data: MainData<SC>,
    ) -> SegmentProof<SC>
    where
        SC::Val: PrimeField32,
        SC: Send + Sync,
    {
        // Get the traces.
        let traces = main_data.traces;

        // For each trace, compute the degree.
        let degrees = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>();
        let log_degrees = degrees
            .iter()
            .map(|d| log2_strict_usize(*d))
            .collect::<Vec<_>>();
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let g_subgroups = log_degrees
            .iter()
            .map(|log_deg| SC::Val::two_adic_generator(*log_deg))
            .collect::<Vec<_>>();

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Generate the permutation traces.
        let mut permutation_traces = Vec::with_capacity(chips.len());
        let mut commulative_sums = Vec::with_capacity(chips.len());
        tracing::debug_span!("generate permutation traces").in_scope(|| {
            chips
                .par_iter()
                .zip(traces.par_iter())
                .map(|(chip, trace)| {
                    let perm_trace =
                        generate_permutation_trace(chip.as_chip(), trace, &permutation_challenges);
                    let commulative_sum = perm_trace
                        .row_slice(trace.height() - 1)
                        .last()
                        .copied()
                        .unwrap();
                    (perm_trace, commulative_sum)
                })
                .unzip_into_vecs(&mut permutation_traces, &mut commulative_sums);
        });

        // Compute some statistics.
        for i in 0..chips.len() {
            let trace_width = traces[i].width();
            let permutation_width = permutation_traces[i].width();
            let total_width = trace_width + permutation_width;
            tracing::debug!(
                "{:<11} | Cols = {:<5} | Rows = {:<5} | Cells = {:<10} | Main Cols = {:.2}% | Perm Cols = {:.2}%",
                chips[i].name(),
                total_width,
                traces[i].height(),
                total_width * traces[i].height(),
                (100f32 * trace_width as f32) / total_width as f32,
                (100f32 * permutation_width as f32) / total_width as f32,
            );
        }

        // Commit to the permutation traces.
        let flattened_permutation_traces = tracing::debug_span!("flatten permutation traces")
            .in_scope(|| {
                permutation_traces
                    .par_iter()
                    .map(|trace| trace.flatten_to_base())
                    .collect::<Vec<_>>()
            });
        let (permutation_commit, permutation_data) =
            tracing::debug_span!("commit permutation traces")
                .in_scope(|| config.pcs().commit_batches(flattened_permutation_traces));
        challenger.observe(permutation_commit.clone());

        // For each chip, compute the quotient polynomial.
        let log_stride_for_quotient = config.pcs().log_blowup() - log_quotient_degree;
        let main_ldes = tracing::debug_span!("get main ldes").in_scope(|| {
            config
                .pcs()
                .get_ldes(&main_data.main_data)
                .into_iter()
                .map(|lde| lde.vertically_strided(1 << log_stride_for_quotient, 0))
                .collect::<Vec<_>>()
        });
        let permutation_ldes = tracing::debug_span!("get perm ldes").in_scope(|| {
            config
                .pcs()
                .get_ldes(&permutation_data)
                .into_iter()
                .map(|lde| lde.vertically_strided(1 << log_stride_for_quotient, 0))
                .collect::<Vec<_>>()
        });
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();

        // Compute the quotient values.
        let quotient_values = tracing::debug_span!("compute quotient values").in_scope(|| {
            (0..chips.len())
                .into_par_iter()
                .map(|i| {
                    Self::quotient_values(
                        config,
                        &*chips[i],
                        commulative_sums[i],
                        log_degrees[i],
                        log_quotient_degree,
                        &main_ldes[i],
                        &permutation_ldes[i],
                        &permutation_challenges,
                        alpha,
                    )
                })
                .collect::<Vec<_>>()
        });

        // Compute the quotient chunks.
        let quotient_chunks = tracing::debug_span!("decompose and flatten").in_scope(|| {
            quotient_values
                .into_iter()
                .map(|values| {
                    decompose_and_flatten::<SC>(
                        values,
                        SC::Challenge::from_base(config.pcs().coset_shift()),
                        log_quotient_degree,
                    )
                })
                .collect::<Vec<_>>()
        });

        // Check the shapes of the quotient chunks.
        #[cfg(not(feature = "perf"))]
        for (i, mat) in quotient_chunks.iter().enumerate() {
            assert_eq!(mat.width(), SC::Challenge::D << log_quotient_degree);
            assert_eq!(mat.height(), traces[i].height());
        }

        let num_quotient_chunks = quotient_chunks.len();
        let coset_shifts = tracing::debug_span!("coset shift").in_scope(|| {
            let shift = config
                .pcs()
                .coset_shift()
                .exp_power_of_2(log_quotient_degree);
            vec![shift; chips.len()]
        });
        let (quotient_commit, quotient_data) = tracing::debug_span!("commit shifted batches")
            .in_scope(|| {
                config
                    .pcs()
                    .commit_shifted_batches(quotient_chunks, &coset_shifts)
            });

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_ext_element();

        let trace_opening_points =
            tracing::debug_span!("compute trace opening points").in_scope(|| {
                g_subgroups
                    .iter()
                    .map(|g| vec![zeta, zeta * *g])
                    .collect::<Vec<_>>()
            });

        let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        let quotient_opening_points = (0..num_quotient_chunks)
            .map(|_| vec![zeta_quot_pow])
            .collect::<Vec<_>>();

        let (openings, opening_proof) = tracing::debug_span!("open multi batches").in_scope(|| {
            config.pcs().open_multi_batches(
                &[
                    (&main_data.main_data, &trace_opening_points),
                    (&permutation_data, &trace_opening_points),
                    (&quotient_data, &quotient_opening_points),
                ],
                challenger,
            )
        });

        // Checking the shapes of openings match our expectations.
        //
        // This is a sanity check to make sure we are using the API correctly. We should remove this
        // once everything is stable.

        #[cfg(not(feature = "perf"))]
        {
            // Check for the correct number of opening collections.
            assert_eq!(openings.len(), 3);

            // Check the shape of the main trace openings.
            assert_eq!(openings[0].len(), chips.len());
            for (chip, opening) in chips.iter().zip(openings[0].iter()) {
                let width = chip.air_width();
                assert_eq!(opening.len(), 2);
                assert_eq!(opening[0].len(), width);
                assert_eq!(opening[1].len(), width);
            }
            // Check the shape of the permutation trace openings.
            assert_eq!(openings[1].len(), chips.len());
            for (perm, opening) in permutation_traces.iter().zip(openings[1].iter()) {
                let width = perm.width() * SC::Challenge::D;
                assert_eq!(opening.len(), 2);
                assert_eq!(opening[0].len(), width);
                assert_eq!(opening[1].len(), width);
            }
            // Check the shape of the quotient openings.
            assert_eq!(openings[2].len(), chips.len());
            for opening in openings[2].iter() {
                let width = SC::Challenge::D << log_quotient_degree;
                assert_eq!(opening.len(), 1);
                assert_eq!(opening[0].len(), width);
            }
        }

        #[cfg(feature = "perf")]
        {
            // Collect the opened values for each chip.
            let [main_values, permutation_values, quotient_values] = openings.try_into().unwrap();
            let main_opened_values = main_values
                .into_iter()
                .map(|op| {
                    let [local, next] = op.try_into().unwrap();
                    AirOpenedValues { local, next }
                })
                .collect::<Vec<_>>();
            let permutation_opened_values = permutation_values
                .into_iter()
                .map(|op| {
                    let [local, next] = op.try_into().unwrap();
                    AirOpenedValues { local, next }
                })
                .collect::<Vec<_>>();
            let quotient_opened_values = quotient_values
                .into_iter()
                .map(|mut op| op.pop().unwrap())
                .collect::<Vec<_>>();
            let opened_values = SegmentOpenedValues {
                main: main_opened_values,
                permutation: permutation_opened_values,
                quotient: quotient_opened_values,
            };

            SegmentProof::<SC> {
                commitment: SegmentCommitment {
                    main_commit: main_data.main_commit.clone(),
                    permutation_commit,
                    quotient_commit,
                },
                opened_values,
                commulative_sums,
                opening_proof,
                degree_bits: log_degrees,
            }
        }

        // Check that the table-specific constraints are correct for each chip.
        #[cfg(not(feature = "perf"))]
        tracing::info_span!("debug constraints").in_scope(|| {
            for i in 0..chips.len() {
                debug_constraints(
                    &*chips[i],
                    &traces[i],
                    &permutation_traces[i],
                    &permutation_challenges,
                )
            }
        });

        #[cfg(not(feature = "perf"))]
        return SegmentProof {
            main_commit: main_data.main_commit.clone(),
            traces,
            permutation_traces,
        };
    }

    #[allow(clippy::too_many_arguments)]
    pub fn quotient_values<C, MainLde, PermLde>(
        config: &SC,
        chip: &C,
        commulative_sum: SC::Challenge,
        degree_bits: usize,
        quotient_degree_bits: usize,
        main_lde: &MainLde,
        permutation_lde: &PermLde,
        perm_challenges: &[SC::Challenge],
        alpha: SC::Challenge,
    ) -> Vec<SC::Challenge>
    where
        SC: StarkConfig,
        C: AirChip<SC> + ?Sized,
        MainLde: MatrixGet<SC::Val> + Sync,
        PermLde: MatrixGet<SC::Val> + Sync,
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

        let zerofier_on_coset =
            ZerofierOnCoset::new(degree_bits, quotient_degree_bits, coset_shift);

        // Evaluations of L_first(x) = Z_H(x) / (x - 1) on our coset s H.
        let lagrange_first_evals = zerofier_on_coset.lagrange_basis_unnormalized(0);
        let lagrange_last_evals = zerofier_on_coset.lagrange_basis_unnormalized(degree - 1);

        let ext_degree = SC::Challenge::D;

        (0..quotient_size)
            .into_par_iter()
            .step_by(SC::PackedVal::WIDTH)
            .flat_map_iter(|i_local_start| {
                let wrap = |i| i % quotient_size;
                let i_next_start = wrap(i_local_start + next_step);
                let i_range = i_local_start..i_local_start + SC::PackedVal::WIDTH;

                let x = *SC::PackedVal::from_slice(&coset[i_range.clone()]);
                let is_transition = x - subgroup_last;
                let is_first_row =
                    *SC::PackedVal::from_slice(&lagrange_first_evals[i_range.clone()]);
                let is_last_row = *SC::PackedVal::from_slice(&lagrange_last_evals[i_range]);

                let local: Vec<_> = (0..main_lde.width())
                    .map(|col| {
                        SC::PackedVal::from_fn(|offset| {
                            let row = wrap(i_local_start + offset);
                            main_lde.get(row, col)
                        })
                    })
                    .collect();
                let next: Vec<_> = (0..main_lde.width())
                    .map(|col| {
                        SC::PackedVal::from_fn(|offset| {
                            let row = wrap(i_next_start + offset);
                            main_lde.get(row, col)
                        })
                    })
                    .collect();

                let perm_local: Vec<_> = (0..permutation_lde.width())
                    .step_by(ext_degree)
                    .map(|col| {
                        SC::PackedChallenge::from_base_fn(|i| {
                            SC::PackedVal::from_fn(|offset| {
                                let row = wrap(i_local_start + offset);
                                permutation_lde.get(row, col + i)
                            })
                        })
                    })
                    .collect();

                let perm_next: Vec<_> = (0..permutation_lde.width())
                    .step_by(ext_degree)
                    .map(|col| {
                        SC::PackedChallenge::from_base_fn(|i| {
                            SC::PackedVal::from_fn(|offset| {
                                let row = wrap(i_next_start + offset);
                                permutation_lde.get(row, col + i)
                            })
                        })
                    })
                    .collect();

                let accumulator = SC::PackedChallenge::zero();
                let mut folder = ProverConstraintFolder {
                    preprocessed: TwoRowMatrixView {
                        local: &[],
                        next: &[],
                    },
                    main: TwoRowMatrixView {
                        local: &local,
                        next: &next,
                    },
                    perm: TwoRowMatrixView {
                        local: &perm_local,
                        next: &perm_next,
                    },
                    perm_challenges,
                    is_first_row,
                    is_last_row,
                    is_transition,
                    alpha,
                    accumulator,
                };
                chip.eval(&mut folder);
                eval_permutation_constraints(chip, &mut folder, commulative_sum);

                // quotient(x) = constraints(x) / Z_H(x)
                let zerofier_inv: SC::PackedVal =
                    zerofier_on_coset.eval_inverse_packed(i_local_start);
                let quotient = folder.accumulator * zerofier_inv;

                // "Transpose" D packed base coefficients into WIDTH scalar extension coefficients.
                (0..SC::PackedVal::WIDTH).map(move |idx_in_packing| {
                    let quotient_value = (0..<SC::Challenge as AbstractExtensionField<SC::Val>>::D)
                        .map(|coeff_idx| {
                            quotient.as_base_slice()[coeff_idx].as_slice()[idx_in_packing]
                        })
                        .collect::<Vec<_>>();
                    SC::Challenge::from_base_slice(&quotient_value)
                })
            })
            .collect()
    }
}
