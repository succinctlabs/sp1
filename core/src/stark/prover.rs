use std::marker::PhantomData;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_constraints;

use crate::runtime::Segment;
use crate::stark::permutation::generate_permutation_trace;
use crate::stark::quotient_values;
use crate::utils::AirChip;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{AbstractExtensionField, AbstractField};
use p3_field::{PrimeField32, TwoAdicField};
use p3_matrix::{Matrix, MatrixRowSlices};
use p3_maybe_rayon::*;
use p3_uni_stark::decompose_and_flatten;
use p3_uni_stark::StarkConfig;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;

use super::types::*;

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
    #[allow(unused)]
    pub fn prove(
        config: &SC,
        challenger: &mut SC::Challenger,
        chips: &[Box<dyn AirChip<SC>>],
        main_data: MainData<SC>,
    ) -> SegmentDebugProof<SC>
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
        let permutation_traces =
            tracing::debug_span!("generate permutation traces").in_scope(|| {
                chips
                    .par_iter()
                    .enumerate()
                    .map(|(i, chip)| {
                        generate_permutation_trace(
                            chip.as_ref(),
                            &traces[i],
                            permutation_challenges.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
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

        // Get the commulutative sums of the permutation traces.
        let commulative_sums = permutation_traces
            .par_iter()
            .map(|trace| trace.row_slice(trace.height() - 1).last().copied().unwrap())
            .collect::<Vec<_>>();

        // Commit to the permutation traces.
        let flattened_permutation_traces = permutation_traces
            .par_iter()
            .map(|trace| trace.flatten_to_base())
            .collect::<Vec<_>>();
        let (permutation_commit, permutation_data) =
            tracing::debug_span!("commit permutation traces")
                .in_scope(|| config.pcs().commit_batches(flattened_permutation_traces));
        challenger.observe(permutation_commit.clone());

        // For each chip, compute the quotient polynomial.
        let main_ldes = tracing::debug_span!("get main ldes")
            .in_scope(|| config.pcs().get_ldes(&main_data.main_data));
        let permutation_ldes = tracing::debug_span!("get perm ldes")
            .in_scope(|| config.pcs().get_ldes(&permutation_data));
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();

        // Compute the quotient values.
        let quotient_values = tracing::debug_span!("compute quotient values").in_scope(|| {
            (0..chips.len()).into_par_iter().map(|i| {
                quotient_values(
                    config,
                    &*chips[i],
                    log_degrees[i],
                    log_quotient_degree,
                    &main_ldes[i],
                    alpha,
                )
            })
        });

        // Compute the quotient chunks.
        let quotient_chunks = tracing::debug_span!("decompose and flatten").in_scope(|| {
            quotient_values
                .enumerate()
                .map(|(i, values)| {
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
        let coset_shift = tracing::debug_span!("coset shift").in_scope(|| {
            config
                .pcs()
                .coset_shift()
                .exp_power_of_2(log_quotient_degree)
        });
        let (quotient_commit, quotient_data) = tracing::debug_span!("commit shifted batches")
            .in_scope(|| {
                config
                    .pcs()
                    .commit_shifted_batches(quotient_chunks, coset_shift)
            });

        // Observe the quotient commitments.
        challenger.observe(quotient_commit.clone());

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_ext_element();
        let g_subgroup = g_subgroups[0];

        let trace_openning_points =
            tracing::debug_span!("compute trace opening points").in_scope(|| {
                g_subgroups
                    .iter()
                    .map(|g| vec![zeta, zeta * *g])
                    .collect::<Vec<_>>()
            });

        let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        let quotient_openning_points = (0..num_quotient_chunks)
            .map(|_| vec![zeta_quot_pow])
            .collect::<Vec<_>>();

        let (openings, openning_proof) =
            tracing::debug_span!("open multi batches").in_scope(|| {
                config.pcs().open_multi_batches(
                    &[
                        (&main_data.main_data, &trace_openning_points),
                        (&permutation_data, &trace_openning_points),
                        (&quotient_data, &quotient_openning_points),
                    ],
                    challenger,
                )
            });

        // Checking the shapes of opennings match our expectations.
        //
        // This is a sanity check to make sure we are using the API correctly. We should remove this
        // once everything is stable.

        #[cfg(not(feature = "perf"))]
        {
            // Check for the correct number of openning collections.
            assert_eq!(openings.len(), 3);

            // Check the shape of the main trace opennings.
            assert_eq!(openings[0].len(), chips.len());
            for (chip, opening) in chips.iter().zip(openings[0].iter()) {
                let width = chip.air_width();
                assert_eq!(opening.len(), 2);
                assert_eq!(opening[0].len(), width);
                assert_eq!(opening[1].len(), width);
            }
            // Check the shape of the permutation trace opennings.
            assert_eq!(openings[1].len(), chips.len());
            for (perm, opening) in permutation_traces.iter().zip(openings[1].iter()) {
                let width = perm.width() * SC::Challenge::D;
                assert_eq!(opening.len(), 2);
                assert_eq!(opening[0].len(), width);
                assert_eq!(opening[1].len(), width);
            }
            // Check the shape of the quotient opennings.
            assert_eq!(openings[2].len(), num_quotient_chunks);
            for opening in openings[2].iter() {
                let width = SC::Challenge::D << log_quotient_degree;
                assert_eq!(opening.len(), 1);
                assert_eq!(opening[0].len(), width);
            }
        }

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
        let proof = SegmentProof::<SC> {
            commitment: SegmentCommitment {
                main_commit: main_data.main_commit.clone(),
                permutation_commit,
                quotient_commit,
            },
            opened_values,
            commulative_sums,
            openning_proof,
            degree_bits: log_degrees,
        };

        // Check that the table-specific constraints are correct for each chip.
        #[cfg(not(feature = "perf"))]
        for i in 0..chips.len() {
            debug_constraints(
                &*chips[i],
                &traces[i],
                &permutation_traces[i],
                &permutation_challenges,
            );
        }

        SegmentDebugProof {
            main_commit: main_data.main_commit.clone(),
            traces,
            permutation_traces,
        }
    }
}
