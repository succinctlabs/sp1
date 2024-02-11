use itertools::izip;
#[cfg(not(feature = "perf"))]
use p3_air::BaseAir;
use p3_air::{Air, TwoRowMatrixView};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{cyclic_subgroup_coset_known_order, AbstractExtensionField, AbstractField, Field};
use p3_field::{ExtensionField, PackedField, PrimeField};
use p3_field::{PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRows;
use p3_matrix::{Matrix, MatrixGet, MatrixRowSlices};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::marker::PhantomData;

use super::folder::ProverConstraintFolder;
use super::util::decompose_and_flatten;
use super::zerofier_coset::ZerofierOnCoset;
use super::{types::*, ChipRef, StarkGenericConfig};
use crate::air::MachineAir;
use crate::runtime::ExecutionRecord;
use crate::stark::permutation::generate_permutation_trace;
use crate::utils::env;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_constraints;

pub trait Prover<SC>
where
    SC: StarkGenericConfig,
{
    fn commit_shards<F, EF>(
        config: &SC,
        shards: &mut Vec<ExecutionRecord>,
        all_chips: &[ChipRef<SC>],
    ) -> (Vec<Com<SC>>, Vec<ShardMainDataWrapper<SC>>)
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkGenericConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned;

    fn commit_main(
        config: &SC,
        chips: &[ChipRef<SC>],
        shard: &mut ExecutionRecord,
    ) -> ShardMainData<SC>
    where
        SC::Val: PrimeField32,
    {
        // Filter the chips based on what is used.
        let filtered_chips = chips
            .iter()
            .filter(|chip| chip.include(shard))
            .collect::<Vec<_>>();

        // For each chip, generate the trace.
        let traces = filtered_chips
            .iter()
            .map(|chip| chip.generate_trace(&mut shard.clone()))
            .collect::<Vec<_>>();

        // Commit to the batch of traces.
        let (main_commit, main_data) = config.pcs().commit_batches(traces.to_vec());

        // Get the filtered chip ids.
        let chip_ids = filtered_chips
            .iter()
            .map(|chip| chip.name())
            .collect::<Vec<_>>();

        ShardMainData {
            traces,
            main_commit,
            main_data,
            chip_ids,
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    fn prove_shard(
        config: &SC,
        challenger: &mut SC::Challenger,
        chips: &[ChipRef<SC>],
        shard_data: ShardMainData<SC>,
    ) -> ShardProof<SC>
    where
        SC::Val: PrimeField32,
        SC: Send + Sync,
        ShardMainData<SC>: DeserializeOwned,
    {
        // Get the traces.
        let traces = shard_data.traces;

        let log_degrees = traces
            .iter()
            .map(|trace| log2_strict_usize(trace.height()))
            .collect::<Vec<_>>();
        // TODO: read dynamically from Chip.
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let g_subgroups = log_degrees
            .iter()
            .map(|log_deg| SC::Val::two_adic_generator(*log_deg))
            .collect::<Vec<_>>();

        // Compute the interactions for all chips
        let sends = chips.iter().map(|chip| chip.sends()).collect::<Vec<_>>();
        let receives = chips.iter().map(|chip| chip.receives()).collect::<Vec<_>>();

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Generate the permutation traces.
        let mut permutation_traces = Vec::with_capacity(chips.len());
        let mut cumulative_sums = Vec::with_capacity(chips.len());
        tracing::info_span!("generate permutation traces").in_scope(|| {
            sends
                .par_iter()
                .zip(receives.par_iter())
                .zip(traces.par_iter())
                .map(|((send, rec), main_trace)| {
                    let perm_trace = generate_permutation_trace(
                        send,
                        rec,
                        &None,
                        main_trace,
                        &permutation_challenges,
                    );
                    let cumulative_sum = perm_trace
                        .row_slice(main_trace.height() - 1)
                        .last()
                        .copied()
                        .unwrap();
                    (perm_trace, cumulative_sum)
                })
                .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
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
        let flattened_permutation_traces = tracing::info_span!("flatten permutation traces")
            .in_scope(|| {
                permutation_traces
                    .par_iter()
                    .map(|trace| trace.flatten_to_base())
                    .collect::<Vec<_>>()
            });
        let (permutation_commit, permutation_data) =
            tracing::info_span!("commit permutation traces")
                .in_scope(|| config.pcs().commit_batches(flattened_permutation_traces));
        challenger.observe(permutation_commit.clone());

        // For each chip, compute the quotient polynomial.
        let log_stride_for_quotient = config.pcs().log_blowup() - log_quotient_degree;
        let main_ldes = tracing::info_span!("get main ldes").in_scope(|| {
            config
                .pcs()
                .get_ldes(&shard_data.main_data)
                .into_iter()
                .map(|lde| lde.vertically_strided(1 << log_stride_for_quotient, 0))
                .collect::<Vec<_>>()
        });
        let permutation_ldes = tracing::info_span!("get perm ldes").in_scope(|| {
            config
                .pcs()
                .get_ldes(&permutation_data)
                .into_iter()
                .map(|lde| lde.vertically_strided(1 << log_stride_for_quotient, 0))
                .collect::<Vec<_>>()
        });
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();

        // Compute the quotient values.
        let quotient_values = tracing::info_span!("compute quotient values").in_scope(|| {
            (0..chips.len())
                .into_par_iter()
                .map(|i| {
                    Self::quotient_values(
                        config,
                        &chips[i],
                        cumulative_sums[i],
                        log_degrees[i],
                        &main_ldes[i],
                        &permutation_ldes[i],
                        &permutation_challenges,
                        alpha,
                    )
                })
                .collect::<Vec<_>>()
        });

        // Compute the quotient chunks.
        let quotient_chunks = tracing::info_span!("decompose and flatten").in_scope(|| {
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
        let coset_shifts = tracing::info_span!("coset shift").in_scope(|| {
            let shift = config
                .pcs()
                .coset_shift()
                .exp_power_of_2(log_quotient_degree);
            vec![shift; chips.len()]
        });
        let (quotient_commit, quotient_data) = tracing::info_span!("commit shifted batches")
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
            tracing::info_span!("compute trace opening points").in_scope(|| {
                g_subgroups
                    .iter()
                    .map(|g| vec![zeta, zeta * *g])
                    .collect::<Vec<_>>()
            });

        let zeta_quot_pow = zeta.exp_power_of_2(log_quotient_degree);
        let quotient_opening_points = (0..num_quotient_chunks)
            .map(|_| vec![zeta_quot_pow])
            .collect::<Vec<_>>();

        let (openings, opening_proof) = tracing::info_span!("open multi batches").in_scope(|| {
            config.pcs().open_multi_batches(
                &[
                    (&shard_data.main_data, &trace_opening_points),
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
                let width = chip.width();
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

            let opened_values = izip!(
                main_opened_values,
                permutation_opened_values,
                quotient_opened_values,
                cumulative_sums,
                log_degrees
            )
            .map(
                |(main, permutation, quotient, cumulative_sum, log_degree)| ChipOpenedValues {
                    preprocessed: AirOpenedValues {
                        local: vec![],
                        next: vec![],
                    },
                    main,
                    permutation,
                    quotient,
                    cumulative_sum,
                    log_degree,
                },
            )
            .collect::<Vec<_>>();

            ShardProof::<SC> {
                commitment: ShardCommitment {
                    main_commit: shard_data.main_commit.clone(),
                    permutation_commit,
                    quotient_commit,
                },
                opened_values: ShardOpenedValues {
                    chips: opened_values,
                },
                opening_proof,
                chip_ids: chips.iter().map(|chip| chip.name()).collect::<Vec<_>>(),
            }
        }

        // Check that the table-specific constraints are correct for each chip.
        #[cfg(not(feature = "perf"))]
        tracing::info_span!("debug constraints").in_scope(|| {
            for i in 0..chips.len() {
                debug_constraints(
                    &chips[i],
                    None,
                    &traces[i],
                    &permutation_traces[i],
                    &permutation_challenges,
                );
            }
        });

        #[cfg(not(feature = "perf"))]
        return ShardProof {
            main_commit: main_data.main_commit.clone(),
            traces,
            permutation_traces,
            chip_ids: chips.iter().map(|chip| chip.name()).collect::<Vec<_>>(),
        };
    }

    #[allow(clippy::too_many_arguments)]
    fn quotient_values<MainLde, PermLde>(
        config: &SC,
        chip: &ChipRef<SC>,
        cumulative_sum: SC::Challenge,
        degree_bits: usize,
        main_lde: &MainLde,
        permutation_lde: &PermLde,
        perm_challenges: &[SC::Challenge],
        alpha: SC::Challenge,
    ) -> Vec<SC::Challenge>
    where
        SC: StarkGenericConfig,
        MainLde: MatrixGet<SC::Val> + Sync,
        PermLde: MatrixGet<SC::Val> + Sync,
    {
        let degree = 1 << degree_bits;
        let quotient_degree_bits = chip.log_quotient_degree();
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
                    cumulative_sum,
                    is_first_row,
                    is_last_row,
                    is_transition,
                    alpha,
                    accumulator,
                };
                chip.eval(&mut folder);

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

pub struct LocalProver<SC>(PhantomData<SC>);

impl<SC> Prover<SC> for LocalProver<SC>
where
    SC: StarkGenericConfig,
{
    fn commit_shards<F, EF>(
        config: &SC,
        shards: &mut Vec<ExecutionRecord>,
        chips: &[ChipRef<SC>],
    ) -> (
        Vec<<SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment>,
        Vec<ShardMainDataWrapper<SC>>,
    )
    where
        F: PrimeField + TwoAdicField + PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkGenericConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::Commitment: Send + Sync,
        <SC::Pcs as Pcs<SC::Val, RowMajorMatrix<SC::Val>>>::ProverData: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
    {
        let num_shards = shards.len();
        tracing::info!("num_shards={}", num_shards);
        // Get the number of shards that is the threshold for saving shards to disk instead of
        // keeping all the shards in memory.
        let save_disk_threshold = env::save_disk_threshold();
        let (commitments, shard_main_data): (Vec<_>, Vec<_>) =
            tracing::info_span!("commit main for all shards").in_scope(|| {
                shards
                    .into_par_iter()
                    .map(|shard| {
                        let data = tracing::info_span!("shard commit main", shard = shard.index)
                            .in_scope(|| Self::commit_main(config, chips, shard));
                        let commitment = data.main_commit.clone();
                        let file = tempfile::tempfile().unwrap();
                        let data = if num_shards > save_disk_threshold {
                            tracing::info_span!("saving trace to disk").in_scope(|| {
                                data.save(file).expect("failed to save shard main data")
                            })
                        } else {
                            data.to_in_memory()
                        };
                        (commitment, data)
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .unzip()
            });

        #[cfg(not(feature = "perf"))]
        {
            let bytes_written = shard_main_data
                .iter()
                .map(|data| match data {
                    ShardMainDataWrapper::InMemory(_) => 0,
                    ShardMainDataWrapper::TempFile(_, bytes_written) => *bytes_written,
                })
                .sum::<u64>();
            if bytes_written > 0 {
                tracing::debug!(
                    "total main data written to disk: {}",
                    size::Size::from_bytes(bytes_written)
                );
            }
        }

        (commitments, shard_main_data)
    }
}
