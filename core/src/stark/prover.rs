use super::ProvingKey;
use super::{quotient_values, RiscvStark};
use itertools::izip;
#[cfg(not(feature = "perf"))]
use p3_air::BaseAir;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, UnivariatePcs, UnivariatePcsWithLde};
use p3_field::{AbstractExtensionField, AbstractField};
use p3_field::{ExtensionField, PrimeField};
use p3_field::{PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::MatrixRows;
use p3_matrix::{Matrix, MatrixRowSlices};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::marker::PhantomData;

use super::util::decompose_and_flatten;
use super::{types::*, ChipRef, StarkGenericConfig};
use crate::air::MachineAir;
use crate::runtime::ExecutionRecord;
use crate::stark::permutation::generate_permutation_trace;
use crate::utils::env;

#[cfg(not(feature = "perf"))]
use crate::stark::debug_constraints;

pub trait Prover<SC: StarkGenericConfig> {
    fn prove_shards(
        machine: &RiscvStark<SC>,
        pk: &ProvingKey<SC>,
        shards: &mut Vec<ExecutionRecord>,
        challenger: &mut SC::Challenger,
    ) -> Proof<SC>;
}

impl<SC> Prover<SC> for LocalProver<SC>
where
    SC::Val: PrimeField32 + TwoAdicField + Send + Sync,
    SC: StarkGenericConfig + Send + Sync,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    PcsProof<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
{
    fn prove_shards(
        machine: &RiscvStark<SC>,
        pk: &ProvingKey<SC>,
        shards: &mut Vec<ExecutionRecord>,
        challenger: &mut SC::Challenger,
    ) -> Proof<SC> {
        let config = machine.config();
        let all_chips = machine.chips();
        tracing::info!("Generating and commiting traces for each shard.");
        // Generate and commit the traces for each segment.
        let (shard_commits, shard_data) = Self::commit_shards(config, shards, &all_chips);

        // Observe the challenges for each segment.
        tracing::info_span!("observing all challenges").in_scope(|| {
            shard_commits.into_iter().for_each(|commitment| {
                challenger.observe(commitment);
            });
        });

        // Generate a proof for each segment. Note that we clone the challenger so we can observe
        // identical global challenges across the segments.
        let shard_proofs = shard_data
            .into_par_iter()
            .map(|data| {
                let data = tracing::info_span!("materializing data")
                    .in_scope(|| data.materialize().expect("failed to load shard main data"));
                let chips = all_chips
                    .iter()
                    .filter(|chip| data.chip_ids.contains(&chip.name()))
                    .collect::<Vec<_>>();
                tracing::info_span!("proving shard").in_scope(|| {
                    Self::prove_shard(config, pk, &chips, data, &mut challenger.clone())
                })
            })
            .collect::<Vec<_>>();

        Proof { shard_proofs }
    }
}

pub struct LocalProver<SC>(PhantomData<SC>);

impl<SC> LocalProver<SC>
where
    SC::Val: PrimeField + TwoAdicField + PrimeField32,
    SC: StarkGenericConfig + Send + Sync,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
{
    fn commit_main(
        config: &SC,
        chips: &[ChipRef<SC>],
        shard: &mut ExecutionRecord,
        index: usize,
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
            index,
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    fn prove_shard(
        config: &SC,
        _pk: &ProvingKey<SC>,
        chips: &[&ChipRef<SC>],
        shard_data: ShardMainData<SC>,
        challenger: &mut SC::Challenger,
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
                    quotient_values(
                        config,
                        chips[i],
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
                index: shard_data.index,
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
            main_commit: shard_data.main_commit.clone(),
            traces,
            permutation_traces,
            chip_ids: chips.iter().map(|chip| chip.name()).collect::<Vec<_>>(),
        };
    }

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
                    .enumerate()
                    .map(|(i, shard)| {
                        let data = tracing::info_span!("shard commit main", shard = shard.index)
                            .in_scope(|| Self::commit_main(config, chips, shard, i));
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
