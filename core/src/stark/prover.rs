use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cmp::Reverse;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU32, Ordering};

use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Pcs;
use p3_commit::PolynomialSpace;
use p3_field::AbstractField;
use p3_field::ExtensionField;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_ceil_usize;
use p3_util::log2_strict_usize;
use web_time::Instant;

use super::{quotient_values, MachineStark, PcsProverData, Val};
use super::{types::*, StarkGenericConfig};
use super::{Com, OpeningProof};
use super::{ProvingKey, VerifierConstraintFolder};
use crate::air::MachineAir;
use crate::lookup::InteractionBuilder;
use crate::stark::record::MachineRecord;
use crate::stark::MachineChip;
use crate::stark::PackedChallenge;
use crate::stark::ProverConstraintFolder;
use crate::utils::env;

fn chunk_vec<T>(mut vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    let mut result = Vec::new();
    while !vec.is_empty() {
        let current_chunk_size = std::cmp::min(chunk_size, vec.len());
        let current_chunk = vec.drain(..current_chunk_size).collect::<Vec<T>>();
        result.push(current_chunk);
    }
    result
}

pub trait Prover<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> {
    fn prove_shards(
        machine: &MachineStark<SC, A>,
        pk: &ProvingKey<SC>,
        shards: Vec<A::Record>,
        challenger: &mut SC::Challenger,
    ) -> Proof<SC>
    where
        A: for<'a> Air<ProverConstraintFolder<'a, SC>>
            + Air<InteractionBuilder<Val<SC>>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>;
}

impl<SC, A> Prover<SC, A> for LocalProver<SC, A>
where
    SC::Val: PrimeField32,
    SC: StarkGenericConfig + Send + Sync,
    SC::Challenger: Clone,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    OpeningProof<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
    A: MachineAir<Val<SC>>,
{
    fn prove_shards(
        machine: &MachineStark<SC, A>,
        pk: &ProvingKey<SC>,
        shards: Vec<A::Record>,
        challenger: &mut SC::Challenger,
    ) -> Proof<SC>
    where
        A: for<'a> Air<ProverConstraintFolder<'a, SC>>
            + Air<InteractionBuilder<Val<SC>>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // Observe the preprocessed commitment.
        pk.observe_into(challenger);
        // Generate and commit the traces for each segment.
        let (shard_commits, shard_data) = Self::commit_shards(machine, &shards);

        // Observe the challenges for each segment.
        tracing::debug_span!("observing all challenges").in_scope(|| {
            shard_commits
                .into_iter()
                .zip(shards.iter())
                .for_each(|(commitment, shard)| {
                    challenger.observe(commitment);
                    challenger
                        .observe_slice(&shard.public_values::<SC::Val>()[0..machine.num_pv_elts()]);
                });
        });

        let finished = AtomicU32::new(0);
        let total = shards.len() as u32;

        // Generate a proof for each segment. Note that we clone the challenger so we can observe
        // identical global challenges across the segments.
        let chunk_size = std::cmp::max(shards.len() / num_cpus::get(), 1);
        let config = machine.config();
        let reconstruct_commitments = env::reconstruct_commitments();
        let shard_data_chunks = chunk_vec(shard_data, chunk_size);
        let shard_chunks = chunk_vec(shards, chunk_size);
        log::info!("open shards");
        let shard_proofs = tracing::debug_span!("open shards").in_scope(|| {
            shard_data_chunks
                .into_par_iter()
                .zip(shard_chunks.into_par_iter())
                .map(|(datas, shards)| {
                    datas
                        .into_iter()
                        .zip(shards)
                        .map(|(data, shard)| {
                            let start = Instant::now();

                            let idx = shard.index() as usize;
                            let data = if reconstruct_commitments {
                                Self::commit_main(config, machine, &shard, idx)
                            } else {
                                data.materialize()
                                    .expect("failed to materialize shard main data")
                            };
                            let ordering = data.chip_ordering.clone();
                            let chips = machine.shard_chips_ordered(&ordering).collect::<Vec<_>>();
                            let proof = Self::prove_shard(
                                config,
                                pk,
                                &chips,
                                data,
                                &mut challenger.clone(),
                            );
                            finished.fetch_add(1, Ordering::Relaxed);
                            log::info!(
                                "> open shards ({}/{}): shard = {}, time = {:.2} secs",
                                finished.load(Ordering::Relaxed),
                                total,
                                idx,
                                start.elapsed().as_secs_f64()
                            );
                            proof
                        })
                        .collect::<Vec<_>>()
                })
                .flatten()
                .collect::<Vec<_>>()
        });

        Proof { shard_proofs }
    }
}

pub struct LocalProver<SC, A>(PhantomData<SC>, PhantomData<A>);

impl<SC, A> LocalProver<SC, A>
where
    SC: StarkGenericConfig,
    SC::Challenger: Clone,
    A: MachineAir<SC::Val>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
    ShardMainData<SC>: Serialize + DeserializeOwned,
{
    pub fn commit_main(
        config: &SC,
        machine: &MachineStark<SC, A>,
        shard: &A::Record,
        index: usize,
    ) -> ShardMainData<SC> {
        // Filter the chips based on what is used.
        let shard_chips = machine.shard_chips(shard).collect::<Vec<_>>();

        // For each chip, generate the trace.
        let mut named_traces = shard_chips
            .par_iter()
            .map(|chip| {
                (
                    chip.name(),
                    chip.generate_trace(shard, &mut A::Record::default()),
                )
            })
            .collect::<Vec<_>>();

        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_traces.sort_by_key(|(_, trace)| Reverse(trace.height()));

        let pcs = config.pcs();

        let domains_and_traces = named_traces
            .iter()
            .map(|(_, trace)| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                (domain, trace.to_owned())
            })
            .collect::<Vec<_>>();

        // Commit to the batch of traces.
        let (main_commit, main_data) = pcs.commit(domains_and_traces);

        // Get the chip ordering.
        let chip_ordering = named_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect();

        let traces = named_traces
            .into_iter()
            .map(|(_, trace)| trace)
            .collect::<Vec<_>>();

        ShardMainData {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            index,
            public_values: shard.public_values(),
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    pub fn prove_shard(
        config: &SC,
        pk: &ProvingKey<SC>,
        chips: &[&MachineChip<SC, A>],
        mut shard_data: ShardMainData<SC>,
        challenger: &mut SC::Challenger,
    ) -> ShardProof<SC>
    where
        Val<SC>: PrimeField32,
        SC: Send + Sync,
        ShardMainData<SC>: DeserializeOwned,
        A: for<'a> Air<ProverConstraintFolder<'a, SC>>
            + Air<InteractionBuilder<Val<SC>>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // Get the traces.
        let traces = &mut shard_data.traces;

        let degrees = traces
            .iter()
            .map(|trace| trace.height())
            .collect::<Vec<_>>();

        let log_degrees = degrees
            .iter()
            .map(|degree| log2_strict_usize(*degree))
            .collect::<Vec<_>>();

        // TODO: read dynamically from Chip.
        let max_constraint_degree = 3;
        let log_quotient_degree = log2_ceil_usize(max_constraint_degree - 1);
        let quotient_degree = 1 << log_quotient_degree;

        let pcs = config.pcs();
        let trace_domains = degrees
            .iter()
            .map(|degree| pcs.natural_domain_for_degree(*degree))
            .collect::<Vec<_>>();

        // Obtain the challenges used for the permutation argument.
        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }
        let packed_perm_challenges = permutation_challenges
            .iter()
            .map(|c| PackedChallenge::<SC>::from_f(*c))
            .collect::<Vec<_>>();

        // Generate the permutation traces.
        let mut permutation_traces = Vec::with_capacity(chips.len());
        let mut cumulative_sums = Vec::with_capacity(chips.len());
        tracing::debug_span!("generate permutation traces").in_scope(|| {
            chips
                .par_iter()
                .zip(traces.par_iter_mut())
                .map(|(chip, main_trace)| {
                    let preprocessed_trace = pk
                        .chip_ordering
                        .get(&chip.name())
                        .map(|&index| &pk.traces[index]);
                    let perm_trace = chip.generate_permutation_trace(
                        preprocessed_trace,
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

        let domains_and_perm_traces =
            tracing::debug_span!("flatten permutation traces and collect domains").in_scope(|| {
                permutation_traces
                    .into_iter()
                    .zip(trace_domains.iter())
                    .map(|(perm_trace, domain)| {
                        let trace = perm_trace.flatten_to_base();
                        (*domain, trace.to_owned())
                    })
                    .collect::<Vec<_>>()
            });

        let pcs = config.pcs();

        let (permutation_commit, permutation_data) =
            tracing::debug_span!("commit to permutation traces")
                .in_scope(|| pcs.commit(domains_and_perm_traces));
        challenger.observe(permutation_commit.clone());

        // Compute the quotient polynomial for all chips.

        let quotient_domains = trace_domains
            .iter()
            .zip(log_degrees.iter())
            .map(|(domain, log_degree)| {
                domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree))
            })
            .collect::<Vec<_>>();

        // Compute the quotient values.
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();
        let quotient_values = tracing::debug_span!("compute quotient values").in_scope(|| {
            quotient_domains
                .into_par_iter()
                .enumerate()
                .map(|(i, quotient_domain)| {
                    let preprocessed_trace_on_quotient_domains = pk
                        .chip_ordering
                        .get(&chips[i].name())
                        .map(|&index| {
                            pcs.get_evaluations_on_domain(&pk.data, index, *quotient_domain)
                                .to_row_major_matrix()
                        })
                        .unwrap_or_else(|| {
                            RowMajorMatrix::new_col(vec![SC::Val::zero(); quotient_domain.size()])
                        });
                    let main_trace_on_quotient_domains = pcs
                        .get_evaluations_on_domain(&shard_data.main_data, i, *quotient_domain)
                        .to_row_major_matrix();
                    let permutation_trace_on_quotient_domains = pcs
                        .get_evaluations_on_domain(&permutation_data, i, *quotient_domain)
                        .to_row_major_matrix();
                    quotient_values(
                        chips[i],
                        cumulative_sums[i],
                        trace_domains[i],
                        *quotient_domain,
                        preprocessed_trace_on_quotient_domains,
                        main_trace_on_quotient_domains,
                        permutation_trace_on_quotient_domains,
                        &packed_perm_challenges,
                        alpha,
                        shard_data.public_values.clone(),
                    )
                })
                .collect::<Vec<_>>()
        });

        // Split the quotient values and commit to them.
        let quotient_domains_and_chunks = quotient_domains
            .into_iter()
            .zip_eq(quotient_values)
            .flat_map(|(quotient_domain, quotient_values)| {
                let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();
                let quotient_chunks = quotient_domain.split_evals(quotient_degree, quotient_flat);
                let qc_domains = quotient_domain.split_domains(quotient_degree);
                qc_domains.into_iter().zip_eq(quotient_chunks)
            })
            .collect::<Vec<_>>();

        let num_quotient_chunks = quotient_domains_and_chunks.len();
        assert_eq!(num_quotient_chunks, chips.len() * quotient_degree);

        let (quotient_commit, quotient_data) = tracing::debug_span!("commit to quotient traces")
            .in_scope(|| pcs.commit(quotient_domains_and_chunks));
        challenger.observe(quotient_commit.clone());

        // Compute the quotient argument.
        let zeta: SC::Challenge = challenger.sample_ext_element();

        let preprocessed_opening_points =
            tracing::debug_span!("compute preprocessed opening points").in_scope(|| {
                pk.traces
                    .iter()
                    .map(|trace| {
                        let domain = pcs.natural_domain_for_degree(trace.height());
                        vec![zeta, domain.next_point(zeta).unwrap()]
                    })
                    .collect::<Vec<_>>()
            });

        let trace_opening_points =
            tracing::debug_span!("compute trace opening points").in_scope(|| {
                trace_domains
                    .iter()
                    .map(|domain| vec![zeta, domain.next_point(zeta).unwrap()])
                    .collect::<Vec<_>>()
            });

        // Compute quotient openning points, open every chunk at zeta.
        let quotient_opening_points = (0..num_quotient_chunks)
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();

        let (openings, opening_proof) = tracing::debug_span!("open multi batches").in_scope(|| {
            pcs.open(
                vec![
                    (&pk.data, preprocessed_opening_points),
                    (&shard_data.main_data, trace_opening_points.clone()),
                    (&permutation_data, trace_opening_points),
                    (&quotient_data, quotient_opening_points),
                ],
                challenger,
            )
        });

        // Collect the opened values for each chip.
        let [preprocessed_values, main_values, permutation_values, mut quotient_values] =
            openings.try_into().unwrap();
        assert!(main_values.len() == chips.len());
        let preprocessed_opened_values = preprocessed_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                AirOpenedValues { local, next }
            })
            .collect::<Vec<_>>();

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
            .chunks_exact_mut(quotient_degree)
            .map(|slice| {
                slice
                    .iter_mut()
                    .map(|op| op.pop().unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let opened_values = main_opened_values
            .into_iter()
            .zip_eq(permutation_opened_values)
            .zip_eq(quotient_opened_values)
            .zip_eq(cumulative_sums)
            .zip_eq(log_degrees.iter())
            .enumerate()
            .map(
                |(i, ((((main, permutation), quotient), cumulative_sum), log_degree))| {
                    let preprocessed = pk
                        .chip_ordering
                        .get(&chips[i].name())
                        .map(|&index| preprocessed_opened_values[index].clone())
                        .unwrap_or(AirOpenedValues {
                            local: vec![],
                            next: vec![],
                        });
                    ChipOpenedValues {
                        preprocessed,
                        main,
                        permutation,
                        quotient,
                        cumulative_sum,
                        log_degree: *log_degree,
                    }
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
            chip_ordering: shard_data.chip_ordering,
            public_values: shard_data.public_values,
        }
    }

    pub fn commit_shards<F, EF>(
        machine: &MachineStark<SC, A>,
        shards: &[A::Record],
    ) -> (Vec<Com<SC>>, Vec<ShardMainDataWrapper<SC>>)
    where
        F: PrimeField32,
        EF: ExtensionField<F>,
        SC: StarkGenericConfig<Val = F, Challenge = EF> + Send + Sync,
        SC::Challenger: Clone,
        PcsProverData<SC>: Send + Sync,
        ShardMainData<SC>: Serialize + DeserializeOwned,
    {
        let config = machine.config();
        let num_shards = shards.len();
        log::info!("commit shards");

        // Get the number of shards that is the threshold for saving shards to disk instead of
        // keeping all the shards in memory.
        let save_disk_threshold = env::save_disk_threshold();
        let reconstruct_commitments = env::reconstruct_commitments();
        let finished = AtomicU32::new(0);
        let total = shards.len() as u32;
        let (commitments, shard_main_data): (Vec<_>, Vec<_>) =
            tracing::debug_span!("commit shards").in_scope(|| {
                let chunk_size = std::cmp::max(shards.len() / num_cpus::get(), 1);
                shards
                    .par_chunks(chunk_size)
                    .map(|shard_batch| {
                        shard_batch
                            .iter()
                            .map(|shard| {
                                let index = shard.index();
                                let start = Instant::now();
                                let data =
                                    Self::commit_main(config, machine, shard, index as usize);
                                finished.fetch_add(1, Ordering::Relaxed);
                                log::info!(
                                    "> commit shards ({}/{}): shard = {}, time = {:.2} secs",
                                    finished.load(Ordering::Relaxed),
                                    total,
                                    index,
                                    start.elapsed().as_secs_f64()
                                );
                                let commitment = data.main_commit.clone();
                                let data = if reconstruct_commitments {
                                    ShardMainDataWrapper::Empty()
                                } else if num_shards > save_disk_threshold {
                                    let file = tempfile::tempfile().unwrap();
                                    tracing::info_span!("saving trace to disk").in_scope(|| {
                                        data.save(file).expect("failed to save shard main data")
                                    })
                                } else {
                                    data.to_in_memory()
                                };
                                (commitment, data)
                            })
                            .collect::<Vec<_>>()
                    })
                    .flatten()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .unzip()
            });

        (commitments, shard_main_data)
    }
}
