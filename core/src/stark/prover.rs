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
use p3_field::ExtensionField;
use p3_field::PrimeField32;
use p3_field::{AbstractExtensionField, AbstractField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use super::{quotient_values, PcsProverData, StarkMachine, Val};
use super::{types::*, StarkGenericConfig};
use super::{Com, OpeningProof};
use super::{StarkProvingKey, VerifierConstraintFolder};
use crate::air::MachineAir;
use crate::lookup::InteractionBuilder;
use crate::stark::record::MachineRecord;
use crate::stark::MachineChip;
use crate::stark::PackedChallenge;
use crate::stark::ProverConstraintFolder;
use crate::utils::SP1CoreOpts;

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
        machine: &StarkMachine<SC, A>,
        pk: &StarkProvingKey<SC>,
        shards: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: SP1CoreOpts,
    ) -> MachineProof<SC>
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
        machine: &StarkMachine<SC, A>,
        pk: &StarkProvingKey<SC>,
        shards: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: SP1CoreOpts,
    ) -> MachineProof<SC>
    where
        A: for<'a> Air<ProverConstraintFolder<'a, SC>>
            + Air<InteractionBuilder<Val<SC>>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        // Observe the preprocessed commitment.
        pk.observe_into(challenger);
        // Generate and commit the traces for each segment.
        let (shard_commits, shard_data) = Self::commit_shards(machine, &shards, opts);

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

        // Generate a proof for each segment. Note that we clone the challenger so we can observe
        // identical global challenges across the segments.
        let chunking_multiplier = opts.shard_chunking_multiplier;
        let chunk_size = std::cmp::max(chunking_multiplier * shards.len() / num_cpus::get(), 1);
        let config = machine.config();
        let reconstruct_commitments = opts.reconstruct_commitments;
        let shard_data_chunks = chunk_vec(shard_data, chunk_size);
        let shard_chunks = chunk_vec(shards, chunk_size);
        let parent_span = tracing::debug_span!("open_shards");
        let shard_proofs = parent_span.in_scope(|| {
            shard_data_chunks
                .into_par_iter()
                .zip(shard_chunks.into_par_iter())
                .map(|(datas, shards)| {
                    datas
                        .into_iter()
                        .zip(shards)
                        .map(|(data, shard)| {
                            tracing::debug_span!(parent: &parent_span, "prove shard opening")
                                .in_scope(|| {
                                    let idx = shard.index() as usize;
                                    let data = if reconstruct_commitments {
                                        Self::commit_main(config, machine, &shard, idx)
                                    } else {
                                        data.materialize()
                                            .expect("failed to materialize shard main data")
                                    };
                                    let ordering = data.chip_ordering.clone();
                                    let chips =
                                        machine.shard_chips_ordered(&ordering).collect::<Vec<_>>();
                                    let proof = Self::prove_shard(
                                        config,
                                        pk,
                                        &chips,
                                        data,
                                        &mut challenger.clone(),
                                    );
                                    finished.fetch_add(1, Ordering::Relaxed);
                                    proof
                                })
                        })
                        .collect::<Vec<_>>()
                })
                .flatten()
                .collect::<Vec<_>>()
        });

        MachineProof { shard_proofs }
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
        machine: &StarkMachine<SC, A>,
        shard: &A::Record,
        index: usize,
    ) -> ShardMainData<SC> {
        // Filter the chips based on what is used.
        let shard_chips = machine.shard_chips(shard).collect::<Vec<_>>();

        // For each chip, generate the trace.
        let parent_span = tracing::debug_span!("generate traces for shard");
        let mut named_traces = parent_span.in_scope(|| {
            shard_chips
                .par_iter()
                .map(|chip| {
                    let chip_name = chip.name();

                    // We need to create an outer span here because, for some reason,
                    // the #[instrument] macro on the chip impl isn't attaching its span to `parent_span`
                    // to avoid the unnecessary span, remove the #[instrument] macro.
                    let trace =
                        tracing::debug_span!(parent: &parent_span, "generate trace for chip", %chip_name)
                            .in_scope(|| chip.generate_trace(shard, &mut A::Record::default()));
                    (chip_name, trace)
                })
                .collect::<Vec<_>>()
        });

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
        pk: &StarkProvingKey<SC>,
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

        let log_quotient_degrees = chips
            .iter()
            .map(|chip| chip.log_quotient_degree())
            .collect::<Vec<_>>();

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
            let total_width = trace_width
                + permutation_width * <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
            tracing::debug!(
                "{:<15} | Main Cols = {:<5} | Perm Cols = {:<5} | Rows = {:<5} | Cells = {:<10}",
                chips[i].name(),
                trace_width,
                permutation_width * <SC::Challenge as AbstractExtensionField<SC::Val>>::D,
                traces[i].height(),
                total_width * traces[i].height(),
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
            .zip_eq(log_degrees.iter())
            .zip_eq(log_quotient_degrees.iter())
            .map(|((domain, log_degree), log_quotient_degree)| {
                domain.create_disjoint_domain(1 << (log_degree + log_quotient_degree))
            })
            .collect::<Vec<_>>();

        // Compute the quotient values.
        let alpha: SC::Challenge = challenger.sample_ext_element::<SC::Challenge>();
        let parent_span = tracing::debug_span!("compute quotient values");
        let quotient_values = parent_span.in_scope(|| {
            quotient_domains
                .into_par_iter()
                .enumerate()
                .map(|(i, quotient_domain)| {
                    tracing::debug_span!(parent: &parent_span, "compute quotient values for domain")
                        .in_scope(|| {
                            let preprocessed_trace_on_quotient_domains = pk
                                .chip_ordering
                                .get(&chips[i].name())
                                .map(|&index| {
                                    pcs.get_evaluations_on_domain(&pk.data, index, *quotient_domain)
                                        .to_row_major_matrix()
                                })
                                .unwrap_or_else(|| {
                                    RowMajorMatrix::new_col(vec![
                                        SC::Val::zero();
                                        quotient_domain.size()
                                    ])
                                });
                            let main_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(
                                    &shard_data.main_data,
                                    i,
                                    *quotient_domain,
                                )
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
                                &shard_data.public_values,
                            )
                        })
                })
                .collect::<Vec<_>>()
        });

        // Split the quotient values and commit to them.
        let quotient_domains_and_chunks = quotient_domains
            .into_iter()
            .zip_eq(quotient_values)
            .zip_eq(log_quotient_degrees.iter())
            .flat_map(
                |((quotient_domain, quotient_values), log_quotient_degree)| {
                    let quotient_degree = 1 << *log_quotient_degree;
                    let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();
                    let quotient_chunks =
                        quotient_domain.split_evals(quotient_degree, quotient_flat);
                    let qc_domains = quotient_domain.split_domains(quotient_degree);
                    qc_domains.into_iter().zip_eq(quotient_chunks)
                },
            )
            .collect::<Vec<_>>();

        let num_quotient_chunks = quotient_domains_and_chunks.len();
        assert_eq!(
            num_quotient_chunks,
            chips
                .iter()
                .map(|c| 1 << c.log_quotient_degree())
                .sum::<usize>()
        );

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
        let mut quotient_opened_values = Vec::with_capacity(log_quotient_degrees.len());
        for log_quotient_degree in log_quotient_degrees.iter() {
            let degree = 1 << *log_quotient_degree;
            let slice = quotient_values.drain(0..degree);
            quotient_opened_values.push(slice.map(|mut op| op.pop().unwrap()).collect::<Vec<_>>());
        }

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
        machine: &StarkMachine<SC, A>,
        shards: &[A::Record],
        opts: SP1CoreOpts,
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

        // Get the number of shards that is the threshold for saving shards to disk instead of
        // keeping all the shards in memory.
        let reconstruct_commitments = opts.reconstruct_commitments;
        let finished = AtomicU32::new(0);
        let chunk_size = std::cmp::max(shards.len() / num_cpus::get(), 1);
        let parent_span = tracing::debug_span!("commit to all shards");
        let (commitments, shard_main_data): (Vec<_>, Vec<_>) = parent_span.in_scope(|| {
            shards
                .par_chunks(chunk_size)
                .map(|shard_batch| {
                    shard_batch
                        .iter()
                        .map(|shard| {
                            tracing::debug_span!(parent: &parent_span, "commit to shard").in_scope(
                                || {
                                    let index = shard.index();
                                    let data =
                                        Self::commit_main(config, machine, shard, index as usize);
                                    finished.fetch_add(1, Ordering::Relaxed);
                                    let commitment = data.main_commit.clone();
                                    let data = if reconstruct_commitments {
                                        ShardMainDataWrapper::Empty()
                                    } else {
                                        data.to_in_memory()
                                    };
                                    (commitment, data)
                                },
                            )
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
