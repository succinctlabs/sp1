use core::fmt::Display;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::cmp::Reverse;
use std::error::Error;

use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Pcs;
use p3_commit::PolynomialSpace;
use p3_field::PrimeField32;
use p3_field::{AbstractExtensionField, AbstractField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use super::{quotient_values, StarkMachine, Val};
use super::{types::*, StarkGenericConfig};
use super::{Com, OpeningProof};
use super::{StarkProvingKey, VerifierConstraintFolder};
use crate::air::MachineAir;
use crate::lookup::InteractionBuilder;
use crate::stark::record::MachineRecord;
use crate::stark::DebugConstraintBuilder;
use crate::stark::MachineChip;
use crate::stark::PackedChallenge;
use crate::stark::PcsProverData;
use crate::stark::ProverConstraintFolder;
use crate::stark::StarkVerifyingKey;
use crate::utils::SP1CoreOpts;

pub trait MachineProver<SC: StarkGenericConfig, A: MachineAir<SC::Val>>:
    'static + Send + Sync
{
    /// The type used to store the traces.
    type DeviceMatrix;

    /// The type used to store the polynomial commitment schemes data.
    type DeviceProverData;

    /// The type used for error handling.
    type Error: Error + Send + Sync;

    /// Create a new prover from a given machine.
    fn new(machine: StarkMachine<SC, A>) -> Self;

    /// A reference to the machine that this prover is using.
    fn machine(&self) -> &StarkMachine<SC, A>;

    /// Setup the preprocessed data into a proving and verifying key.
    fn setup(&self, program: &A::Program) -> (StarkProvingKey<SC>, StarkVerifyingKey<SC>) {
        self.machine().setup(program)
    }

    /// Generate the main traces.
    fn generate_traces(&self, record: &A::Record) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        // Filter the chips based on what is used.
        let shard_chips = self.shard_chips(record).collect::<Vec<_>>();

        // For each chip, generate the trace.
        let parent_span = tracing::debug_span!("generate traces for shard");
        parent_span.in_scope(|| {
               shard_chips
                   .par_iter()
                   .map(|chip| {
                       let chip_name = chip.name();
                       let trace = tracing::debug_span!(parent: &parent_span, "generate trace for chip", %chip_name)
                                   .in_scope(|| chip.generate_trace(record, &mut A::Record::default()));
                       (chip_name, trace)
                       })
                       .collect::<Vec<_>>()
                    })
    }

    /// Commit to the main traces.
    fn commit(
        &self,
        record: A::Record,
        traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>;

    /// Observe the main commitment and public values and update the challenger.
    fn observe(
        &self,
        challenger: &mut SC::Challenger,
        commitment: Com<SC>,
        public_values: &[SC::Val],
    ) {
        // Observe the commitment.
        challenger.observe(commitment);

        // Observe the public values.
        challenger.observe_slice(public_values);
    }

    /// Compute the openings of the traces.
    fn open(
        &self,
        pk: &StarkProvingKey<SC>,
        data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut SC::Challenger,
        global_permutation_challenges: &[SC::Challenge],
    ) -> Result<ShardProof<SC>, Self::Error>;

    /// Generate a proof for the given records.
    fn prove(
        &self,
        pk: &StarkProvingKey<SC>,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, Self::Error>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>;

    /// The stark config for the machine.
    fn config(&self) -> &SC {
        self.machine().config()
    }

    /// The number of public values elements.
    fn num_pv_elts(&self) -> usize {
        self.machine().num_pv_elts()
    }

    /// The chips that will be necessary to prove this record.
    fn shard_chips<'a, 'b>(
        &'a self,
        record: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
        SC: 'b,
    {
        self.machine().shard_chips(record)
    }

    /// Debug the constraints for the given inputs.
    fn debug_constraints(
        &self,
        pk: &StarkProvingKey<SC>,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        global_permutation_challenges: &[SC::Challenge],
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        self.machine()
            .debug_constraints(pk, records, challenger, global_permutation_challenges)
    }
}

pub struct CpuProver<SC: StarkGenericConfig, A> {
    machine: StarkMachine<SC, A>,
}

#[derive(Debug, Clone, Copy)]
pub struct CpuProverError;

impl<SC, A> MachineProver<SC, A> for CpuProver<SC, A>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    A: MachineAir<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + Air<InteractionBuilder<Val<SC>>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    A::Record: MachineRecord<Config = SP1CoreOpts>,
    SC::Val: PrimeField32,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    OpeningProof<SC>: Send + Sync,
    SC::Challenger: Clone,
{
    type DeviceMatrix = RowMajorMatrix<Val<SC>>;
    type DeviceProverData = PcsProverData<SC>;
    type Error = CpuProverError;

    fn new(machine: StarkMachine<SC, A>) -> Self {
        Self { machine }
    }

    fn machine(&self) -> &StarkMachine<SC, A> {
        &self.machine
    }

    fn commit(
        &self,
        record: A::Record,
        mut named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData> {
        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_traces.sort_by_key(|(_, trace)| Reverse(trace.height()));

        let pcs = self.config().pcs();

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
            public_values: record.public_values(),
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    fn open(
        &self,
        pk: &StarkProvingKey<SC>,
        mut data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut <SC as StarkGenericConfig>::Challenger,
        global_permutation_challenges: &[SC::Challenge],
    ) -> Result<ShardProof<SC>, Self::Error> {
        let chips = self
            .machine()
            .shard_chips_ordered(&data.chip_ordering)
            .collect::<Vec<_>>();
        let config = self.machine().config();
        // Get the traces.
        let traces = &mut data.traces;

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

        // Observe the main commitment.
        challenger.observe(data.main_commit.clone());

        // Obtain the challenges used for the local permutation argument.
        let mut local_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            local_permutation_challenges.push(challenger.sample_ext_element());
        }

        let [packed_global_perm_challenges, packed_local_perm_challenges] =
            [global_permutation_challenges, &local_permutation_challenges].map(|challenges| {
                challenges
                    .iter()
                    .map(|c| PackedChallenge::<SC>::from_f(*c))
                    .collect::<Vec<_>>()
            });

        // Generate the permutation traces.
        let mut permutation_traces = Vec::with_capacity(chips.len());
        let mut cumulative_sums = Vec::with_capacity(chips.len());
        tracing::debug_span!("generate global and local permutation traces").in_scope(|| {
            chips
                .par_iter()
                .zip(traces.par_iter_mut())
                .map(|(chip, main_trace)| {
                    let preprocessed_trace = pk
                        .chip_ordering
                        .get(&chip.name())
                        .map(|&index| &pk.traces[index]);
                    let (global_perm_trace, local_perm_trace) = chip.generate_permutation_trace(
                        preprocessed_trace,
                        main_trace,
                        &global_permutation_challenges,
                        &local_permutation_challenges,
                    );
                    let [global_cumulative_sums, local_cumulative_sums] =
                        [&global_perm_trace, &local_perm_trace].map(|perm_trace| {
                            perm_trace
                                .row_slice(perm_trace.height() - 1)
                                .last()
                                .copied()
                                .unwrap()
                        });
                    (
                        (global_perm_trace, local_perm_trace),
                        (global_cumulative_sums, local_cumulative_sums),
                    )
                })
                .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
        });

        let (global_permutation_traces, local_permutation_traces): (Vec<_>, Vec<_>) =
            permutation_traces.into_iter().unzip();

        // Compute some statistics.
        for i in 0..chips.len() {
            let trace_width = traces[i].width();
            let permutation_width =
                global_permutation_traces[i].width() + local_permutation_traces[i].width();
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
            tracing::debug_span!("flatten global and local permutation traces and collect domains")
                .in_scope(|| {
                    [global_permutation_traces, local_permutation_traces].map(|perm_traces| {
                        perm_traces
                            .into_iter()
                            .zip(trace_domains.iter())
                            .map(|(perm_trace, domain)| {
                                let trace = perm_trace.flatten_to_base();
                                (*domain, trace.to_owned())
                            })
                            .collect::<Vec<_>>()
                    })
                });

        let pcs = config.pcs();

        let [(global_permutation_commit, global_permutation_data), (local_permutation_commit, local_permutation_data)] =
            tracing::debug_span!("commit to global and local permutation traces").in_scope(|| {
                domains_and_perm_traces.map(|scoped_domains_and_perm_traces| {
                    pcs.commit(scoped_domains_and_perm_traces)
                })
            });
        challenger.observe(global_permutation_commit.clone());
        challenger.observe(local_permutation_commit.clone());

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
                                .get_evaluations_on_domain(&data.main_data, i, *quotient_domain)
                                .to_row_major_matrix();
                            let global_permutation_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(
                                    &global_permutation_data,
                                    i,
                                    *quotient_domain,
                                )
                                .to_row_major_matrix();
                            let local_permutation_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(
                                    &local_permutation_data,
                                    i,
                                    *quotient_domain,
                                )
                                .to_row_major_matrix();
                            quotient_values(
                                chips[i],
                                cumulative_sums[i].into(),
                                trace_domains[i],
                                *quotient_domain,
                                preprocessed_trace_on_quotient_domains,
                                main_trace_on_quotient_domains,
                                global_permutation_trace_on_quotient_domains,
                                &packed_global_perm_challenges,
                                local_permutation_trace_on_quotient_domains,
                                &packed_local_perm_challenges,
                                alpha,
                                &data.public_values,
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
                    (&data.main_data, trace_opening_points.clone()),
                    (&global_permutation_data, trace_opening_points.clone()),
                    (&local_permutation_data, trace_opening_points),
                    (&quotient_data, quotient_opening_points),
                ],
                challenger,
            )
        });

        // Collect the opened values for each chip.
        let [preprocessed_values, main_values, global_permutation_values, local_permutation_values, mut quotient_values] =
            openings.try_into().unwrap();
        assert!(main_values.len() == chips.len());
        let [preprocessed_opened_values, main_opened_values, global_permutation_opened_values, local_permutation_opened_values] =
            [
                preprocessed_values,
                main_values,
                global_permutation_values,
                local_permutation_values,
            ]
            .map(|values| {
                values
                    .into_iter()
                    .map(|op| {
                        let [local, next] = op.try_into().unwrap();
                        AirOpenedValues { local, next }
                    })
                    .collect::<Vec<_>>()
            });

        let mut quotient_opened_values = Vec::with_capacity(log_quotient_degrees.len());
        for log_quotient_degree in log_quotient_degrees.iter() {
            let degree = 1 << *log_quotient_degree;
            let slice = quotient_values.drain(0..degree);
            quotient_opened_values.push(slice.map(|mut op| op.pop().unwrap()).collect::<Vec<_>>());
        }

        let opened_values = main_opened_values
            .into_iter()
            .zip_eq(global_permutation_opened_values)
            .zip_eq(local_permutation_opened_values)
            .zip_eq(quotient_opened_values)
            .zip_eq(cumulative_sums)
            .zip_eq(log_degrees.iter())
            .enumerate()
            .map(
                |(
                    i,
                    (
                        (
                            (((main, global_permutation), local_permutation), quotient),
                            cumulative_sum,
                        ),
                        log_degree,
                    ),
                )| {
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
                        global_permutation,
                        local_permutation,
                        quotient,
                        global_cumulative_sum: cumulative_sum.0,
                        local_cumulative_sum: cumulative_sum.1,
                        log_degree: *log_degree,
                    }
                },
            )
            .collect::<Vec<_>>();

        Ok(ShardProof::<SC> {
            commitment: ShardCommitment {
                main_commit: data.main_commit.clone(),
                global_permutation_commit,
                local_permutation_commit,
                quotient_commit,
            },
            opened_values: ShardOpenedValues {
                chips: opened_values,
            },
            opening_proof,
            chip_ordering: data.chip_ordering,
            public_values: data.public_values,
        })
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    fn prove(
        &self,
        pk: &StarkProvingKey<SC>,
        mut records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
        opts: <A::Record as MachineRecord>::Config,
    ) -> Result<MachineProof<SC>, Self::Error>
    where
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        // Generate dependencies.
        self.machine().generate_dependencies(&mut records, &opts);

        // Observe the preprocessed commitment.
        pk.observe_into(challenger);

        // Generate and commit the traces for each shard.
        let shard_data = records
            .into_par_iter()
            .map(|record| {
                let named_traces = self.generate_traces(&record);
                self.commit(record, named_traces)
            })
            .collect::<Vec<_>>();

        // Observe the challenges for each segment.
        tracing::debug_span!("observing all challenges").in_scope(|| {
            shard_data.iter().for_each(|data| {
                challenger.observe(data.main_commit.clone());
                challenger.observe_slice(&data.public_values[0..self.num_pv_elts()]);
            });
        });

        // Obtain the challenges used for the global permutation argument.
        let mut global_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            global_permutation_challenges.push(challenger.sample_ext_element());
        }

        let shard_proofs = tracing::info_span!("prove_shards").in_scope(|| {
            shard_data
                .into_par_iter()
                .map(|data| {
                    self.open(
                        pk,
                        data,
                        &mut challenger.clone(),
                        &global_permutation_challenges,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(MachineProof { shard_proofs })
    }
}

impl Display for CpuProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DefaultProverError")
    }
}

impl Error for CpuProverError {}
