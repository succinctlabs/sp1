use core::fmt::Display;
use hashbrown::HashMap;
use itertools::Itertools;
use serde::{de::DeserializeOwned, Serialize};
use std::{array, cmp::Reverse, error::Error, time::Instant};

use crate::{air::InteractionScope, AirOpenedValues, ChipOpenedValues, ShardOpenedValues};
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{AbstractExtensionField, AbstractField, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use super::{
    quotient_values, Com, OpeningProof, StarkGenericConfig, StarkMachine, StarkProvingKey, Val,
    VerifierConstraintFolder,
};
use crate::{
    air::MachineAir, config::ZeroCommitment, lookup::InteractionBuilder, opts::SP1CoreOpts,
    record::MachineRecord, Challenger, DebugConstraintBuilder, MachineChip, MachineProof,
    PackedChallenge, PcsProverData, ProverConstraintFolder, ShardCommitment, ShardMainData,
    ShardProof, StarkVerifyingKey,
};

/// A merged prover data item from the global and local prover data.
pub struct MergedProverDataItem<'a, M> {
    /// The trace.
    pub trace: &'a M,
    /// The main data index.
    pub main_data_idx: usize,
}

/// An algorithmic & hardware independent prover implementation for any [`MachineAir`].
pub trait MachineProver<SC: StarkGenericConfig, A: MachineAir<SC::Val>>:
    'static + Send + Sync
{
    /// The type used to store the traces.
    type DeviceMatrix: Matrix<SC::Val>;

    /// The type used to store the polynomial commitment schemes data.
    type DeviceProverData;

    /// The type used to store the proving key.
    type DeviceProvingKey: MachineProvingKey<SC>;

    /// The type used for error handling.
    type Error: Error + Send + Sync;

    /// Create a new prover from a given machine.
    fn new(machine: StarkMachine<SC, A>) -> Self;

    /// A reference to the machine that this prover is using.
    fn machine(&self) -> &StarkMachine<SC, A>;

    /// Setup the preprocessed data into a proving and verifying key.
    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>);

    /// Generate the main traces.
    fn generate_traces(
        &self,
        record: &A::Record,
        interaction_scope: InteractionScope,
    ) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        let shard_chips = self.shard_chips(record).collect::<Vec<_>>();
        let chips = shard_chips
            .iter()
            .filter(|chip| chip.commit_scope() == interaction_scope)
            .collect::<Vec<_>>();
        assert!(!chips.is_empty());

        // For each chip, generate the trace.
        let parent_span = tracing::debug_span!("generate traces for shard");
        parent_span.in_scope(|| {
            chips
                .par_iter()
                .map(|chip| {
                    let chip_name = chip.name();
                    let begin = Instant::now();
                    let trace = chip.generate_trace(record, &mut A::Record::default());
                    tracing::debug!(
                        parent: &parent_span,
                        "generated trace for chip {} in {:?}",
                        chip_name,
                        begin.elapsed()
                    );
                    (chip_name, trace)
                })
                .collect::<Vec<_>>()
        })
    }

    /// Commit to the main traces.
    fn commit(
        &self,
        record: &A::Record,
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
        pk: &Self::DeviceProvingKey,
        global_data: Option<ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>>,
        local_data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut SC::Challenger,
        global_permutation_challenges: &[SC::Challenge],
    ) -> Result<ShardProof<SC>, Self::Error>;

    /// Generate a proof for the given records.
    fn prove(
        &self,
        pk: &Self::DeviceProvingKey,
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
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        self.machine().debug_constraints(pk, records, challenger);
    }

    /// Merge the global and local chips' sorted traces.
    #[allow(clippy::type_complexity)]
    fn merge_shard_traces<'a, 'b>(
        &'a self,
        global_traces: &'b [Self::DeviceMatrix],
        global_chip_ordering: &'b HashMap<String, usize>,
        local_traces: &'b [Self::DeviceMatrix],
        local_chip_ordering: &'b HashMap<String, usize>,
    ) -> (
        HashMap<String, usize>,
        Vec<InteractionScope>,
        Vec<MergedProverDataItem<'b, Self::DeviceMatrix>>,
    )
    where
        'a: 'b,
    {
        // Get the sort order of the chips.
        let global_chips = global_chip_ordering
            .iter()
            .sorted_by_key(|(_, &i)| i)
            .map(|chip| chip.0.clone())
            .collect::<Vec<_>>();
        let local_chips = local_chip_ordering
            .iter()
            .sorted_by_key(|(_, &i)| i)
            .map(|chip| chip.0.clone())
            .collect::<Vec<_>>();

        let mut merged_chips = Vec::with_capacity(global_traces.len() + local_traces.len());
        let mut merged_prover_data = Vec::with_capacity(global_chips.len() + local_chips.len());

        assert!(global_traces.len() == global_chips.len());
        let mut global_iter = global_traces.iter().zip(global_chips.iter()).enumerate();
        assert!(local_traces.len() == local_chips.len());
        let mut local_iter = local_traces.iter().zip(local_chips.iter()).enumerate();

        let mut global_next = global_iter.next();
        let mut local_next = local_iter.next();

        let mut chip_scopes = Vec::new();

        while global_next.is_some() || local_next.is_some() {
            match (global_next, local_next) {
                (Some(global), Some(local)) => {
                    let (global_prover_data_idx, (global_trace, global_chip)) = global;
                    let (local_prover_data_idx, (local_trace, local_chip)) = local;
                    if (Reverse(global_trace.height()), global_chip)
                        < (Reverse(local_trace.height()), local_chip)
                    {
                        merged_chips.push(global_chip.clone());
                        chip_scopes.push(InteractionScope::Global);
                        merged_prover_data.push(MergedProverDataItem {
                            trace: global_trace,
                            main_data_idx: global_prover_data_idx,
                        });
                        global_next = global_iter.next();
                    } else {
                        merged_chips.push(local_chip.clone());
                        chip_scopes.push(InteractionScope::Local);
                        merged_prover_data.push(MergedProverDataItem {
                            trace: local_trace,
                            main_data_idx: local_prover_data_idx,
                        });
                        local_next = local_iter.next();
                    }
                }
                (Some(global), None) => {
                    let (global_prover_data_idx, (global_trace, global_chip)) = global;
                    merged_chips.push(global_chip.clone());
                    chip_scopes.push(InteractionScope::Global);
                    merged_prover_data.push(MergedProverDataItem {
                        trace: global_trace,
                        main_data_idx: global_prover_data_idx,
                    });
                    global_next = global_iter.next();
                }
                (None, Some(local)) => {
                    let (local_prover_data_idx, (local_trace, local_chip)) = local;
                    merged_chips.push(local_chip.clone());
                    chip_scopes.push(InteractionScope::Local);
                    merged_prover_data.push(MergedProverDataItem {
                        trace: local_trace,
                        main_data_idx: local_prover_data_idx,
                    });
                    local_next = local_iter.next();
                }
                (None, None) => break,
            }
        }

        let chip_ordering =
            merged_chips.iter().enumerate().map(|(i, name)| (name.clone(), i)).collect();

        (chip_ordering, chip_scopes, merged_prover_data)
    }
}

/// A proving key for any [`MachineAir`] that is agnostic to hardware.
pub trait MachineProvingKey<SC: StarkGenericConfig>: Send + Sync {
    /// The main commitment.
    fn preprocessed_commit(&self) -> Com<SC>;

    /// The start pc.
    fn pc_start(&self) -> Val<SC>;

    /// The proving key on the host.
    fn to_host(&self) -> StarkProvingKey<SC>;

    /// The proving key on the device.
    fn from_host(host: &StarkProvingKey<SC>) -> Self;

    /// Observe itself in the challenger.
    fn observe_into(&self, challenger: &mut Challenger<SC>);
}

/// A prover implementation based on x86 and ARM CPUs.
pub struct CpuProver<SC: StarkGenericConfig, A> {
    machine: StarkMachine<SC, A>,
}

/// An error that occurs during the execution of the [`CpuProver`].
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
    type DeviceProvingKey = StarkProvingKey<SC>;
    type Error = CpuProverError;

    fn new(machine: StarkMachine<SC, A>) -> Self {
        Self { machine }
    }

    fn machine(&self) -> &StarkMachine<SC, A> {
        &self.machine
    }

    fn setup(&self, program: &A::Program) -> (Self::DeviceProvingKey, StarkVerifyingKey<SC>) {
        self.machine().setup(program)
    }

    fn commit(
        &self,
        record: &A::Record,
        mut named_traces: Vec<(String, RowMajorMatrix<Val<SC>>)>,
    ) -> ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData> {
        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_traces.sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

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
        let chip_ordering =
            named_traces.iter().enumerate().map(|(i, (name, _))| (name.to_owned(), i)).collect();

        let traces = named_traces.into_iter().map(|(_, trace)| trace).collect::<Vec<_>>();

        ShardMainData {
            traces,
            main_commit,
            main_data,
            chip_ordering,
            public_values: record.public_values(),
        }
    }

    /// Prove the program for the given shard and given a commitment to the main data.
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::redundant_closure_for_method_calls)]
    #[allow(clippy::map_unwrap_or)]
    fn open(
        &self,
        pk: &StarkProvingKey<SC>,
        global_data: Option<ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>>,
        local_data: ShardMainData<SC, Self::DeviceMatrix, Self::DeviceProverData>,
        challenger: &mut <SC as StarkGenericConfig>::Challenger,
        global_permutation_challenges: &[SC::Challenge],
    ) -> Result<ShardProof<SC>, Self::Error> {
        let (global_traces, global_main_commit, global_main_data, global_chip_ordering) =
            if let Some(global_data) = global_data {
                let ShardMainData {
                    traces: global_traces,
                    main_commit: global_main_commit,
                    main_data: global_main_data,
                    chip_ordering: global_chip_ordering,
                    public_values: _,
                } = global_data;
                (global_traces, global_main_commit, Some(global_main_data), global_chip_ordering)
            } else {
                (vec![], self.config().pcs().zero_commitment(), None, HashMap::new())
            };

        let ShardMainData {
            traces: local_traces,
            main_commit: local_main_commit,
            main_data: local_main_data,
            chip_ordering: local_chip_ordering,
            public_values: local_public_values,
        } = local_data;

        // Merge the chip ordering and traces from the global and local data.
        let (all_chips_ordering, all_chip_scopes, all_shard_data) = self.merge_shard_traces(
            &global_traces,
            &global_chip_ordering,
            &local_traces,
            &local_chip_ordering,
        );

        let chips = self.machine().shard_chips_ordered(&all_chips_ordering).collect::<Vec<_>>();

        assert!(chips.len() == all_shard_data.len());

        let config = self.machine().config();

        let degrees =
            all_shard_data.iter().map(|shard_data| shard_data.trace.height()).collect::<Vec<_>>();

        let log_degrees =
            degrees.iter().map(|degree| log2_strict_usize(*degree)).collect::<Vec<_>>();

        let log_quotient_degrees =
            chips.iter().map(|chip| chip.log_quotient_degree()).collect::<Vec<_>>();

        let pcs = config.pcs();
        let trace_domains =
            degrees.iter().map(|degree| pcs.natural_domain_for_degree(*degree)).collect::<Vec<_>>();

        // Observe the main commitment.
        challenger.observe(local_main_commit.clone());

        // Obtain the challenges used for the local permutation argument.
        let mut local_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            local_permutation_challenges.push(challenger.sample_ext_element());
        }

        let permutation_challenges = global_permutation_challenges
            .iter()
            .chain(local_permutation_challenges.iter())
            .copied()
            .collect::<Vec<_>>();

        let packed_perm_challenges = permutation_challenges
            .iter()
            .chain(local_permutation_challenges.iter())
            .map(|c| PackedChallenge::<SC>::from_f(*c))
            .collect::<Vec<_>>();

        // Generate the permutation traces.
        let ((permutation_traces, prep_traces), cumulative_sums): ((Vec<_>, Vec<_>), Vec<_>) =
            tracing::debug_span!("generate permutation traces").in_scope(|| {
                chips
                    .par_iter()
                    .zip(all_shard_data.par_iter())
                    .map(|(chip, shard_data)| {
                        let preprocessed_trace =
                            pk.chip_ordering.get(&chip.name()).map(|&index| &pk.traces[index]);
                        let (perm_trace, global_sum, local_sum) = chip.generate_permutation_trace(
                            preprocessed_trace,
                            shard_data.trace,
                            &permutation_challenges,
                        );
                        ((perm_trace, preprocessed_trace), [global_sum, local_sum])
                    })
                    .unzip()
            });

        // Compute some statistics.
        for i in 0..chips.len() {
            let trace_width = all_shard_data[i].trace.width();
            let trace_height = all_shard_data[i].trace.height();
            let prep_width = prep_traces[i].map_or(0, |x| x.width());
            let permutation_width = permutation_traces[i].width();
            let total_width = trace_width
                + prep_width
                + permutation_width * <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
            tracing::debug!(
                "{:<15} | Main Cols = {:<5} | Pre Cols = {:<5}  | Perm Cols = {:<5} | Rows = {:<5} | Cells = {:<10}",
                chips[i].name(),
                trace_width,
                prep_width,
                permutation_width * <SC::Challenge as AbstractExtensionField<SC::Val>>::D,
                trace_height,
                total_width * trace_height,
            );
        }

        let domains_and_perm_traces =
            tracing::debug_span!("flatten permutation traces and collect domains").in_scope(|| {
                permutation_traces
                    .into_iter()
                    .zip(trace_domains.iter())
                    .map(|(perm_trace, domain)| {
                        let trace = perm_trace.flatten_to_base();
                        (*domain, trace.clone())
                    })
                    .collect::<Vec<_>>()
            });

        let pcs = config.pcs();

        let (permutation_commit, permutation_data) =
            tracing::debug_span!("commit to permutation traces")
                .in_scope(|| pcs.commit(domains_and_perm_traces));

        // Observe the permutation commitment and cumulative sums.
        challenger.observe(permutation_commit.clone());
        for [global_sum, local_sum] in cumulative_sums.iter() {
            challenger.observe_slice(global_sum.as_base_slice());
            challenger.observe_slice(local_sum.as_base_slice());
        }

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
                            let preprocessed_trace_on_quotient_domains =
                                pk.chip_ordering.get(&chips[i].name()).map(|&index| {
                                    pcs.get_evaluations_on_domain(&pk.data, index, *quotient_domain)
                                });
                            let scope = all_chip_scopes[i];
                            let main_data = if scope == InteractionScope::Global {
                                global_main_data
                                    .as_ref()
                                    .expect("Expected global_main_data to be Some")
                            } else {
                                &local_main_data
                            };
                            let main_trace_on_quotient_domains = pcs.get_evaluations_on_domain(
                                main_data,
                                all_shard_data[i].main_data_idx,
                                *quotient_domain,
                            );
                            let permutation_trace_on_quotient_domains = pcs
                                .get_evaluations_on_domain(&permutation_data, i, *quotient_domain);
                            quotient_values(
                                chips[i],
                                &cumulative_sums[i],
                                trace_domains[i],
                                *quotient_domain,
                                preprocessed_trace_on_quotient_domains,
                                main_trace_on_quotient_domains,
                                permutation_trace_on_quotient_domains,
                                &packed_perm_challenges,
                                alpha,
                                &local_public_values,
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
            .flat_map(|((quotient_domain, quotient_values), log_quotient_degree)| {
                let quotient_degree = 1 << *log_quotient_degree;
                let quotient_flat = RowMajorMatrix::new_col(quotient_values).flatten_to_base();
                let quotient_chunks = quotient_domain.split_evals(quotient_degree, quotient_flat);
                let qc_domains = quotient_domain.split_domains(quotient_degree);
                qc_domains.into_iter().zip_eq(quotient_chunks)
            })
            .collect::<Vec<_>>();

        let num_quotient_chunks = quotient_domains_and_chunks.len();
        assert_eq!(
            num_quotient_chunks,
            chips.iter().map(|c| 1 << c.log_quotient_degree()).sum::<usize>()
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

        // Compute quotient opening points, open every chunk at zeta.
        let quotient_opening_points =
            (0..num_quotient_chunks).map(|_| vec![zeta]).collect::<Vec<_>>();

        // Split the trace_opening_points to the global and local chips.
        let mut global_trace_opening_points = Vec::with_capacity(global_chip_ordering.len());
        let mut local_trace_opening_points = Vec::with_capacity(local_chip_ordering.len());
        for (i, trace_opening_point) in trace_opening_points.clone().into_iter().enumerate() {
            let scope = all_chip_scopes[i];
            if scope == InteractionScope::Global {
                global_trace_opening_points.push(trace_opening_point);
            } else {
                local_trace_opening_points.push(trace_opening_point);
            }
        }

        let rounds = if let Some(global_main_data) = global_main_data.as_ref() {
            vec![
                (&pk.data, preprocessed_opening_points),
                (global_main_data, global_trace_opening_points),
                (&local_main_data, local_trace_opening_points),
                (&permutation_data, trace_opening_points),
                (&quotient_data, quotient_opening_points),
            ]
        } else {
            vec![
                (&pk.data, preprocessed_opening_points),
                (&local_main_data, local_trace_opening_points),
                (&permutation_data, trace_opening_points),
                (&quotient_data, quotient_opening_points),
            ]
        };

        let (openings, opening_proof) =
            tracing::debug_span!("open multi batches").in_scope(|| pcs.open(rounds, challenger));

        // Collect the opened values for each chip.
        let (
            preprocessed_values,
            global_main_values,
            local_main_values,
            permutation_values,
            mut quotient_values,
        ) = if global_main_data.is_some() {
            let [preprocessed_values, global_main_values, local_main_values, permutation_values, quotient_values] =
                openings.try_into().unwrap();
            (
                preprocessed_values,
                Some(global_main_values),
                local_main_values,
                permutation_values,
                quotient_values,
            )
        } else {
            let [preprocessed_values, local_main_values, permutation_values, quotient_values] =
                openings.try_into().unwrap();
            (preprocessed_values, None, local_main_values, permutation_values, quotient_values)
        };

        let preprocessed_opened_values = preprocessed_values
            .into_iter()
            .map(|op| {
                let [local, next] = op.try_into().unwrap();
                AirOpenedValues { local, next }
            })
            .collect::<Vec<_>>();

        // Merge the global and local main values.
        let mut main_values =
            Vec::with_capacity(global_chip_ordering.len() + local_chip_ordering.len());
        for chip in chips.iter() {
            let global_order = global_chip_ordering.get(&chip.name());
            let local_order = local_chip_ordering.get(&chip.name());
            match (global_order, local_order) {
                (Some(&global_order), None) => {
                    let global_main_values =
                        global_main_values.as_ref().expect("Global main values should be Some");
                    main_values.push(global_main_values[global_order].clone());
                }
                (None, Some(&local_order)) => {
                    main_values.push(local_main_values[local_order].clone());
                }
                _ => unreachable!(),
            }
        }
        assert!(main_values.len() == chips.len());

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
            .map(|(i, ((((main, permutation), quotient), cumulative_sums), log_degree))| {
                let preprocessed = pk
                    .chip_ordering
                    .get(&chips[i].name())
                    .map(|&index| preprocessed_opened_values[index].clone())
                    .unwrap_or(AirOpenedValues { local: vec![], next: vec![] });
                ChipOpenedValues {
                    preprocessed,
                    main,
                    permutation,
                    quotient,
                    global_cumulative_sum: cumulative_sums[0],
                    local_cumulative_sum: cumulative_sums[1],
                    log_degree: *log_degree,
                }
            })
            .collect::<Vec<_>>();

        Ok(ShardProof::<SC> {
            commitment: ShardCommitment {
                global_main_commit,
                local_main_commit,
                permutation_commit,
                quotient_commit,
            },
            opened_values: ShardOpenedValues { chips: opened_values },
            opening_proof,
            chip_ordering: all_chips_ordering,
            public_values: local_public_values,
        })
    }

    /// Prove the execution record is valid.
    ///
    /// Given a proving key `pk` and a matching execution record `record`, this function generates
    /// a STARK proof that the execution record is valid.
    #[allow(clippy::needless_for_each)]
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
        // Observe the preprocessed commitment.
        pk.observe_into(challenger);

        let contains_global_bus = self.machine().contains_global_bus();

        if contains_global_bus {
            // Generate dependencies.
            self.machine().generate_dependencies(&mut records, &opts, None);
        }

        // Generate and commit the global traces for each shard.
        let global_data = records
            .par_iter()
            .map(|record| {
                if contains_global_bus {
                    let global_named_traces =
                        self.generate_traces(record, InteractionScope::Global);
                    Some(self.commit(record, global_named_traces))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Observe the challenges for each segment.
        tracing::debug_span!("observing all challenges").in_scope(|| {
            global_data.iter().zip_eq(records.iter()).for_each(|(global_data, record)| {
                if contains_global_bus {
                    challenger.observe(
                        global_data
                            .as_ref()
                            .expect("must have a global commitment")
                            .main_commit
                            .clone(),
                    );
                }
                challenger.observe_slice(&record.public_values::<SC::Val>()[0..self.num_pv_elts()]);
            });
        });

        // Obtain the challenges used for the global permutation argument.
        let global_permutation_challenges: [SC::Challenge; 2] = array::from_fn(|_| {
            if contains_global_bus {
                challenger.sample_ext_element()
            } else {
                SC::Challenge::zero()
            }
        });

        let shard_proofs = tracing::info_span!("prove_shards").in_scope(|| {
            global_data
                .into_par_iter()
                .zip_eq(records.par_iter())
                .map(|(global_shard_data, record)| {
                    let local_named_traces = self.generate_traces(record, InteractionScope::Local);
                    let local_shard_data = self.commit(record, local_named_traces);
                    self.open(
                        pk,
                        global_shard_data,
                        local_shard_data,
                        &mut challenger.clone(),
                        &global_permutation_challenges,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        })?;

        Ok(MachineProof { shard_proofs })
    }
}

impl<SC> MachineProvingKey<SC> for StarkProvingKey<SC>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    PcsProverData<SC>: Send + Sync + Serialize + DeserializeOwned,
    Com<SC>: Send + Sync,
{
    fn preprocessed_commit(&self) -> Com<SC> {
        self.commit.clone()
    }

    fn pc_start(&self) -> Val<SC> {
        self.pc_start
    }

    fn to_host(&self) -> StarkProvingKey<SC> {
        self.clone()
    }

    fn from_host(host: &StarkProvingKey<SC>) -> Self {
        host.clone()
    }

    fn observe_into(&self, challenger: &mut Challenger<SC>) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        let zero = Val::<SC>::zero();
        for _ in 0..7 {
            challenger.observe(zero);
        }
    }
}

impl Display for CpuProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DefaultProverError")
    }
}

impl Error for CpuProverError {}
