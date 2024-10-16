use hashbrown::HashMap;
use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Pcs;
use p3_field::{AbstractExtensionField, AbstractField, Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Dimensions, Matrix};
use p3_maybe_rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{array, cmp::Reverse, env, fmt::Debug, time::Instant};
use tracing::instrument;

use super::{debug_constraints, Dom};
use crate::{
    air::{InteractionScope, MachineAir, MachineProgram},
    lookup::{debug_interactions_with_all_chips, InteractionKind},
    record::MachineRecord,
    DebugConstraintBuilder, ShardProof, VerifierConstraintFolder,
};

use super::{
    Chip, Com, MachineProof, PcsProverData, StarkGenericConfig, Val, VerificationError, Verifier,
};

/// A chip in a machine.
pub type MachineChip<SC, A> = Chip<Val<SC>, A>;

/// A STARK for proving RISC-V execution.
pub struct StarkMachine<SC: StarkGenericConfig, A> {
    /// The STARK settings for the RISC-V STARK.
    config: SC,
    /// The chips that make up the RISC-V STARK machine, in order of their execution.
    chips: Vec<Chip<Val<SC>, A>>,

    /// The number of public values elements that the machine uses
    num_pv_elts: usize,

    /// Contains a global bus.  This should be true for the core machine and false otherwise.
    contains_global_bus: bool,
}

impl<SC: StarkGenericConfig, A> StarkMachine<SC, A> {
    /// Creates a new [`StarkMachine`].
    pub const fn new(
        config: SC,
        chips: Vec<Chip<Val<SC>, A>>,
        num_pv_elts: usize,
        contains_global_bus: bool,
    ) -> Self {
        Self { config, chips, num_pv_elts, contains_global_bus }
    }
}

/// A proving key for a STARK.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PcsProverData<SC>: Serialize"))]
#[serde(bound(deserialize = "PcsProverData<SC>: DeserializeOwned"))]
pub struct StarkProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
    /// The preprocessed traces.
    pub traces: Vec<RowMajorMatrix<Val<SC>>>,
    /// The pcs data for the preprocessed traces.
    pub data: PcsProverData<SC>,
    /// The preprocessed chip ordering.
    pub chip_ordering: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> StarkProvingKey<SC> {
    /// Observes the values of the proving key into the challenger.
    pub fn observe_into(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        for _ in 0..7 {
            challenger.observe(Val::<SC>::zero());
        }
    }
}

/// A verifying key for a STARK.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Dom<SC>: Serialize"))]
#[serde(bound(deserialize = "Dom<SC>: DeserializeOwned"))]
pub struct StarkVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// The start pc of the program.
    pub pc_start: Val<SC>,
    /// The chip information.
    pub chip_information: Vec<(String, Dom<SC>, Dimensions)>,
    /// The chip ordering.
    pub chip_ordering: HashMap<String, usize>,
}

impl<SC: StarkGenericConfig> StarkVerifyingKey<SC> {
    /// Observes the values of the verifying key into the challenger.
    pub fn observe_into(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        for _ in 0..7 {
            challenger.observe(Val::<SC>::zero());
        }
    }
}

impl<SC: StarkGenericConfig> Debug for StarkVerifyingKey<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey").finish()
    }
}

impl<SC: StarkGenericConfig, A: MachineAir<Val<SC>>> StarkMachine<SC, A> {
    /// Get an array containing a `ChipRef` for all the chips of this RISC-V STARK machine.
    pub fn chips(&self) -> &[MachineChip<SC, A>] {
        &self.chips
    }

    /// Returns the number of public values elements.
    pub const fn num_pv_elts(&self) -> usize {
        self.num_pv_elts
    }

    /// Returns whether the machine contains a global bus.
    pub const fn contains_global_bus(&self) -> bool {
        self.contains_global_bus
    }

    /// Returns the id of all chips in the machine that have preprocessed columns.
    pub fn preprocessed_chip_ids(&self) -> Vec<usize> {
        self.chips
            .iter()
            .enumerate()
            .filter(|(_, chip)| chip.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// Returns an iterator over the chips in the machine that are included in the given shard.
    pub fn shard_chips<'a, 'b>(
        &'a self,
        shard: &'b A::Record,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips.iter().filter(|chip| chip.included(shard))
    }

    /// Returns an iterator over the chips in the machine that are included in the given shard.
    pub fn shard_chips_ordered<'a, 'b>(
        &'a self,
        chip_ordering: &'b HashMap<String, usize>,
    ) -> impl Iterator<Item = &'b MachineChip<SC, A>>
    where
        'a: 'b,
    {
        self.chips
            .iter()
            .filter(|chip| chip_ordering.contains_key(&chip.name()))
            .sorted_by_key(|chip| chip_ordering.get(&chip.name()))
    }

    /// Returns the indices of the chips in the machine that are included in the given shard.
    pub fn chips_sorted_indices(&self, proof: &ShardProof<SC>) -> Vec<Option<usize>> {
        self.chips().iter().map(|chip| proof.chip_ordering.get(&chip.name()).copied()).collect()
    }

    /// The setup preprocessing phase.
    ///
    /// Given a program, this function generates the proving and verifying keys. The keys correspond
    /// to the program code and other preprocessed colunms such as lookup tables.
    #[instrument("setup machine", level = "debug", skip_all)]
    #[allow(clippy::map_unwrap_or)]
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn setup(&self, program: &A::Program) -> (StarkProvingKey<SC>, StarkVerifyingKey<SC>) {
        let parent_span = tracing::debug_span!("generate preprocessed traces");
        let mut named_preprocessed_traces = parent_span.in_scope(|| {
            self.chips()
                .par_iter()
                .filter_map(|chip| {
                    let chip_name = chip.name();
                    let begin = Instant::now();
                    let prep_trace = chip.generate_preprocessed_trace(program);
                    tracing::debug!(
                        parent: &parent_span,
                        "generated preprocessed trace for chip {} in {:?}",
                        chip_name,
                        begin.elapsed()
                    );
                    // Assert that the chip width data is correct.
                    let expected_width = prep_trace.as_ref().map(|t| t.width()).unwrap_or(0);
                    assert_eq!(
                        expected_width,
                        chip.preprocessed_width(),
                        "Incorrect number of preprocessed columns for chip {chip_name}"
                    );
                    prep_trace.map(move |t| (chip_name, t))
                })
                .collect::<Vec<_>>()
        });

        // Order the chips and traces by trace size (biggest first), and get the ordering map.
        named_preprocessed_traces
            .sort_by_key(|(name, trace)| (Reverse(trace.height()), name.clone()));

        let pcs = self.config.pcs();
        let (chip_information, domains_and_traces): (Vec<_>, Vec<_>) = named_preprocessed_traces
            .iter()
            .map(|(name, trace)| {
                let domain = pcs.natural_domain_for_degree(trace.height());
                ((name.to_owned(), domain, trace.dimensions()), (domain, trace.to_owned()))
            })
            .unzip();

        // Commit to the batch of traces.
        let (commit, data) = tracing::debug_span!("commit to preprocessed traces")
            .in_scope(|| pcs.commit(domains_and_traces));

        // Get the chip ordering.
        let chip_ordering = named_preprocessed_traces
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_owned(), i))
            .collect::<HashMap<_, _>>();

        // Get the preprocessed traces
        let traces =
            named_preprocessed_traces.into_iter().map(|(_, trace)| trace).collect::<Vec<_>>();

        let pc_start = program.pc_start();

        (
            StarkProvingKey {
                commit: commit.clone(),
                pc_start,
                traces,
                data,
                chip_ordering: chip_ordering.clone(),
            },
            StarkVerifyingKey { commit, pc_start, chip_information, chip_ordering },
        )
    }

    /// Generates the dependencies of the given records.
    #[allow(clippy::needless_for_each)]
    pub fn generate_dependencies(
        &self,
        records: &mut [A::Record],
        opts: &<A::Record as MachineRecord>::Config,
        chips_filter: Option<&[String]>,
    ) {
        let chips = self
            .chips
            .iter()
            .filter(|chip| {
                if let Some(chips_filter) = chips_filter {
                    chips_filter.contains(&chip.name())
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        records.iter_mut().for_each(|record| {
            chips.iter().for_each(|chip| {
                tracing::debug_span!("chip dependencies", chip = chip.name()).in_scope(|| {
                    let mut output = A::Record::default();
                    chip.generate_dependencies(record, &mut output);
                    record.append(&mut output);
                });
            });
            tracing::debug_span!("register nonces").in_scope(|| record.register_nonces(opts));
        });
    }

    /// Returns the config of the machine.
    pub const fn config(&self) -> &SC {
        &self.config
    }

    /// Verify that a proof is complete and valid given a verifying key and a claimed digest.
    #[instrument("verify", level = "info", skip_all)]
    #[allow(clippy::match_bool)]
    pub fn verify(
        &self,
        vk: &StarkVerifyingKey<SC>,
        proof: &MachineProof<SC>,
        challenger: &mut SC::Challenger,
    ) -> Result<(), MachineVerificationError<SC>>
    where
        SC::Challenger: Clone,
        A: for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    {
        let contains_global_bus = self.contains_global_bus();

        // Observe the preprocessed commitment.
        vk.observe_into(challenger);
        tracing::debug_span!("observe challenges for all shards").in_scope(|| {
            proof.shard_proofs.iter().for_each(|shard_proof| {
                if contains_global_bus {
                    challenger.observe(shard_proof.commitment.global_main_commit.clone());
                }
                challenger.observe_slice(&shard_proof.public_values[0..self.num_pv_elts()]);
            });
        });

        // Verify the shard proofs.
        if proof.shard_proofs.is_empty() {
            return Err(MachineVerificationError::EmptyProof);
        }

        // Obtain the challenges used for the global permutation argument.
        let global_permutation_challenges: [SC::Challenge; 2] = array::from_fn(|_| {
            if contains_global_bus {
                challenger.sample_ext_element()
            } else {
                SC::Challenge::zero()
            }
        });

        tracing::debug_span!("verify shard proofs").in_scope(|| {
            for (i, shard_proof) in proof.shard_proofs.iter().enumerate() {
                tracing::debug_span!("verifying shard", shard = i).in_scope(|| {
                    let chips =
                        self.shard_chips_ordered(&shard_proof.chip_ordering).collect::<Vec<_>>();
                    Verifier::verify_shard(
                        &self.config,
                        vk,
                        &chips,
                        &mut challenger.clone(),
                        shard_proof,
                        &global_permutation_challenges,
                    )
                    .map_err(MachineVerificationError::InvalidShardProof)
                })?;
            }

            Ok(())
        })?;

        // Verify the cumulative sum is 0.
        tracing::debug_span!("verify global cumulative sum is 0").in_scope(|| {
            let sum = proof
                .shard_proofs
                .iter()
                .map(|proof| proof.cumulative_sum(InteractionScope::Global))
                .sum::<SC::Challenge>();

            if !sum.is_zero() {
                return Err(MachineVerificationError::NonZeroCumulativeSum(
                    InteractionScope::Global,
                    0,
                ));
            }

            Ok(())
        })
    }

    /// Debugs the constraints of the given records.
    #[instrument("debug constraints", level = "debug", skip_all)]
    pub fn debug_constraints(
        &self,
        pk: &StarkProvingKey<SC>,
        records: Vec<A::Record>,
        challenger: &mut SC::Challenger,
    ) where
        SC::Val: PrimeField32,
        A: for<'a> Air<DebugConstraintBuilder<'a, Val<SC>, SC::Challenge>>,
    {
        tracing::debug!("checking constraints for each shard");

        // Obtain the challenges used for the global permutation argument.
        let mut permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        // Obtain the challenges used for the local permutation argument.
        for _ in 0..2 {
            permutation_challenges.push(challenger.sample_ext_element());
        }

        let mut global_cumulative_sum = SC::Challenge::zero();
        for shard in records.iter() {
            // Filter the chips based on what is used.
            let chips = self.shard_chips(shard).collect::<Vec<_>>();

            // Generate the main trace for each chip.
            let pre_traces = chips
                .iter()
                .map(|chip| pk.chip_ordering.get(&chip.name()).map(|index| &pk.traces[*index]))
                .collect::<Vec<_>>();
            let mut traces = chips
                .par_iter()
                .map(|chip| chip.generate_trace(shard, &mut A::Record::default()))
                .zip(pre_traces)
                .collect::<Vec<_>>();

            // Generate the permutation traces.
            let mut permutation_traces = Vec::with_capacity(chips.len());
            let mut cumulative_sums = Vec::with_capacity(chips.len());
            tracing::debug_span!("generate permutation traces").in_scope(|| {
                chips
                    .par_iter()
                    .zip(traces.par_iter_mut())
                    .map(|(chip, (main_trace, pre_trace))| {
                        let (trace, global_sum, local_sum) = chip.generate_permutation_trace(
                            *pre_trace,
                            main_trace,
                            &permutation_challenges,
                        );
                        (trace, [global_sum, local_sum])
                    })
                    .unzip_into_vecs(&mut permutation_traces, &mut cumulative_sums);
            });

            global_cumulative_sum +=
                cumulative_sums.iter().map(|sum| sum[0]).sum::<SC::Challenge>();

            let local_cumulative_sum =
                cumulative_sums.iter().map(|sum| sum[1]).sum::<SC::Challenge>();
            if !local_cumulative_sum.is_zero() {
                tracing::warn!("Local cumulative sum is not zero");
                tracing::debug_span!("debug local interactions").in_scope(|| {
                    debug_interactions_with_all_chips::<SC, A>(
                        self,
                        pk,
                        &[shard.clone()],
                        InteractionKind::all_kinds(),
                        InteractionScope::Local,
                    )
                });
                panic!("Local cumulative sum is not zero");
            }

            // Compute some statistics.
            for i in 0..chips.len() {
                let trace_width = traces[i].0.width();
                let pre_width = traces[i].1.map_or(0, p3_matrix::Matrix::width);
                let permutation_width = permutation_traces[i].width()
                    * <SC::Challenge as AbstractExtensionField<SC::Val>>::D;
                let total_width = trace_width + pre_width + permutation_width;
                tracing::debug!(
                    "{:<11} | Main Cols = {:<5} | Pre Cols = {:<5} | Perm Cols = {:<5} | Rows = {:<10} | Cells = {:<10}",
                    chips[i].name(),
                    trace_width,
                    pre_width,
                    permutation_width,
                    traces[i].0.height(),
                    total_width * traces[i].0.height(),
                );
            }

            if env::var("SKIP_CONSTRAINTS").is_err() {
                tracing::info_span!("debug constraints").in_scope(|| {
                    for i in 0..chips.len() {
                        let preprocessed_trace =
                            pk.chip_ordering.get(&chips[i].name()).map(|index| &pk.traces[*index]);
                        debug_constraints::<SC, A>(
                            chips[i],
                            preprocessed_trace,
                            &traces[i].0,
                            &permutation_traces[i],
                            &permutation_challenges,
                            &shard.public_values(),
                            &cumulative_sums[i],
                        );
                    }
                });
            }
        }

        tracing::info!("Constraints verified successfully");

        // If the global cumulative sum is not zero, debug the interactions.
        if !global_cumulative_sum.is_zero() {
            tracing::warn!("Global cumulative sum is not zero");
            tracing::debug_span!("debug global interactions").in_scope(|| {
                debug_interactions_with_all_chips::<SC, A>(
                    self,
                    pk,
                    &records,
                    InteractionKind::all_kinds(),
                    InteractionScope::Global,
                )
            });
            panic!("Global cumulative sum is not zero");
        }
    }
}

/// Errors that can occur during machine verification.
pub enum MachineVerificationError<SC: StarkGenericConfig> {
    /// An error occurred during the verification of a shard proof.
    InvalidShardProof(VerificationError<SC>),
    /// An error occurred during the verification of a global proof.
    InvalidGlobalProof(VerificationError<SC>),
    /// The cumulative sum is non-zero.
    NonZeroCumulativeSum(InteractionScope, usize),
    /// The public values digest is invalid.
    InvalidPublicValuesDigest,
    /// The debug interactions failed.
    DebugInteractionsFailed,
    /// The proof is empty.
    EmptyProof,
    /// The public values are invalid.
    InvalidPublicValues(&'static str),
    /// The number of shards is too large.
    TooManyShards,
    /// The chip occurrence is invalid.
    InvalidChipOccurrence(String),
    /// The CPU is missing in the first shard.
    MissingCpuInFirstShard,
    /// The CPU log degree is too large.
    CpuLogDegreeTooLarge(usize),
    /// The verification key is not allowed.
    InvalidVerificationKey,
}

impl<SC: StarkGenericConfig> Debug for MachineVerificationError<SC> {
    #[allow(clippy::uninlined_format_args)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MachineVerificationError::InvalidShardProof(e) => {
                write!(f, "Invalid shard proof: {:?}", e)
            }
            MachineVerificationError::InvalidGlobalProof(e) => {
                write!(f, "Invalid global proof: {:?}", e)
            }
            MachineVerificationError::NonZeroCumulativeSum(scope, shard) => {
                write!(f, "Non-zero cumulative sum.  Scope: {}, Shard: {}", scope, shard)
            }
            MachineVerificationError::InvalidPublicValuesDigest => {
                write!(f, "Invalid public values digest")
            }
            MachineVerificationError::EmptyProof => {
                write!(f, "Empty proof")
            }
            MachineVerificationError::DebugInteractionsFailed => {
                write!(f, "Debug interactions failed")
            }
            MachineVerificationError::InvalidPublicValues(s) => {
                write!(f, "Invalid public values: {}", s)
            }
            MachineVerificationError::TooManyShards => {
                write!(f, "Too many shards")
            }
            MachineVerificationError::InvalidChipOccurrence(s) => {
                write!(f, "Invalid chip occurrence: {}", s)
            }
            MachineVerificationError::MissingCpuInFirstShard => {
                write!(f, "Missing CPU in first shard")
            }
            MachineVerificationError::CpuLogDegreeTooLarge(log_degree) => {
                write!(f, "CPU log degree too large: {}", log_degree)
            }
            MachineVerificationError::InvalidVerificationKey => {
                write!(f, "Invalid verification key")
            }
        }
    }
}

impl<SC: StarkGenericConfig> std::fmt::Display for MachineVerificationError<SC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl<SC: StarkGenericConfig> std::error::Error for MachineVerificationError<SC> {}
