use derive_where::derive_where;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use slop_air::Air;
use slop_algebra::{AbstractField, Field};
use slop_alloc::{Backend, CanCopyFromRef, CpuBackend};
use slop_challenger::{CanObserve, FieldChallenger, IopCtx, VariableLengthChallenger};
use slop_commit::Rounds;
use slop_jagged::{DefaultJaggedProver, JaggedProver, JaggedProverData};
use slop_matrix::dense::RowMajorMatrixView;
use slop_multilinear::{
    Evaluations, MleEval, MultilinearPcsProver, MultilinearPcsVerifier, Point, VirtualGeq,
};
use slop_sumcheck::{reduce_sumcheck_to_evaluation, PartialSumcheckProof};
use slop_tensor::Tensor;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    future::Future,
    iter::once,
    sync::Arc,
};
use thousands::Separable;
use tracing::Instrument;

use crate::{
    air::{MachineAir, MachineProgram},
    prover::{
        DefaultTraceGenerator, Program, ProverPermit, ProverSemaphore, Record, ZeroCheckPoly,
        ZerocheckCpuProverData,
    },
    septic_digest::SepticDigest,
    AirOpenedValues, Chip, ChipEvaluation, ChipOpenedValues, ChipStatistics,
    ConstraintSumcheckFolder, GkrProverImpl, LogUpEvaluations, Machine, MachineVerifyingKey,
    ShardContext, ShardOpenedValues, ShardProof,
};

use super::{TraceGenerator, Traces};

/// The PCS proof type associated to a shard context.
pub type PcsProof<GC, SC> = <<SC as ShardContext<GC>>::Config as MultilinearPcsVerifier<GC>>::Proof;

/// A prover for an AIR.
#[allow(clippy::type_complexity)]
pub trait AirProver<GC: IopCtx, SC: ShardContext<GC>>: 'static + Send + Sync + Sized {
    /// The proving key type.
    type PreprocessedData: 'static + Send + Sync;

    /// Get the machine.
    fn machine(&self) -> &Machine<GC::F, SC::Air>;

    /// Setup from a verifying key.
    fn setup_from_vk(
        &self,
        program: Arc<Program<GC, SC>>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> impl Future<Output = (PreprocessedData<ProvingKey<GC, SC, Self>>, MachineVerifyingKey<GC>)> + Send;

    /// Setup and prove a shard.
    fn setup_and_prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        record: Record<GC, SC>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> impl Future<
        Output = (MachineVerifyingKey<GC>, ShardProof<GC, PcsProof<GC, SC>>, ProverPermit),
    > + Send;

    /// Prove a shard with a given proving key.
    fn prove_shard_with_pk(
        &self,
        pk: Arc<ProvingKey<GC, SC, Self>>,
        record: Record<GC, SC>,
        prover_permits: ProverSemaphore,
    ) -> impl Future<Output = (ShardProof<GC, PcsProof<GC, SC>>, ProverPermit)> + Send;
    /// Get all the chips in the machine.
    fn all_chips(&self) -> &[Chip<GC::F, SC::Air>] {
        self.machine().chips()
    }

    /// Setup from a program.
    ///
    /// The setup phase produces a pair '(pk, vk)' of proving and verifying keys. The proving key
    /// consists of information used by the prover that only depends on the program itself and not
    /// a specific execution.
    fn setup(
        &self,
        program: Arc<Program<GC, SC>>,
        setup_permits: ProverSemaphore,
    ) -> impl Future<Output = (PreprocessedData<ProvingKey<GC, SC, Self>>, MachineVerifyingKey<GC>)> + Send
    {
        self.setup_from_vk(program, None, setup_permits)
    }

    /// A function which deduces preprocessed table heights from the proving key.
    fn preprocessed_table_heights(
        pk: Arc<ProvingKey<GC, SC, Self>>,
    ) -> impl Future<Output = BTreeMap<String, usize>> + Send;
}

/// A proving key for an AIR prover.
pub struct ProvingKey<GC: IopCtx, SC: ShardContext<GC>, Prover: AirProver<GC, SC>> {
    /// The verifying key.
    pub vk: MachineVerifyingKey<GC>,
    /// The preprocessed data.
    pub preprocessed_data: Prover::PreprocessedData,
}

/// A collection of main traces with a permit.
#[allow(clippy::type_complexity)]
pub struct ShardData<GC: IopCtx, SC: ShardContext<GC>, C: DefaultJaggedProver<GC, SC::Config>> {
    /// The proving key.
    pub pk: Arc<ProvingKey<GC, SC, ShardProver<GC, SC, C>>>,
    /// Main trace data
    pub main_trace_data: MainTraceData<GC::F, SC::Air, CpuBackend>,
}

/// The main traces for a program, with a permit.
pub struct MainTraceData<F: Field, A: MachineAir<F>, B: Backend> {
    /// The traces.
    pub traces: Traces<F, B>,
    /// The public values.
    pub public_values: Vec<F>,
    /// The shape cluster corresponding to the traces.
    pub shard_chips: BTreeSet<Chip<F, A>>,
    /// A permit for a prover resource.
    pub permit: ProverPermit,
}

/// The total trace data for a shard.
pub struct TraceData<F: Field, A: MachineAir<F>, B: Backend> {
    /// The preprocessed traces.
    pub preprocessed_traces: Traces<F, B>,
    /// The main traces.
    pub main_trace_data: MainTraceData<F, A, B>,
}

/// The preprocessed traces for a program.
pub struct PreprocessedTraceData<F: Field, B: Backend> {
    /// The preprocessed traces.
    pub preprocessed_traces: Traces<F, B>,
    /// A permit for a prover resource.
    pub permit: ProverPermit,
}

/// The preprocessed data for a program.
pub struct PreprocessedData<T> {
    /// The proving key.
    pub pk: Arc<T>,
    /// A permit for a prover resource.
    pub permit: ProverPermit,
}

impl<T> PreprocessedData<T> {
    /// Unsafely take the inner proving key.
    ///
    /// # Safety
    /// This is unsafe because the permit is dropped.
    #[must_use]
    #[inline]
    pub unsafe fn into_inner(self) -> Arc<T> {
        self.pk
    }
}

/// Inner struct containing the actual prover data.
pub struct ShardProverInner<
    GC: IopCtx,
    SC: ShardContext<GC>,
    C: MultilinearPcsProver<GC, PcsProof<GC, SC>>,
> {
    /// The trace generator.
    pub trace_generator: DefaultTraceGenerator<GC::F, SC::Air, CpuBackend>,
    /// The logup GKR prover.
    pub logup_gkr_prover: GkrProverImpl<GC, SC>,
    /// A prover for the PCS.
    pub pcs_prover: JaggedProver<GC, PcsProof<GC, SC>, C>,
}

/// A prover for the hypercube STARK, given a configuration.
/// Wrapped in Arc for cheap cloning to enable `spawn_blocking`.
pub struct ShardProver<
    GC: IopCtx,
    SC: ShardContext<GC>,
    C: MultilinearPcsProver<GC, PcsProof<GC, SC>>,
> {
    inner: Arc<ShardProverInner<GC, SC, C>>,
}

// Implement Clone manually to avoid requiring Clone bounds on generic parameters.
// Arc::clone doesn't need the inner type to be Clone.
impl<GC: IopCtx, SC: ShardContext<GC>, C: MultilinearPcsProver<GC, PcsProof<GC, SC>>> Clone
    for ShardProver<GC, SC, C>
{
    fn clone(&self) -> Self {
        Self { inner: Arc::clone(&self.inner) }
    }
}

impl<GC: IopCtx, SC: ShardContext<GC>, C: MultilinearPcsProver<GC, PcsProof<GC, SC>>>
    ShardProver<GC, SC, C>
{
    /// Create a new `ShardProver` from its components.
    pub fn from_components(
        trace_generator: DefaultTraceGenerator<GC::F, SC::Air, CpuBackend>,
        logup_gkr_prover: GkrProverImpl<GC, SC>,
        pcs_prover: JaggedProver<GC, PcsProof<GC, SC>, C>,
    ) -> Self {
        Self { inner: Arc::new(ShardProverInner { trace_generator, logup_gkr_prover, pcs_prover }) }
    }

    /// Access the trace generator.
    #[must_use]
    pub fn trace_generator(&self) -> &DefaultTraceGenerator<GC::F, SC::Air, CpuBackend> {
        &self.inner.trace_generator
    }

    /// Access the logup GKR prover.
    #[must_use]
    pub fn logup_gkr_prover(&self) -> &GkrProverImpl<GC, SC> {
        &self.inner.logup_gkr_prover
    }

    /// Access the PCS prover.
    #[must_use]
    pub fn pcs_prover(&self) -> &JaggedProver<GC, PcsProof<GC, SC>, C> {
        &self.inner.pcs_prover
    }
}

impl<GC: IopCtx, SC: ShardContext<GC>, C: DefaultJaggedProver<GC, SC::Config>> AirProver<GC, SC>
    for ShardProver<GC, SC, C>
{
    type PreprocessedData = ShardProverData<GC, SC, C>;

    fn machine(&self) -> &Machine<GC::F, SC::Air> {
        self.inner.trace_generator.machine()
    }

    /// Setup a shard, using a verifying key if provided.
    async fn setup_from_vk(
        &self,
        program: Arc<Program<GC, SC>>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> (PreprocessedData<ProvingKey<GC, SC, Self>>, MachineVerifyingKey<GC>) {
        if let Some(vk) = vk {
            let initial_global_cumulative_sum = vk.initial_global_cumulative_sum;
            self.setup_with_initial_global_cumulative_sum(
                program,
                initial_global_cumulative_sum,
                prover_permits,
            )
            .await
        } else {
            let program_sent = program.clone();
            let initial_global_cumulative_sum =
                tokio::task::spawn_blocking(move || program_sent.initial_global_cumulative_sum())
                    .await
                    .unwrap();
            self.setup_with_initial_global_cumulative_sum(
                program,
                initial_global_cumulative_sum,
                prover_permits,
            )
            .await
        }
    }

    /// Setup and prove a shard.
    async fn setup_and_prove_shard(
        &self,
        program: Arc<Program<GC, SC>>,
        record: Record<GC, SC>,
        vk: Option<MachineVerifyingKey<GC>>,
        prover_permits: ProverSemaphore,
    ) -> (MachineVerifyingKey<GC>, ShardProof<GC, PcsProof<GC, SC>>, ProverPermit) {
        // Get the initial global cumulative sum and pc start.
        let pc_start = program.pc_start();
        let enable_untrusted_programs = program.enable_untrusted_programs();
        let initial_global_cumulative_sum = if let Some(vk) = vk {
            vk.initial_global_cumulative_sum
        } else {
            let program = program.clone();
            tokio::task::spawn_blocking(move || program.initial_global_cumulative_sum())
                .instrument(tracing::debug_span!("initial_global_cumulative_sum"))
                .await
                .unwrap()
        };

        // Generate trace.
        let trace_data = self
            .inner
            .trace_generator
            .generate_traces(program, record, self.max_log_row_count(), prover_permits)
            .instrument(tracing::debug_span!("generate full traces"))
            .await;

        let TraceData { preprocessed_traces, main_trace_data } = trace_data;

        let (pk, vk) = {
            let _span = tracing::debug_span!("setup_from_preprocessed_data_and_traces").entered();
            self.setup_from_preprocessed_data_and_traces(
                pc_start,
                initial_global_cumulative_sum,
                preprocessed_traces,
                enable_untrusted_programs,
            )
        };

        let pk = ProvingKey { vk: vk.clone(), preprocessed_data: pk };

        let pk = Arc::new(pk);

        // Create a challenger.
        let mut challenger = GC::default_challenger();
        // Observe the preprocessed information.
        vk.observe_into(&mut challenger);

        let shard_data = ShardData { pk, main_trace_data };

        let prover = self.clone();
        let (shard_proof, permit) = tokio::task::spawn_blocking(move || {
            let _span = tracing::debug_span!("prove shard with data").entered();
            prover.prove_shard_with_data(shard_data, challenger)
        })
        .await
        .unwrap();

        (vk, shard_proof, permit)
    }

    /// Prove a shard with a given proving key.
    async fn prove_shard_with_pk(
        &self,
        pk: Arc<ProvingKey<GC, SC, Self>>,
        record: Record<GC, SC>,
        prover_permits: ProverSemaphore,
    ) -> (ShardProof<GC, PcsProof<GC, SC>>, ProverPermit) {
        let mut challenger = GC::default_challenger();
        pk.vk.observe_into(&mut challenger);
        // Generate the traces.
        let main_trace_data = self
            .inner
            .trace_generator
            .generate_main_traces(record, self.max_log_row_count(), prover_permits)
            .instrument(tracing::debug_span!("generate main traces"))
            .await;

        let shard_data = ShardData { pk, main_trace_data };

        let prover = self.clone();
        tokio::task::spawn_blocking(move || {
            let _span = tracing::debug_span!("prove shard with data").entered();
            prover.prove_shard_with_data(shard_data, challenger)
        })
        .await
        .unwrap()
    }

    async fn preprocessed_table_heights(
        pk: Arc<super::ProvingKey<GC, SC, Self>>,
    ) -> BTreeMap<String, usize> {
        std::future::ready(
            pk.preprocessed_data
                .preprocessed_traces
                .iter()
                .map(|(name, trace)| (name.to_owned(), trace.num_real_entries()))
                .collect(),
        )
        .await
    }
}

impl<GC: IopCtx, SC: ShardContext<GC>, C: DefaultJaggedProver<GC, SC::Config>>
    ShardProver<GC, SC, C>
{
    /// Get all the chips in the machine.
    #[must_use]
    pub fn all_chips(&self) -> &[Chip<GC::F, SC::Air>] {
        self.inner.trace_generator.machine().chips()
    }

    /// Get the machine.
    #[must_use]
    pub fn machine(&self) -> &Machine<GC::F, SC::Air> {
        self.inner.trace_generator.machine()
    }

    /// Get the number of public values in the machine.
    #[must_use]
    pub fn num_pv_elts(&self) -> usize {
        self.inner.trace_generator.machine().num_pv_elts()
    }

    /// Get the maximum log row count.
    #[inline]
    #[must_use]
    pub fn max_log_row_count(&self) -> usize {
        self.inner.pcs_prover.max_log_row_count
    }

    /// Setup from preprocessed data and traces.
    pub fn setup_from_preprocessed_data_and_traces(
        &self,
        pc_start: [GC::F; 3],
        initial_global_cumulative_sum: SepticDigest<GC::F>,
        preprocessed_traces: Traces<GC::F, CpuBackend>,
        enable_untrusted_programs: GC::F,
    ) -> (ShardProverData<GC, SC, C>, MachineVerifyingKey<GC>) {
        // Commit to the preprocessed traces, if there are any.
        assert!(!preprocessed_traces.is_empty(), "preprocessed trace cannot be empty");
        let message = preprocessed_traces.values().cloned().collect::<Vec<_>>();
        let (preprocessed_commit, preprocessed_data) =
            self.inner.pcs_prover.commit_multilinears(message).unwrap();

        let vk = MachineVerifyingKey {
            pc_start,
            initial_global_cumulative_sum,
            preprocessed_commit,
            enable_untrusted_programs,
        };

        let pk = ShardProverData { preprocessed_traces, preprocessed_data };

        (pk, vk)
    }

    /// Setup from a program with a specific initial global cumulative sum.
    pub async fn setup_with_initial_global_cumulative_sum(
        &self,
        program: Arc<Program<GC, SC>>,
        initial_global_cumulative_sum: SepticDigest<GC::F>,
        setup_permits: ProverSemaphore,
    ) -> (PreprocessedData<ProvingKey<GC, SC, Self>>, MachineVerifyingKey<GC>) {
        let pc_start = program.pc_start();
        let enable_untrusted_programs = program.enable_untrusted_programs();
        let preprocessed_data = self
            .inner
            .trace_generator
            .generate_preprocessed_traces(program, self.max_log_row_count(), setup_permits)
            .await;

        let PreprocessedTraceData { preprocessed_traces, permit } = preprocessed_data;

        let (pk, vk) = self.setup_from_preprocessed_data_and_traces(
            pc_start,
            initial_global_cumulative_sum,
            preprocessed_traces,
            enable_untrusted_programs,
        );

        let pk = ProvingKey { vk: vk.clone(), preprocessed_data: pk };

        let pk = Arc::new(pk);

        (PreprocessedData { pk, permit }, vk)
    }

    fn commit_traces(
        &self,
        traces: &Traces<GC::F, CpuBackend>,
    ) -> (GC::Digest, JaggedProverData<GC, C::ProverData>) {
        let message = traces.values().cloned().collect::<Vec<_>>();
        self.inner.pcs_prover.commit_multilinears(message).unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::needless_pass_by_value)]
    fn zerocheck(
        &self,
        chips: &BTreeSet<Chip<GC::F, SC::Air>>,
        preprocessed_traces: Traces<GC::F, CpuBackend>,
        traces: Traces<GC::F, CpuBackend>,
        batching_challenge: GC::EF,
        gkr_opening_batch_randomness: GC::EF,
        logup_evaluations: &LogUpEvaluations<GC::EF>,
        public_values: Vec<GC::F>,
        challenger: &mut GC::Challenger,
    ) -> (ShardOpenedValues<GC::F, GC::EF>, PartialSumcheckProof<GC::EF>) {
        let max_num_constraints =
            itertools::max(chips.iter().map(|chip| chip.num_constraints)).unwrap();
        let powers_of_challenge =
            batching_challenge.powers().take(max_num_constraints).collect::<Vec<_>>();
        let airs =
            chips.iter().map(|chip| (chip.air.clone(), chip.num_constraints)).collect::<Vec<_>>();

        let public_values = Arc::new(public_values);

        let mut zerocheck_polys = Vec::new();
        let mut chip_sumcheck_claims = Vec::new();

        let LogUpEvaluations { point: gkr_point, chip_openings } = logup_evaluations;

        let mut chip_heights = BTreeMap::new();
        for ((air, num_constraints), chip) in airs.iter().cloned().zip_eq(chips.iter()) {
            let ChipEvaluation {
                main_trace_evaluations: main_opening,
                preprocessed_trace_evaluations: prep_opening,
            } = chip_openings.get(chip.name()).unwrap();

            let main_trace = traces.get(air.name()).unwrap().clone();
            let num_real_entries = main_trace.num_real_entries();

            let threshold_point =
                Point::from_usize(num_real_entries, self.inner.pcs_prover.max_log_row_count + 1);
            chip_heights.insert(air.name().to_string(), threshold_point);
            let name = air.name();
            let num_variables = main_trace.num_variables();
            assert_eq!(num_variables, self.inner.pcs_prover.max_log_row_count as u32);

            let preprocessed_width = air.preprocessed_width();
            let dummy_preprocessed_trace = vec![GC::F::zero(); preprocessed_width];
            let dummy_main_trace = vec![GC::F::zero(); main_trace.num_polynomials()];

            // Calculate powers of alpha for constraint evaluation:
            // 1. Generate sequence [α⁰, α¹, ..., α^(n-1)] where n = num_constraints.
            // 2. Reverse to [α^(n-1), ..., α¹, α⁰] to align with Horner's method in the verifier.
            let mut chip_powers_of_alpha = powers_of_challenge[0..num_constraints].to_vec();
            chip_powers_of_alpha.reverse();

            let mut folder = ConstraintSumcheckFolder {
                preprocessed: RowMajorMatrixView::new_row(&dummy_preprocessed_trace),
                main: RowMajorMatrixView::new_row(&dummy_main_trace),
                accumulator: GC::EF::zero(),
                public_values: &public_values,
                constraint_index: 0,
                powers_of_alpha: &chip_powers_of_alpha,
            };

            air.eval(&mut folder);
            let padded_row_adjustment = folder.accumulator;

            // TODO: This could be computed once for the maximally wide chip and stored for later
            // use, but since it's a computation that's done once per chip, we have chosen not to
            // perform this optimization for now.
            let gkr_opening_batch_randomness_powers = gkr_opening_batch_randomness
                .powers()
                .skip(1)
                .take(
                    main_opening.num_polynomials()
                        + prep_opening.as_ref().map_or(0, MleEval::num_polynomials),
                )
                .collect::<Vec<_>>();
            let gkr_powers = Arc::new(gkr_opening_batch_randomness_powers);

            let alpha_powers = Arc::new(chip_powers_of_alpha);
            let air_data = ZerocheckCpuProverData::round_prover(
                air,
                public_values.clone(),
                alpha_powers,
                gkr_powers.clone(),
            );
            let preprocessed_trace = preprocessed_traces.get(name).cloned();

            let chip_sumcheck_claim = main_opening
                .evaluations()
                .as_slice()
                .iter()
                .chain(
                    prep_opening
                        .as_ref()
                        .map_or_else(Vec::new, |mle| mle.evaluations().as_slice().to_vec())
                        .iter(),
                )
                .zip(gkr_powers.iter())
                .map(|(opening, power)| *opening * *power)
                .sum::<GC::EF>();

            let initial_geq_value =
                if main_trace.num_real_entries() > 0 { GC::EF::zero() } else { GC::EF::one() };

            let virtual_geq = VirtualGeq::new(
                main_trace.num_real_entries() as u32,
                GC::F::one(),
                GC::F::zero(),
                self.inner.pcs_prover.max_log_row_count as u32,
            );

            let zerocheck_poly = ZeroCheckPoly::new(
                air_data,
                gkr_point.clone(),
                preprocessed_trace,
                main_trace,
                GC::EF::one(),
                initial_geq_value,
                padded_row_adjustment,
                virtual_geq,
            );
            zerocheck_polys.push(zerocheck_poly);
            chip_sumcheck_claims.push(chip_sumcheck_claim);
        }

        // Same lambda for the RLC of the zerocheck polynomials.
        let lambda = challenger.sample_ext_element::<GC::EF>();

        // Compute the sumcheck proof for the zerocheck polynomials.
        let (partial_sumcheck_proof, component_poly_evals) = reduce_sumcheck_to_evaluation(
            zerocheck_polys,
            challenger,
            chip_sumcheck_claims,
            1,
            lambda,
        );

        let mut point_extended = partial_sumcheck_proof.point_and_eval.0.clone();
        point_extended.add_dimension(GC::EF::zero());

        // Compute the chip openings from the component poly evaluations.

        debug_assert_eq!(component_poly_evals.len(), airs.len());
        let len = airs.len();
        challenger.observe(GC::F::from_canonical_usize(len));
        let shard_open_values = airs
            .into_iter()
            .zip_eq(component_poly_evals)
            .map(|((air, _), evals)| {
                let (preprocessed_evals, main_evals) = evals.split_at(air.preprocessed_width());

                // Observe the openings
                challenger.observe_variable_length_extension_slice(preprocessed_evals);
                challenger.observe_variable_length_extension_slice(main_evals);

                let preprocessed = AirOpenedValues { local: preprocessed_evals.to_vec() };

                let main = AirOpenedValues { local: main_evals.to_vec() };

                (
                    air.name().to_string(),
                    ChipOpenedValues {
                        preprocessed,
                        main,
                        degree: chip_heights[air.name()].clone(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        let shard_open_values = ShardOpenedValues { chips: shard_open_values };

        (shard_open_values, partial_sumcheck_proof)
    }

    /// Generate a proof for a given execution record.
    #[allow(clippy::type_complexity)]
    pub fn prove_shard_with_data(
        &self,
        data: ShardData<GC, SC, C>,
        mut challenger: GC::Challenger,
    ) -> (ShardProof<GC, PcsProof<GC, SC>>, ProverPermit) {
        let ShardData { pk, main_trace_data } = data;
        let MainTraceData { traces, public_values, shard_chips, permit } = main_trace_data;

        // Log the shard data.
        let mut total_number_of_cells = 0;
        tracing::debug!("Proving shard");
        for (chip, trace) in shard_chips.iter().zip_eq(traces.values()) {
            let height = trace.num_real_entries();
            let stats = ChipStatistics::new(chip, height);
            tracing::debug!("{}", stats);
            total_number_of_cells += stats.total_number_of_cells();
        }

        tracing::debug!(
            "Total number of cells: {}, number of variables: {}",
            total_number_of_cells.separate_with_underscores(),
            total_number_of_cells.next_power_of_two().ilog2(),
        );

        // Observe the public values.
        challenger.observe_constant_length_slice(&public_values);

        // Commit to the traces.
        let (main_commit, main_data) = {
            let _span = tracing::debug_span!("commit traces").entered();
            self.commit_traces(&traces)
        };
        // Observe the commitments.
        challenger.observe(main_commit);
        // Observe the number of chips.
        challenger.observe(GC::F::from_canonical_usize(shard_chips.len()));

        for chips in shard_chips.iter() {
            let num_real_entries = traces.get(chips.air.name()).unwrap().num_real_entries();
            challenger.observe(GC::F::from_canonical_usize(num_real_entries));
            challenger.observe(GC::F::from_canonical_usize(chips.air.name().len()));
            for byte in chips.air.name().as_bytes() {
                challenger.observe(GC::F::from_canonical_u8(*byte));
            }
        }

        let logup_gkr_proof = {
            let _span = tracing::debug_span!("logup gkr proof").entered();
            self.inner.logup_gkr_prover.prove_logup_gkr(
                &shard_chips,
                &pk.preprocessed_data.preprocessed_traces,
                &traces,
                public_values.clone(),
                &mut challenger,
            )
        };
        // Get the challenge for batching constraints.
        let batching_challenge = challenger.sample_ext_element::<GC::EF>();
        // Get the challenge for batching the evaluations from the GKR proof.
        let gkr_opening_batch_challenge = challenger.sample_ext_element::<GC::EF>();

        #[cfg(sp1_debug_constraints)]
        {
            crate::debug::debug_constraints_all_chips::<GC, _>(
                &shard_chips.iter().cloned().collect::<Vec<_>>(),
                &pk.preprocessed_data.preprocessed_traces,
                &traces,
                &public_values,
            );
        }

        // Generate the zerocheck proof.
        let (shard_open_values, zerocheck_partial_sumcheck_proof) = {
            let _span = tracing::debug_span!("zerocheck").entered();
            self.zerocheck(
                &shard_chips,
                pk.preprocessed_data.preprocessed_traces.clone(),
                traces,
                batching_challenge,
                gkr_opening_batch_challenge,
                &logup_gkr_proof.logup_evaluations,
                public_values.clone(),
                &mut challenger,
            )
        };

        // Get the evaluation point for the trace polynomials.
        let evaluation_point = zerocheck_partial_sumcheck_proof.point_and_eval.0.clone();
        let mut preprocessed_evaluation_claims: Option<Evaluations<GC::EF, CpuBackend>> = None;
        let mut main_evaluation_claims = Evaluations::new(vec![]);

        let alloc = self.inner.trace_generator.allocator();

        for (_, open_values) in shard_open_values.chips.iter() {
            let prep_local = &open_values.preprocessed.local;
            let main_local = &open_values.main.local;
            if !prep_local.is_empty() {
                let preprocessed_evals = alloc.copy_to(&MleEval::from(prep_local.clone())).unwrap();
                if let Some(preprocessed_claims) = preprocessed_evaluation_claims.as_mut() {
                    preprocessed_claims.push(preprocessed_evals);
                } else {
                    let evals = Evaluations::new(vec![preprocessed_evals]);
                    preprocessed_evaluation_claims = Some(evals);
                }
            }
            let main_evals = alloc.copy_to(&MleEval::from(main_local.clone())).unwrap();
            main_evaluation_claims.push(main_evals);
        }

        let round_evaluation_claims = preprocessed_evaluation_claims
            .into_iter()
            .chain(once(main_evaluation_claims))
            .collect::<Rounds<_>>();

        let round_prover_data = once(pk.preprocessed_data.preprocessed_data.clone())
            .chain(once(main_data))
            .collect::<Rounds<_>>();

        // Generate the evaluation proof.
        let evaluation_proof = {
            let _span = tracing::debug_span!("prove evaluation claims").entered();
            self.inner
                .pcs_prover
                .prove_trusted_evaluations(
                    evaluation_point,
                    round_evaluation_claims,
                    round_prover_data,
                    &mut challenger,
                )
                .unwrap()
        };

        let proof = ShardProof {
            main_commitment: main_commit,
            opened_values: shard_open_values,
            logup_gkr_proof,
            evaluation_proof,
            zerocheck_proof: zerocheck_partial_sumcheck_proof,
            public_values,
        };

        (proof, permit)
    }
}

/// The shape of the core proof. This and prover setup parameters should entirely determine the
/// verifier circuit.
#[derive_where(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoreProofShape<F: Field, A: MachineAir<F>> {
    /// The chips included in the record.
    pub shard_chips: BTreeSet<Chip<F, A>>,

    /// The multiple of `log_stacking_height` that the preprocessed area adds up to.
    pub preprocessed_multiple: usize,

    /// The multiple of `log_stacking_height` that the main area adds up to.
    pub main_multiple: usize,

    /// The number of columns added to the preprocessed commit to round to the nearest multiple of
    /// `stacking_height`.
    pub preprocessed_padding_cols: usize,

    /// The number of columns added to the main commit to round to the nearest multiple of
    /// `stacking_height`.
    pub main_padding_cols: usize,
}

impl<F, A> Debug for CoreProofShape<F, A>
where
    F: Field + Debug,
    A: MachineAir<F> + Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofShape")
            .field(
                "shard_chips",
                &self.shard_chips.iter().map(MachineAir::name).collect::<BTreeSet<_>>(),
            )
            .field("preprocessed_multiple", &self.preprocessed_multiple)
            .field("main_multiple", &self.main_multiple)
            .field("preprocessed_padding_cols", &self.preprocessed_padding_cols)
            .field("main_padding_cols", &self.main_padding_cols)
            .finish()
    }
}

/// A proving key for a STARK.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Tensor<GC::F, CpuBackend>: Serialize, JaggedProverData<GC, C::ProverData>: Serialize, GC::F: Serialize,"
))]
#[serde(bound(
    deserialize = "Tensor<GC::F, CpuBackend>: Deserialize<'de>, JaggedProverData<GC, C::ProverData>: Deserialize<'de>, GC::F: Deserialize<'de>, "
))]
pub struct ShardProverData<
    GC: IopCtx,
    SC: ShardContext<GC>,
    C: MultilinearPcsProver<GC, PcsProof<GC, SC>>,
> {
    /// The preprocessed traces.
    pub preprocessed_traces: Traces<GC::F, CpuBackend>,
    /// The pcs data for the preprocessed traces.
    pub preprocessed_data: JaggedProverData<GC, C::ProverData>,
}
