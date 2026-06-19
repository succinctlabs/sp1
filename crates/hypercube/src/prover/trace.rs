use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use slop_air::BaseAir;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tracing::Instrument;

use slop_algebra::Field;
use slop_alloc::{Backend, CanCopyFrom, CpuBackend, GLOBAL_CPU_BACKEND};
use slop_multilinear::{Mle, PaddedMle};
use slop_tensor::Tensor;
use tokio::sync::oneshot;

use crate::{air::MachineAir, Chip, Machine, MachineRecord};

use super::{MainTraceData, PreprocessedTraceData, ProverPermit, ProverSemaphore, TraceData};

/// A collection of traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Tensor<F, B>: Serialize, F: Serialize, B: Serialize, "))]
#[serde(bound(
    deserialize = "Tensor<F, B>: Deserialize<'de>, F: Deserialize<'de>, B: Deserialize<'de>, "
))]
pub struct Traces<F, B: Backend> {
    /// The traces for each chip.
    pub named_traces: BTreeMap<String, PaddedMle<F, B>>,
}

impl<F, B: Backend> IntoIterator for Traces<F, B> {
    type Item = (String, PaddedMle<F, B>);
    type IntoIter = <BTreeMap<String, PaddedMle<F, B>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.named_traces.into_iter()
    }
}

impl<F, B: Backend> Deref for Traces<F, B> {
    type Target = BTreeMap<String, PaddedMle<F, B>>;

    fn deref(&self) -> &Self::Target {
        &self.named_traces
    }
}

impl<F, B: Backend> DerefMut for Traces<F, B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.named_traces
    }
}

impl<F, B: Backend> Default for Traces<F, B> {
    fn default() -> Self {
        Self { named_traces: BTreeMap::new() }
    }
}

/// A trace generator for a given machine.
///
/// The trace generator is responsible for producing the preprocessed traces from a program and the
/// traces from an execution record.
pub trait TraceGenerator<F: Field, A: MachineAir<F>, B: Backend>: 'static + Send + Sync {
    /// Get a handle for the machine.
    fn machine(&self) -> &Machine<F, A>;

    /// Get the allocator for the traces.
    fn allocator(&self) -> &B;

    /// Generate the preprocessed traces for the given program.
    fn generate_preprocessed_traces(
        &self,
        program: Arc<A::Program>,
        max_log_row_count: usize,
        setup_permits: ProverSemaphore,
    ) -> impl Future<Output = PreprocessedTraceData<F, B>> + Send;

    /// Generate the main traces for the given execution record.
    fn generate_main_traces(
        &self,
        record: A::Record,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> impl Future<Output = MainTraceData<F, A, B>> + Send;

    /// Generate all traces for the given program and execution record.
    fn generate_traces(
        &self,
        program: Arc<A::Program>,
        record: A::Record,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> impl Future<Output = TraceData<F, A, B>> + Send;
}

/// A trace generator that used the default methods on chips for generating traces.
pub struct DefaultTraceGenerator<F: Field, A, B = CpuBackend> {
    machine: Machine<F, A>,
    trace_allocator: B,
}

impl<F: Field, A: MachineAir<F>, B: Backend> DefaultTraceGenerator<F, A, B> {
    /// Create a new trace generator.
    #[must_use]
    pub fn new_in(machine: Machine<F, A>, trace_allocator: B) -> Self {
        Self { machine, trace_allocator }
    }
}

impl<F: Field, A: MachineAir<F>> DefaultTraceGenerator<F, A, CpuBackend> {
    /// Create a new trace generator on the CPU.
    #[must_use]
    pub fn new(machine: Machine<F, A>) -> Self {
        Self { machine, trace_allocator: GLOBAL_CPU_BACKEND }
    }

    /// Pad and copy the generated `(global, main)` traces to the target backend.
    #[allow(clippy::type_complexity)]
    fn pad_and_copy_traces(
        &self,
        shard_chips: &BTreeSet<Chip<F, A>>,
        chips_and_traces: BTreeMap<Chip<F, A>, (Option<Mle<F>>, Option<Mle<F>>)>,
        max_log_row_count: usize,
    ) -> (Traces<F, CpuBackend>, Traces<F, CpuBackend>) {
        // Make the padded traces for cluster chips without generated traces.
        let mut traces = shard_chips
            .iter()
            .filter(|chip| chip.width() > 0 && !chips_and_traces.contains_key(chip))
            .map(|chip| {
                (chip.name().to_string(), PaddedMle::zeros(chip.width(), max_log_row_count as u32))
            })
            .collect::<BTreeMap<_, _>>();
        let mut global_traces = shard_chips
            .iter()
            .filter(|chip| chip.global_width() > 0 && !chips_and_traces.contains_key(chip))
            .map(|chip| {
                (
                    chip.name().to_string(),
                    PaddedMle::zeros(chip.global_width(), max_log_row_count as u32),
                )
            })
            .collect::<BTreeMap<_, _>>();

        // Copy the real traces to the target backend.
        for (chip, (global, main)) in chips_and_traces {
            if let Some(main) = main {
                let main = self.trace_allocator.copy_into(main).unwrap();
                traces.insert(
                    chip.name().to_string(),
                    PaddedMle::padded_with_zeros(Arc::new(main), max_log_row_count as u32),
                );
            }
            if let Some(global) = global {
                let global = self.trace_allocator.copy_into(global).unwrap();
                global_traces.insert(
                    chip.name().to_string(),
                    PaddedMle::padded_with_zeros(Arc::new(global), max_log_row_count as u32),
                );
            }
        }

        (Traces { named_traces: traces }, Traces { named_traces: global_traces })
    }

    /// Generate the global traces for the record, skipping the main section.
    pub(crate) async fn generate_global_traces(
        &self,
        record: A::Record,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> (Traces<F, CpuBackend>, ProverPermit) {
        let airs = self.machine.chips().to_vec();
        let (tx, rx) = oneshot::channel();
        // Spawn a rayon task to generate the global traces on the CPU.
        slop_futures::rayon::spawn(move || {
            let chips_and_traces = airs
                .into_par_iter()
                .filter(|air| air.included(&record))
                .map(|air| {
                    // Only the global section is generated; the main section is left as `None`.
                    let global = air
                        .generate_global_trace(&record, &mut A::Record::default())
                        .map(Mle::from);
                    (air, (global, None::<Mle<F>>))
                })
                .collect::<BTreeMap<_, _>>();

            tx.send(chips_and_traces).ok().unwrap();
            // Emphasize that we are dropping the record after sending the traces.
            drop(record);
        });
        // Wait for the traces to be generated.
        let chips_and_traces = rx.await.unwrap();

        let chip_set = chips_and_traces.keys().cloned().collect::<BTreeSet<_>>();
        let shard_chips = self
            .machine
            .smallest_cluster(&chip_set)
            .unwrap_or_else(|| {
                panic!(
                    "no chip cluster contains the included chip set: {:?}",
                    chip_set.iter().map(MachineAir::name).collect::<Vec<_>>()
                )
            })
            .clone();

        // Wait for a prover to be available.
        let permit = prover_permits
            .acquire()
            .instrument(tracing::debug_span!("acquire prover"))
            .await
            .unwrap();

        // Pad and copy only the global section; the main output is discarded.
        let (_, global_traces) =
            self.pad_and_copy_traces(&shard_chips, chips_and_traces, max_log_row_count);

        (global_traces, permit)
    }
}

impl<F: Field, A: MachineAir<F>> TraceGenerator<F, A, CpuBackend>
    for DefaultTraceGenerator<F, A, CpuBackend>
{
    fn machine(&self) -> &Machine<F, A> {
        &self.machine
    }

    fn allocator(&self) -> &CpuBackend {
        &self.trace_allocator
    }

    async fn generate_main_traces(
        &self,
        record: A::Record,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> MainTraceData<F, A, CpuBackend> {
        let airs = self.machine.chips().to_vec();
        let (tx, rx) = oneshot::channel();
        // Spawn a rayon task to generate the traces on the CPU.
        slop_futures::rayon::spawn(move || {
            let chips_and_traces = airs
                .into_par_iter()
                .filter(|air| air.included(&record))
                .map(|air| {
                    // Chips with no main columns (global-only chips) contribute no main trace.
                    let main = (air.width() > 0)
                        .then(|| Mle::from(air.generate_trace(&record, &mut A::Record::default())));
                    let global = air
                        .generate_global_trace(&record, &mut A::Record::default())
                        .map(Mle::from);
                    (air, (global, main))
                })
                .collect::<BTreeMap<_, _>>();

            // Get the public values from the record.
            let public_values = record.public_values::<F>();

            tx.send((chips_and_traces, public_values)).ok().unwrap();
            // Emphasize that we are dropping the record after sending the traces.
            drop(record);
        });
        // Wait for the traces to be generated and copy them to the target backend.
        let (chips_and_traces, public_values) = rx.await.unwrap();

        let chip_set = chips_and_traces.keys().cloned().collect::<BTreeSet<_>>();
        let shard_chips = self
            .machine
            .smallest_cluster(&chip_set)
            .unwrap_or_else(|| {
                panic!(
                    "no chip cluster contains the included chip set: {:?}",
                    chip_set.iter().map(MachineAir::name).collect::<Vec<_>>()
                )
            })
            .clone();

        // Wait for a prover to be available.
        let permit = prover_permits
            .acquire()
            .instrument(tracing::debug_span!("acquire prover"))
            .await
            .unwrap();
        // Copy the traces to the target backend.

        let (traces, global_traces) =
            self.pad_and_copy_traces(&shard_chips, chips_and_traces, max_log_row_count);

        MainTraceData { traces, global_traces, public_values, shard_chips, permit }
    }

    async fn generate_preprocessed_traces(
        &self,
        program: Arc<A::Program>,
        max_log_row_count: usize,
        setup_permits: ProverSemaphore,
    ) -> PreprocessedTraceData<F, CpuBackend> {
        // Generate the traces on the CPU.
        let airs = self.machine.chips().iter().map(|chip| chip.air.clone()).collect::<Vec<_>>();
        let (tx, rx) = oneshot::channel();
        // Spawn a rayon task to generate the traces on the CPU.
        slop_futures::rayon::spawn(move || {
            let named_preprocessed_traces = airs
                .par_iter()
                .filter_map(|air| {
                    let name = air.name().to_string();
                    let trace = air.generate_preprocessed_trace(&program);
                    trace.map(Mle::from).map(|tr| (name, tr))
                })
                .collect::<BTreeMap<_, _>>();
            tx.send(named_preprocessed_traces).ok().unwrap();
        });

        // Wait for the traces to be generated and copy them to the target backend.
        // Wait for traces.
        let named_preprocessed_traces = rx.await.unwrap();

        // Wait for a permit to be available to copy the traces to the target backend.
        let permit = setup_permits
            .acquire()
            .instrument(tracing::debug_span!("acquire setup"))
            .await
            .unwrap();

        // Copy the traces to the target backend.
        let named_traces = named_preprocessed_traces
            .into_iter()
            .map(|(name, trace)| {
                let trace = self.trace_allocator.copy_into(trace).unwrap();
                let padded_mle =
                    PaddedMle::padded_with_zeros(Arc::new(trace), max_log_row_count as u32);
                (name, padded_mle)
            })
            .collect::<BTreeMap<_, _>>();

        let traces = Traces { named_traces };

        PreprocessedTraceData { preprocessed_traces: traces, permit }
    }

    async fn generate_traces(
        &self,
        program: Arc<A::Program>,
        record: A::Record,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> TraceData<F, A, CpuBackend> {
        let airs = self.machine.chips().to_vec();
        let (tx, rx) = oneshot::channel();
        // Spawn a rayon task to generate the traces on the CPU.
        slop_futures::rayon::spawn(move || {
            let named_preprocessed_traces = airs
                .par_iter()
                .filter_map(|air| {
                    let name = air.name().to_string();
                    let trace = air.generate_preprocessed_trace(&program);
                    trace.map(Mle::from).map(|tr| (name, tr))
                })
                .collect::<BTreeMap<_, _>>();

            let chips_and_traces = airs
                .into_par_iter()
                .filter(|air| air.included(&record))
                .map(|air| {
                    let main = (air.width() > 0)
                        .then(|| Mle::from(air.generate_trace(&record, &mut A::Record::default())));
                    let global = air
                        .generate_global_trace(&record, &mut A::Record::default())
                        .map(Mle::from);
                    (air, (global, main))
                })
                .collect::<BTreeMap<_, _>>();

            // Get the public values from the record.
            let public_values = record.public_values::<F>();
            tx.send((named_preprocessed_traces, chips_and_traces, public_values)).ok().unwrap();
            // Emphasize that we are dropping the record after sending the traces.
            drop(record);
        });
        // Wait for the traces to be generated and copy them to the target backend.
        let (named_preprocessed_traces, chips_and_traces, public_values) = rx.await.unwrap();

        let chip_set = chips_and_traces.keys().cloned().collect::<BTreeSet<_>>();
        let shard_chips = self
            .machine
            .smallest_cluster(&chip_set)
            .unwrap_or_else(|| {
                panic!(
                    "no chip cluster contains the included chip set: {:?}",
                    chip_set.iter().map(MachineAir::name).collect::<Vec<_>>()
                )
            })
            .clone();

        // Wait for a prover to be available.
        let permit = prover_permits
            .acquire()
            .instrument(tracing::debug_span!("acquire prover"))
            .await
            .unwrap();

        // Copy the preprocessed traces to the target backend.
        let preprocessed_traces = named_preprocessed_traces
            .into_iter()
            .map(|(name, trace)| {
                let trace = self.trace_allocator.copy_into(trace).unwrap();
                let padded_mle =
                    PaddedMle::padded_with_zeros(Arc::new(trace), max_log_row_count as u32);
                (name, padded_mle)
            })
            .collect::<BTreeMap<_, _>>();

        let preprocessed_traces = Traces { named_traces: preprocessed_traces };

        let (traces, global_traces) =
            self.pad_and_copy_traces(&shard_chips, chips_and_traces, max_log_row_count);

        let main_trace_data =
            MainTraceData { traces, global_traces, public_values, shard_chips, permit };

        TraceData { preprocessed_traces, main_trace_data }
    }
}
