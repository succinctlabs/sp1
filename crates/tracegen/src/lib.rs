mod recursion;
mod riscv;

use core::future::{ready, Future};
use core::pin::pin;
use std::collections::BTreeSet;
use std::{collections::BTreeMap, sync::Arc};

use futures::stream::FuturesUnordered;
use futures::{join, StreamExt};
use rayon::prelude::*;
use slop_air::BaseAir;
use slop_algebra::Field;
use slop_alloc::mem::CopyError;
use slop_koala_bear::KoalaBear;
use slop_multilinear::{Mle, PaddedMle};
use sp1_gpu_cudart::{DeviceMle, DeviceTransposeKernel, TaskScope};
use sp1_hypercube::prover::{MainTraceData, PreprocessedTraceData, ProverSemaphore, TraceData};
use sp1_hypercube::{
    air::MachineAir,
    prover::{TraceGenerator, Traces},
    Machine,
};
use sp1_hypercube::{Chip, MachineRecord};
use tracing::{debug_span, instrument, Instrument};

/// We currently only link to KoalaBear-specialized trace generation FFI.
pub(crate) type F = KoalaBear;

/// A trace generator that is GPU accelerated.
pub struct CudaTraceGenerator<F: Field, A> {
    machine: Machine<F, A>,
    trace_allocator: TaskScope,
}

impl<A: MachineAir<F>> CudaTraceGenerator<F, A> {
    /// Create a new trace generator.
    #[must_use]
    pub fn new_in(machine: Machine<F, A>, trace_allocator: TaskScope) -> Self {
        Self { machine, trace_allocator }
    }
}

/// TODO(tqn) documentation
struct HostPhaseTracegen<F, A> {
    pub device_airs: Vec<Arc<A>>,
    pub host_traces: futures::channel::mpsc::UnboundedReceiver<(String, Mle<F>)>,
}

/// TODO(tqn) documentation
struct HostPhaseShapePadding<F: Field, A> {
    pub shard_chips: BTreeSet<Chip<F, A>>,
    pub padded_traces: BTreeMap<String, PaddedMle<F, TaskScope>>,
}

impl<F, A> CudaTraceGenerator<F, A>
where
    F: Field,
    A: CudaTracegenAir<F>,
    TaskScope: DeviceTransposeKernel<F>,
{
    /// TODO(tqn) documentation
    #[instrument(skip_all, level = "debug")]
    fn host_preprocessed_tracegen(
        &self,
        program: Arc<<A as MachineAir<F>>::Program>,
    ) -> HostPhaseTracegen<F, A> {
        // Split chips based on where we will generate their traces.
        let (device_airs, host_airs): (Vec<_>, Vec<_>) = self
            .machine
            .chips()
            .iter()
            .map(|chip| chip.air.clone())
            .partition(|air| air.supports_device_preprocessed_tracegen());

        // Spawn a rayon task to generate the traces on the CPU.
        // `traces` is a futures Stream that will immediately begin buffering traces.
        let (host_traces_tx, host_traces) = futures::channel::mpsc::unbounded();
        slop_futures::rayon::spawn(move || {
            host_airs.into_par_iter().for_each_with(host_traces_tx, |tx, air| {
                if let Some(trace) = air.generate_preprocessed_trace(&program) {
                    tx.unbounded_send((air.name().to_string(), Mle::from(trace))).unwrap();
                }
            });
            // Make this explicit.
            // If we are the last users of the program, this will expensively drop it.
            drop(program);
        });
        HostPhaseTracegen { device_airs, host_traces }
    }

    #[instrument(skip_all, level = "debug")]
    async fn device_preprocessed_tracegen(
        &self,
        program: Arc<<A as MachineAir<F>>::Program>,
        max_log_row_count: usize,
        host_phase_tracegen: HostPhaseTracegen<F, A>,
    ) -> Traces<F, TaskScope> {
        let HostPhaseTracegen { device_airs, host_traces } = host_phase_tracegen;

        // Stream that, when polled, copies the host traces to the device.
        let copied_host_traces = pin!(host_traces.then(|(name, trace)| async move {
            (name, DeviceMle::from_host(&trace, &self.trace_allocator).unwrap().into())
        }));
        // Stream that, when polled, copies events to the device and generates traces.
        let device_traces = device_airs
            .into_iter()
            .map(|air| {
                // We want to borrow the program and move the air.
                let program = program.as_ref();
                async move {
                    let maybe_trace = air
                        .generate_preprocessed_trace_device(program, &self.trace_allocator)
                        .await
                        .unwrap();
                    (air, maybe_trace)
                }
            })
            .collect::<FuturesUnordered<_>>()
            .filter_map(|(air, maybe_trace)| {
                ready(maybe_trace.map(|trace| (air.name().to_string(), trace.into())))
            });

        let named_traces = futures::stream_select!(copied_host_traces, device_traces)
            .map(|(name, trace)| {
                (name, PaddedMle::padded_with_zeros(Arc::new(trace), max_log_row_count as u32))
            })
            .collect::<BTreeMap<_, _>>()
            .await;

        // If we're the last users of the program, expensively drop it in a separate task.
        // TODO: in general, figure out the best way to drop expensive-to-drop things.
        rayon::spawn(move || drop(program));

        Traces { named_traces }
    }

    /// TODO(tqn) documentation
    #[instrument(skip_all, level = "debug")]
    fn host_main_tracegen(
        &self,
        record: Arc<<A as MachineAir<F>>::Record>,
        max_log_row_count: usize,
    ) -> (HostPhaseTracegen<F, A>, HostPhaseShapePadding<F, A>)
    where
        F: Field,
        A: CudaTracegenAir<F>,
    {
        // Set of chips we need to generate traces for.
        let chip_set = self
            .machine
            .chips()
            .iter()
            .filter(|chip| chip.included(&record))
            .cloned()
            .collect::<BTreeSet<_>>();

        // Split chips based on where we will generate their traces.
        let (device_airs, host_airs): (Vec<_>, Vec<_>) = chip_set
            .iter()
            .map(|chip| chip.air.clone())
            .partition(|c| c.supports_device_main_tracegen());

        // Spawn a rayon task to generate the traces on the CPU.
        // `host_traces` is a futures Stream that will immediately begin buffering traces.
        let (host_traces_tx, host_traces) = futures::channel::mpsc::unbounded();
        slop_futures::rayon::spawn(move || {
            host_airs.into_par_iter().for_each_with(host_traces_tx, |tx, air| {
                let trace = Mle::from(air.generate_trace(&record, &mut A::Record::default()));
                // Since it's unbounded, it will only error if the receiver is disconnected.
                tx.unbounded_send((air.name().to_string(), trace)).unwrap();
            });
            // Make this explicit.
            // If we are the last users of the record, this will expensively drop it.
            drop(record);
        });

        // Get the smallest cluster containing our tracegen chip set.
        let shard_chips = self.machine.smallest_cluster(&chip_set).unwrap().clone();
        // For every AIR in the cluster, make a (virtual) padded trace.
        let padded_traces = shard_chips
            .iter()
            .filter(|chip| !chip_set.contains(chip))
            .map(|chip| {
                let num_polynomials = chip.width();
                (
                    chip.name().to_string(),
                    PaddedMle::zeros_in(
                        num_polynomials,
                        max_log_row_count as u32,
                        self.trace_allocator.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>();

        (
            HostPhaseTracegen { device_airs, host_traces },
            HostPhaseShapePadding { shard_chips, padded_traces },
        )
    }

    #[instrument(skip_all, level = "debug")]
    async fn device_main_tracegen(
        &self,
        max_log_row_count: usize,
        record: Arc<<A as MachineAir<F>>::Record>,
        host_phase_tracegen: HostPhaseTracegen<F, A>,
        padded_traces: BTreeMap<String, PaddedMle<F, TaskScope>>,
    ) -> (Traces<F, TaskScope>, Vec<F>)
    where
        F: Field,
        A: CudaTracegenAir<F>,
    {
        let HostPhaseTracegen { device_airs, host_traces } = host_phase_tracegen;

        // Stream that, when polled, copies the host traces to the device.
        let copied_host_traces = pin!(host_traces.then(|(name, trace)| async move {
            (name, DeviceMle::from_host(&trace, &self.trace_allocator).unwrap().into())
        }));
        // Stream that, when polled, copies events to the device and generates traces.
        let device_traces = device_airs
            .into_iter()
            .map(|air| {
                // We want to borrow the record and move the chip.
                let record = record.as_ref();
                async move {
                    let trace = air
                        .generate_trace_device(
                            record,
                            &mut A::Record::default(),
                            &self.trace_allocator,
                        )
                        .await
                        .unwrap();
                    (air.name().to_string(), trace.into())
                }
            })
            .collect::<FuturesUnordered<_>>();

        let mut all_traces = padded_traces;

        // Combine the host and device trace streams and insert them into `all_traces`.
        futures::stream_select!(copied_host_traces, device_traces)
            .for_each(|(name, trace)| {
                all_traces.insert(
                    name,
                    PaddedMle::padded_with_zeros(Arc::new(trace), max_log_row_count as u32),
                );
                ready(())
            })
            .await;

        // All traces are now generated, so the public values are ready.
        // That is, this value will have the correct global cumulative sum.
        let public_values = record.public_values::<F>();

        // If we're the last users of the record, expensively drop it in a separate task.
        // TODO: in general, figure out the best way to drop expensive-to-drop things.
        rayon::spawn(move || drop(record));

        let traces = Traces { named_traces: all_traces };
        (traces, public_values)
    }
}

impl<F, A> TraceGenerator<F, A, TaskScope> for CudaTraceGenerator<F, A>
where
    F: Field,
    A: CudaTracegenAir<F>,
    TaskScope: DeviceTransposeKernel<F>,
{
    fn machine(&self) -> &Machine<F, A> {
        &self.machine
    }

    fn allocator(&self) -> &TaskScope {
        &self.trace_allocator
    }

    async fn generate_preprocessed_traces(
        &self,
        program: Arc<<A as MachineAir<F>>::Program>,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> PreprocessedTraceData<F, TaskScope> {
        let host_phase_tracegen = self.host_preprocessed_tracegen(Arc::clone(&program));

        // Wait for a prover to be available.
        let permit = prover_permits.acquire().instrument(debug_span!("acquire")).await.unwrap();

        // Now that the permit is acquired, we can begin the following two tasks:
        // - Copying host traces to the device.
        // - Generating traces on the device.

        let preprocessed_traces = self
            .device_preprocessed_tracegen(program, max_log_row_count, host_phase_tracegen)
            .await;
        PreprocessedTraceData { preprocessed_traces, permit }
    }

    async fn generate_main_traces(
        &self,
        record: <A as MachineAir<F>>::Record,
        max_log_row_count: usize,
        prover_permits: ProverSemaphore,
    ) -> MainTraceData<F, A, TaskScope> {
        let record = Arc::new(record);

        let (host_phase_tracegen, HostPhaseShapePadding { shard_chips, padded_traces }) =
            self.host_main_tracegen(Arc::clone(&record), max_log_row_count);

        // Wait for a prover to be available.
        let permit = prover_permits.acquire().instrument(debug_span!("acquire")).await.unwrap();

        // Now that the permit is acquired, we can begin the following two tasks:
        // - Copying host traces to the device.
        // - Generating traces on the device.

        let (traces, public_values) = self
            .device_main_tracegen(max_log_row_count, record, host_phase_tracegen, padded_traces)
            .await;

        MainTraceData { traces, public_values, permit, shard_chips }
    }

    async fn generate_traces(
        &self,
        program: Arc<<A as MachineAir<F>>::Program>,
        record: <A as MachineAir<F>>::Record,
        max_log_row_count: usize,
        prover_permits: sp1_hypercube::prover::ProverSemaphore,
    ) -> TraceData<F, A, TaskScope> {
        let record = Arc::new(record);

        let prep_host_phase_tracegen = self.host_preprocessed_tracegen(Arc::clone(&program));

        let (main_host_phase_tracegen, HostPhaseShapePadding { shard_chips, padded_traces }) =
            self.host_main_tracegen(Arc::clone(&record), max_log_row_count);

        // Wait for a prover to be available.
        let permit = prover_permits.acquire().instrument(debug_span!("acquire")).await.unwrap();

        // Now that the permit is acquired, we can begin the following two tasks:
        // - Copying host traces to the device.
        // - Generating traces on the device.

        let (preprocessed_traces, (traces, public_values)) = join!(
            self.device_preprocessed_tracegen(program, max_log_row_count, prep_host_phase_tracegen),
            self.device_main_tracegen(
                max_log_row_count,
                record,
                main_host_phase_tracegen,
                padded_traces,
            )
        );

        TraceData {
            preprocessed_traces,
            main_trace_data: MainTraceData { traces, public_values, permit, shard_chips },
        }
    }
}

/// An AIR that potentially supports device trace generation over the given field.
pub trait CudaTracegenAir<F: Field>: MachineAir<F> {
    /// Whether this AIR supports preprocessed trace generation on the device.
    fn supports_device_preprocessed_tracegen(&self) -> bool {
        false
    }

    /// Generate the preprocessed trace on the device.
    ///
    /// # Panics
    /// Panics if unsupported. See [`CudaTracegenAir::supports_device_preprocessed_tracegen`].
    #[allow(unused_variables)]
    fn generate_preprocessed_trace_device(
        &self,
        program: &Self::Program,
        scope: &TaskScope,
    ) -> impl Future<Output = Result<Option<DeviceMle<F>>, CopyError>> + Send {
        #[allow(unreachable_code)]
        ready(unimplemented!())
    }

    /// Whether this AIR supports main trace generation on the device.
    fn supports_device_main_tracegen(&self) -> bool {
        false
    }

    /// Generate the main trace on the device.
    ///
    /// # Panics
    /// Panics if unsupported. See [`CudaTracegenAir::supports_device_main_tracegen`].
    #[allow(unused_variables)]
    fn generate_trace_device(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        scope: &TaskScope,
    ) -> impl Future<Output = Result<DeviceMle<F>, CopyError>> + Send {
        #[allow(unreachable_code)]
        ready(unimplemented!())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{CudaTracegenAir, F};
    use rand::{rngs::StdRng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;
    use std::collections::BTreeSet;

    pub(crate) fn test_traces_eq(
        trace: &Tensor<F>,
        gpu_trace: &Tensor<F>,
        events: &[impl core::fmt::Debug],
    ) {
        assert_eq!(gpu_trace.dimensions, trace.dimensions);

        println!("{:?}", trace.dimensions);

        let mut eventful_mismatched_columns = BTreeSet::new();
        let mut padding_mismatched_columns = BTreeSet::new();
        for row_idx in 0..trace.sizes()[0] {
            let mut col_mismatches = BTreeSet::new();
            for col_idx in 0..trace.sizes()[1] {
                let actual = gpu_trace[[row_idx, col_idx]];
                let expected = trace[[row_idx, col_idx]];
                if actual != expected {
                    println!(
                        "mismatch on row {} col {}. actual: {:?} expected: {:?}",
                        row_idx, col_idx, *actual, *expected
                    );
                    col_mismatches.insert(col_idx);
                }
            }
            let event = events.get(row_idx);
            if col_mismatches.is_empty() {
                println!("row {row_idx} matches   . event (assuming events/row = 1): {event:?}");
            } else {
                println!("row {row_idx} MISMATCHES. event (assuming events/row = 1): {event:?}");
                println!("mismatched columns: {col_mismatches:?}");
            }
            if event.is_some() {
                eventful_mismatched_columns.extend(col_mismatches);
            } else {
                padding_mismatched_columns.extend(col_mismatches);
            }
        }
        println!("eventful mismatched columns: {eventful_mismatched_columns:?}");
        println!("padding mismatched columns: {padding_mismatched_columns:?}");

        assert_eq!(gpu_trace, trace);
    }

    pub async fn test_main_tracegen<A, Event, Record>(
        chip: A,
        mut make_event: impl FnMut(&mut StdRng) -> Event,
        mut insert_events: impl FnMut(Vec<Event>) -> Record,
        scope: TaskScope,
    ) where
        A: CudaTracegenAir<F> + MachineAir<F, Record = Record>,
        Record: Default,
        Event: Clone + core::fmt::Debug,
    {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

        let events =
            core::iter::repeat_with(|| make_event(&mut rng)).take(1000).collect::<Vec<_>>();

        let [shard, gpu_shard] = core::array::from_fn(|_| insert_events(events.clone()));

        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut Record::default()));

        let gpu_trace = chip
            .generate_trace_device(&gpu_shard, &mut Record::default(), &scope)
            .await
            .expect("should copy events to device successfully")
            .to_host()
            .expect("should copy trace to host successfully")
            .into_guts();

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
    }
}
