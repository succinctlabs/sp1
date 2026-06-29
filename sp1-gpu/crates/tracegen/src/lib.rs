mod recursion;
mod riscv;
pub use riscv::LookupHist;
#[cfg(test)]
mod witgen_interp;

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
use slop_alloc::Buffer;
use slop_multilinear::{Mle, PaddedMle};
use sp1_gpu_cudart::{DeviceBuffer, DeviceMle, DeviceTransposeKernel, TaskScope};
use sp1_hypercube::prover::{MainTraceData, PreprocessedTraceData, ProverSemaphore, TraceData};
use sp1_hypercube::{
    air::MachineAir,
    prover::{TraceGenerator, Traces},
    Machine,
};

use sp1_hypercube::{Chip, MachineRecord};
use sp1_primitives::SP1Field;
use tracing::{debug_span, instrument, Instrument};

/// We currently only link to KoalaBear-specialized trace generation FFI.
pub(crate) type F = SP1Field;

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
    /// Byte/Range lookup-table chips deferred out of the concurrent host set: their
    /// traces depend on the full `byte_lookups` map, which (when device chips generate
    /// dependencies on the GPU via the fused kernel) is not complete until device
    /// tracegen finishes. Empty unless device-dependency chips are present.
    pub byte_range_airs: Vec<Arc<A>>,
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
        HostPhaseTracegen { device_airs, host_traces, byte_range_airs: Vec::new() }
    }

    #[instrument(skip_all, level = "debug")]
    async fn device_preprocessed_tracegen(
        &self,
        program: Arc<<A as MachineAir<F>>::Program>,
        max_log_row_count: usize,
        host_phase_tracegen: HostPhaseTracegen<F, A>,
    ) -> Traces<F, TaskScope> {
        let HostPhaseTracegen { device_airs, host_traces, byte_range_airs: _ } =
            host_phase_tracegen;

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

        // When device chips generate their byte-lookup dependencies on the GPU (fused
        // into the main-trace kernel), the full `byte_lookups` map isn't complete until
        // device tracegen finishes — so defer the Byte/Range lookup-table chips out of
        // the concurrent host set; `device_main_tracegen` generates them afterward from
        // the reconstructed map. With no device-dependency chips (e.g. recursion/wrap),
        // nothing is deferred and the host set is unchanged.
        let defer_byte_range = device_airs.iter().any(|c| c.supports_device_dependencies());
        let (byte_range_airs, host_airs): (Vec<_>, Vec<_>) = if defer_byte_range {
            host_airs.into_iter().partition(|c| c.name() == "Byte" || c.name() == "Range")
        } else {
            (Vec::new(), host_airs)
        };

        // Spawn a rayon task to generate the (remaining) host traces on the CPU.
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
            HostPhaseTracegen { device_airs, host_traces, byte_range_airs },
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
        let HostPhaseTracegen { device_airs, host_traces, byte_range_airs } = host_phase_tracegen;

        // When any device chip generates its byte-lookup dependencies on the GPU, all
        // such chips accumulate into ONE shared shard histogram pair via the fused
        // kernel (no separate dependency pre-pass). Shared by raw pointer across the
        // concurrent device futures — the device-side atomicAdds serialize the writes,
        // and the histogram is read back only after the stream drains.
        let has_device_deps = device_airs.iter().any(|c| c.supports_device_dependencies());
        let histograms = has_device_deps.then(|| new_byte_histograms(&self.trace_allocator));
        let hist = match &histograms {
            Some((range_dev, byte_dev)) => LookupHist {
                range: range_dev.as_ptr() as *mut u32,
                byte: byte_dev.as_ptr() as *mut u32,
            },
            None => LookupHist { range: std::ptr::null_mut(), byte: std::ptr::null_mut() },
        };

        // Stream that, when polled, copies the host traces to the device.
        let copied_host_traces = pin!(host_traces.then(|(name, trace)| async move {
            (name, DeviceMle::from_host(&trace, &self.trace_allocator).unwrap().into())
        }));
        // Stream that, when polled, copies events to the device and generates traces.
        // Device-dependency chips use the FUSED kernel (columns + lookups in one pass,
        // accumulating into the shared histogram); others (e.g. Global) the plain one.
        let device_traces = device_airs
            .into_iter()
            .map(|air| {
                // We want to borrow the record and move the chip.
                let record = record.as_ref();
                async move {
                    let trace = if air.supports_device_dependencies() {
                        air.generate_trace_device_with_lookups(record, hist, &self.trace_allocator)
                            .await
                            .unwrap()
                    } else {
                        air.generate_trace_device(
                            record,
                            &mut A::Record::default(),
                            &self.trace_allocator,
                        )
                        .await
                        .unwrap()
                    };
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

        // Reconstruct the full `byte_lookups` map and generate the deferred Byte/Range
        // table traces from it. The device-dependency chips ran the fused kernel on
        // their own task streams (concurrently), accumulating into the shared histogram;
        // we MUST synchronize the scope so every fused kernel's atomicAdds are visible
        // before reading the histogram back (otherwise the readback races the kernels
        // and yields an incomplete map → GKR cumulative-sum mismatch).
        if let Some((range_dev, byte_dev)) = histograms {
            self.trace_allocator.synchronize().await.expect("synchronize device tracegen");
            let range_hist = range_dev.to_host().expect("read back range histogram");
            let byte_hist = byte_dev.to_host().expect("read back byte histogram");
            if let Some(first) = byte_range_airs.first() {
                // host chips' lookups (already in `record`) unioned with the device
                // chips' lookups reconstructed from the shared histogram.
                let merged =
                    first.record_with_byte_lookups(record.as_ref(), &range_hist, &byte_hist);
                for air in &byte_range_airs {
                    let host_trace =
                        Mle::from(air.generate_trace(&merged, &mut A::Record::default()));
                    let device_trace =
                        DeviceMle::from_host(&host_trace, &self.trace_allocator).unwrap();
                    all_traces.insert(
                        air.name().to_string(),
                        PaddedMle::padded_with_zeros(
                            Arc::new(device_trace.into()),
                            max_log_row_count as u32,
                        ),
                    );
                }
            }
        }

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

    /// Whether this AIR generates its dependencies (byte lookups) on the device. When
    /// true, the host `generate_dependencies` SKIPS this chip (see
    /// `AirProver::host_dependency_skip_chips`) and the prover instead calls
    /// [`CudaTracegenAir::generate_device_dependencies`], accumulating the chip's byte
    /// lookups into the SHARED shard histograms, then reconstructs the `byte_lookups`
    /// map ONCE via [`CudaTracegenAir::add_lookups_from_histograms`] (so the Byte/Range
    /// chips' host tracegen is unchanged).
    fn supports_device_dependencies(&self) -> bool {
        false
    }

    /// Accumulate this chip's byte-lookup dependencies into the SHARED shard-level
    /// histograms `range_dev`/`byte_dev` (allocated once by the prover via
    /// [`new_byte_histograms`], shared across all device-dependency chips). The dense
    /// histograms are opcode-indexed, so accumulating every chip into one pair and
    /// reconstructing once equals the union of the per-chip maps — but with a single
    /// alloc/zero, a single D2H readback, and a single host reconstruct per shard
    /// instead of one set per chip (heed iter-004). Default: no-op.
    #[allow(unused_variables)]
    fn generate_device_dependencies(
        &self,
        input: &Self::Record,
        range_dev: &mut DeviceBuffer<u32>,
        byte_dev: &mut DeviceBuffer<u32>,
        scope: &TaskScope,
    ) -> impl Future<Output = Result<(), CopyError>> + Send {
        ready(Ok(()))
    }

    /// Reconstruct the `byte_lookups` map from the shared histograms (already read back
    /// to host) and merge it into `output`. Called ONCE per shard, after every device
    /// chip has accumulated into the shared histograms. Default: no-op.
    #[allow(unused_variables)]
    fn add_lookups_from_histograms(
        &self,
        range_hist: &[u32],
        byte_hist: &[u32],
        output: &mut Self::Record,
    ) {
    }

    /// FUSED main tracegen: generate this chip's trace columns AND accumulate its
    /// byte/range lookups into the shared shard histograms `hist` in a single op-DAG
    /// pass (the device counterpart of running `generate_trace_device` +
    /// `generate_device_dependencies` separately, but with the witgen evaluated once).
    /// Called for chips with [`supports_device_dependencies`] during the device trace
    /// phase, so the separate dependency pre-pass is unnecessary. Default: unsupported.
    #[allow(unused_variables)]
    fn generate_trace_device_with_lookups(
        &self,
        input: &Self::Record,
        hist: LookupHist,
        scope: &TaskScope,
    ) -> impl Future<Output = Result<DeviceMle<F>, CopyError>> + Send {
        #[allow(unreachable_code)]
        ready(unimplemented!())
    }

    /// Build a record carrying the full `byte_lookups` map (the host chips' lookups in
    /// `base` unioned with the device chips' lookups reconstructed from the shared
    /// histograms) for the deferred Byte/Range table chips to generate their traces
    /// from. Called ONCE after device tracegen completes. Default: empty record.
    #[allow(unused_variables)]
    fn record_with_byte_lookups(
        &self,
        base: &Self::Record,
        range_hist: &[u32],
        byte_hist: &[u32],
    ) -> Self::Record {
        Self::Record::default()
    }
}

/// Allocate the two shard-level byte-lookup histograms (`range`, `byte`), zeroed, on
/// the device. Shared across every device-dependency chip in a shard: each accumulates
/// via the byte-lookup kernel, then the host reconstructs the `byte_lookups` map ONCE
/// (heed iter-004 — one dense histogram pair per shard, not one per chip per shard).
pub fn new_byte_histograms(scope: &TaskScope) -> (DeviceBuffer<u32>, DeviceBuffer<u32>) {
    use sp1_core_machine::air::{BYTE_HIST_ROWS, RANGE_HIST_ROWS};
    use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
    let range_len = RANGE_HIST_ROWS;
    let byte_len = BYTE_HIST_ROWS * NUM_BYTE_MULT_COLS;
    let mut range_buf = Buffer::try_with_capacity_in(range_len, scope.clone()).unwrap();
    range_buf.extend_from_host_slice(&vec![0u32; range_len]).unwrap();
    let mut byte_buf = Buffer::try_with_capacity_in(byte_len, scope.clone()).unwrap();
    byte_buf.extend_from_host_slice(&vec![0u32; byte_len]).unwrap();
    (DeviceBuffer::from_raw(range_buf), DeviceBuffer::from_raw(byte_buf))
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

        tracing::info!("{:?}", trace.dimensions);

        let mut eventful_mismatched_columns = BTreeSet::new();
        let mut padding_mismatched_columns = BTreeSet::new();
        for row_idx in 0..trace.sizes()[0] {
            let mut col_mismatches = BTreeSet::new();
            for col_idx in 0..trace.sizes()[1] {
                let actual = gpu_trace[[row_idx, col_idx]];
                let expected = trace[[row_idx, col_idx]];
                if actual != expected {
                    tracing::error!(
                        "mismatch on row {} col {}. actual: {:?} expected: {:?}",
                        row_idx,
                        col_idx,
                        *actual,
                        *expected
                    );
                    col_mismatches.insert(col_idx);
                }
            }
            let event = events.get(row_idx);
            if col_mismatches.is_empty() {
                tracing::info!(
                    "row {row_idx} matches   . event (assuming events/row = 1): {event:?}"
                );
            } else {
                tracing::error!(
                    "row {row_idx} MISMATCHES. event (assuming events/row = 1): {event:?}"
                );
                tracing::error!("mismatched columns: {col_mismatches:?}");
            }
            if event.is_some() {
                eventful_mismatched_columns.extend(col_mismatches);
            } else {
                padding_mismatched_columns.extend(col_mismatches);
            }
        }
        tracing::info!("eventful mismatched columns: {eventful_mismatched_columns:?}");
        tracing::info!("padding mismatched columns: {padding_mismatched_columns:?}");

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
