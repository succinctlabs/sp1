//! GPU tracegen for memory state chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::adapter::bump::StateBumpChip;
use sp1_core_machine::memory::{MemoryBumpChip, MemoryChipType, MemoryLocalChip};
use sp1_core_machine::riscv::MemoryGlobalChip;
use sp1_gpu_cudart::sys::{MemoryBumpGpuEvent, MemoryGlobalGpuEvent, MemoryLocalGpuEvent};
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvMemoryBumpKernel, TracegenRiscvMemoryGlobalKernel,
    TracegenRiscvMemoryLocalKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of columns in MemoryInitCols<u8>.
const NUM_MEMORY_INIT_COLS: usize =
    std::mem::size_of::<sp1_core_machine::memory::MemoryInitCols<u8>>();

/// Number of columns in SingleMemoryLocal<u8>.
const NUM_MEMORY_LOCAL_COLS: usize =
    std::mem::size_of::<sp1_core_machine::memory::SingleMemoryLocal<u8>>();

/// Number of columns in MemoryBumpCols<u8>.
const NUM_MEMORY_BUMP_COLS: usize =
    std::mem::size_of::<sp1_core_machine::memory::MemoryBumpCols<u8>>();

impl CudaTracegenAir<F> for MemoryGlobalChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Get the events and previous_addr based on chip kind
        let mut memory_events = match self.kind {
            MemoryChipType::Initialize => input.global_memory_initialize_events.clone(),
            MemoryChipType::Finalize => input.global_memory_finalize_events.clone(),
        };

        let previous_addr: u64 = match self.kind {
            MemoryChipType::Initialize => input.public_values.previous_init_addr,
            MemoryChipType::Finalize => input.public_values.previous_finalize_addr,
        };

        // Sort by address (same as CPU implementation)
        memory_events.sort_by_key(|event| event.addr);

        let events_len = memory_events.len();

        // Convert events to GPU-compatible format
        let gpu_events: Vec<MemoryGlobalGpuEvent> = memory_events
            .iter()
            .map(|event| MemoryGlobalGpuEvent {
                addr: event.addr,
                value: event.value,
                timestamp: event.timestamp,
            })
            .collect();

        // Copy events to device
        let events_device = {
            let mut buf = Buffer::try_with_capacity_in(gpu_events.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&gpu_events)?;
            buf
        };

        // Compute trace height
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");

        // Allocate trace on device
        let mut trace =
            Tensor::<F, TaskScope>::zeros_in([NUM_MEMORY_INIT_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(
                trace.as_mut_ptr(),
                height,
                events_device.as_ptr(),
                events_len,
                previous_addr
            );

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_memory_global_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::from(trace))
    }
}

impl CudaTracegenAir<F> for MemoryLocalChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Collect events from both precompile and CPU local memory access
        let events: Vec<_> = input.get_local_mem_events().collect();
        let events_len = events.len();

        // Convert events to GPU-compatible format
        let gpu_events: Vec<MemoryLocalGpuEvent> = events
            .iter()
            .map(|event| MemoryLocalGpuEvent {
                addr: event.addr,
                initial_timestamp: event.initial_mem_access.timestamp,
                initial_value: event.initial_mem_access.value,
                final_timestamp: event.final_mem_access.timestamp,
                final_value: event.final_mem_access.value,
            })
            .collect();

        // Copy events to device
        let events_device = {
            let mut buf = Buffer::try_with_capacity_in(gpu_events.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&gpu_events)?;
            buf
        };

        // Compute trace height
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");

        // Allocate trace on device
        let mut trace =
            Tensor::<F, TaskScope>::zeros_in([NUM_MEMORY_LOCAL_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_memory_local_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::from(trace))
    }
}

impl CudaTracegenAir<F> for MemoryBumpChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events_len = input.bump_memory_events.len();

        // Convert events to GPU-compatible format
        let gpu_events: Vec<MemoryBumpGpuEvent> = input
            .bump_memory_events
            .iter()
            .map(|(event, addr, is_refresh)| {
                let prev_value = event.prev_value();
                let prev_timestamp = event.previous_record().timestamp;
                let mut timestamp = event.current_record().timestamp;
                if !is_refresh {
                    timestamp = (timestamp >> 24) << 24;
                }
                MemoryBumpGpuEvent {
                    prev_value,
                    prev_timestamp,
                    current_timestamp: timestamp,
                    addr: *addr,
                }
            })
            .collect();

        // Copy events to device
        let events_device = {
            let mut buf = Buffer::try_with_capacity_in(gpu_events.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&gpu_events)?;
            buf
        };

        // Compute trace height
        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");

        // Allocate trace on device
        let mut trace =
            Tensor::<F, TaskScope>::zeros_in([NUM_MEMORY_BUMP_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_memory_bump_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::from(trace))
    }
}

impl CudaTracegenAir<F> for StateBumpChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("StateBumpChip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::{
        events::{
            MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord, MemoryRecord,
            MemoryRecordEnum,
        },
        ExecutionRecord,
    };
    use sp1_core_machine::memory::{MemoryBumpChip, MemoryChipType, MemoryLocalChip};
    use sp1_core_machine::riscv::MemoryGlobalChip;
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
    use sp1_hypercube::air::MachineAir;
    use std::time::Instant;

    use crate::{CudaTracegenAir, F};

    /// Generate random memory initialize/finalize events for testing.
    /// Returns sorted events with strictly increasing addresses.
    fn generate_memory_global_events(count: usize) -> Vec<MemoryInitializeFinalizeEvent> {
        let mut rng = StdRng::seed_from_u64(0xDE00_BEEF);
        let mut events = Vec::with_capacity(count);

        let mut current_addr: u64 = 0x1000;
        for _ in 0..count {
            // Strictly increasing addresses with random gaps
            current_addr += rng.gen_range(1..=0x100) as u64;

            let value: u64 = rng.gen();
            let timestamp: u64 = rng.gen_range(0..0x1_0000_0000u64);

            events.push(MemoryInitializeFinalizeEvent { addr: current_addr, value, timestamp });
        }

        events
    }

    #[tokio::test]
    async fn test_memory_global_init_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_memory_global_init_generate_trace).await.unwrap();
    }

    async fn inner_test_memory_global_init_generate_trace(scope: TaskScope) {
        let events = generate_memory_global_events(1000);
        let previous_addr: u64 = 0x800; // a valid previous address < first event addr

        let make_record = |events: &[MemoryInitializeFinalizeEvent]| {
            let mut record = ExecutionRecord::default();
            record.global_memory_initialize_events = events.to_vec();
            record.public_values.previous_init_addr = previous_addr;
            record
        };

        let [shard, gpu_shard] = [make_record(&events), make_record(&events)];

        let chip = MemoryGlobalChip::new(MemoryChipType::Initialize);

        // GPU warmup
        let _ = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("warmup should succeed");
        scope.synchronize().await.unwrap();

        // CPU timing
        scope.synchronize().await.unwrap();
        let cpu_start = Instant::now();
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
        let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
        let cpu_duration = cpu_start.elapsed();

        // GPU timing
        scope.synchronize().await.unwrap();
        let gpu_start = Instant::now();
        let gpu_device_mle = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("should copy events to device successfully");
        scope.synchronize().await.unwrap();
        let gpu_duration = gpu_start.elapsed();

        let gpu_trace =
            gpu_device_mle.to_host().expect("should copy trace to host successfully").into_guts();

        println!("MemoryGlobalInit Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    #[tokio::test]
    async fn test_memory_global_final_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_memory_global_final_generate_trace).await.unwrap();
    }

    async fn inner_test_memory_global_final_generate_trace(scope: TaskScope) {
        let events = generate_memory_global_events(1000);
        let previous_addr: u64 = 0x800;

        let make_record = |events: &[MemoryInitializeFinalizeEvent]| {
            let mut record = ExecutionRecord::default();
            record.global_memory_finalize_events = events.to_vec();
            record.public_values.previous_finalize_addr = previous_addr;
            record
        };

        let [shard, gpu_shard] = [make_record(&events), make_record(&events)];

        let chip = MemoryGlobalChip::new(MemoryChipType::Finalize);

        // GPU warmup
        let _ = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("warmup should succeed");
        scope.synchronize().await.unwrap();

        // CPU timing
        scope.synchronize().await.unwrap();
        let cpu_start = Instant::now();
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
        let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
        let cpu_duration = cpu_start.elapsed();

        // GPU timing
        scope.synchronize().await.unwrap();
        let gpu_start = Instant::now();
        let gpu_device_mle = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("should copy events to device successfully");
        scope.synchronize().await.unwrap();
        let gpu_duration = gpu_start.elapsed();

        let gpu_trace =
            gpu_device_mle.to_host().expect("should copy trace to host successfully").into_guts();

        println!("MemoryGlobalFinal Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random memory local events for testing.
    fn generate_memory_local_events(count: usize) -> Vec<MemoryLocalEvent> {
        let mut rng = StdRng::seed_from_u64(0xDE00_BEEF);
        let mut events = Vec::with_capacity(count);

        for _ in 0..count {
            let addr: u64 = rng.gen_range(0x1000..0x1_0000_0000u64);
            let initial_value: u64 = rng.gen();
            let initial_timestamp: u64 = rng.gen_range(0..0x1_0000_0000u64);
            let final_value: u64 = rng.gen();
            let final_timestamp: u64 = rng.gen_range(0..0x1_0000_0000u64);

            events.push(MemoryLocalEvent {
                addr,
                initial_mem_access: MemoryRecord {
                    timestamp: initial_timestamp,
                    value: initial_value,
                },
                final_mem_access: MemoryRecord { timestamp: final_timestamp, value: final_value },
            });
        }

        events
    }

    #[tokio::test]
    async fn test_memory_local_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_memory_local_generate_trace).await.unwrap();
    }

    async fn inner_test_memory_local_generate_trace(scope: TaskScope) {
        let events = generate_memory_local_events(1000);

        let make_record = |events: &[MemoryLocalEvent]| {
            let mut record = ExecutionRecord::default();
            record.cpu_local_memory_access = events.to_vec();
            record
        };

        let [shard, gpu_shard] = [make_record(&events), make_record(&events)];

        let chip = MemoryLocalChip::new();

        // GPU warmup
        let _ = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("warmup should succeed");
        scope.synchronize().await.unwrap();

        // CPU timing
        scope.synchronize().await.unwrap();
        let cpu_start = Instant::now();
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
        let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
        let cpu_duration = cpu_start.elapsed();

        // GPU timing
        scope.synchronize().await.unwrap();
        let gpu_start = Instant::now();
        let gpu_device_mle = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("should copy events to device successfully");
        scope.synchronize().await.unwrap();
        let gpu_duration = gpu_start.elapsed();

        let gpu_trace =
            gpu_device_mle.to_host().expect("should copy trace to host successfully").into_guts();

        println!("MemoryLocal Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random bump memory events for testing.
    fn generate_memory_bump_events(count: usize) -> Vec<(MemoryRecordEnum, u64, bool)> {
        let mut rng = StdRng::seed_from_u64(0xDE00_BEEF);
        let mut events = Vec::with_capacity(count);

        for _ in 0..count {
            let addr: u64 = rng.gen_range(0..32);
            let value: u64 = rng.gen();
            let is_refresh: bool = rng.gen_bool(0.5);

            // When is_refresh=false, timestamp gets rounded: (ts >> 24) << 24.
            // Ensure prev_timestamp < rounded timestamp.
            let (prev_timestamp, timestamp) = if is_refresh {
                let prev = rng.gen_range(1..0x1_0000_0000u64);
                let ts = prev + rng.gen_range(1..0x1_0000u64);
                (prev, ts)
            } else {
                // Ensure the high part creates a valid rounded timestamp > prev_timestamp.
                // Use a high part >= 1 and prev_timestamp < (high << 24).
                let high: u64 = rng.gen_range(1..0x100u64);
                let rounded = high << 24;
                let prev = rng.gen_range(0..rounded);
                // timestamp must have the same high part but with some low bits
                let ts = rounded + rng.gen_range(0..0xFF_FFFFu64);
                (prev, ts)
            };

            let record = MemoryRecordEnum::Read(MemoryReadRecord {
                value,
                timestamp,
                prev_timestamp,
                prev_page_prot_record: None,
            });

            events.push((record, addr, is_refresh));
        }

        events
    }

    #[tokio::test]
    async fn test_memory_bump_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_memory_bump_generate_trace).await.unwrap();
    }

    async fn inner_test_memory_bump_generate_trace(scope: TaskScope) {
        let events = generate_memory_bump_events(1000);

        let make_record = |events: &[(MemoryRecordEnum, u64, bool)]| {
            let mut record = ExecutionRecord::default();
            record.bump_memory_events = events.to_vec();
            record.cpu_event_count = 1; // needed for included()
            record
        };

        let [shard, gpu_shard] = [make_record(&events), make_record(&events)];

        let chip = MemoryBumpChip {};

        // GPU warmup
        let _ = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("warmup should succeed");
        scope.synchronize().await.unwrap();

        // CPU timing
        scope.synchronize().await.unwrap();
        let cpu_start = Instant::now();
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
        let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
        let cpu_duration = cpu_start.elapsed();

        // GPU timing
        scope.synchronize().await.unwrap();
        let gpu_start = Instant::now();
        let gpu_device_mle = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("should copy events to device successfully");
        scope.synchronize().await.unwrap();
        let gpu_duration = gpu_start.elapsed();

        let gpu_trace =
            gpu_device_mle.to_host().expect("should copy trace to host successfully").into_guts();

        println!("MemoryBump Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_state_bump_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = sp1_core_machine::adapter::bump::StateBumpChip::new();
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
