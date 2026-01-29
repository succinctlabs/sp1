//! GPU tracegen for syscall chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::riscv::SyscallChip;
use sp1_core_machine::syscall::chip::{SyscallShardKind, NUM_SYSCALL_COLS};
use sp1_core_machine::syscall::instructions::columns::NUM_SYSCALL_INSTR_COLS;
use sp1_core_machine::syscall::instructions::SyscallInstrsChip;
use sp1_gpu_cudart::sys::{SyscallGpuEvent, SyscallInstrsGpuEvent};
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvSyscallInstrsKernel, TracegenRiscvSyscallKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::riscv::alu::memory_record_to_gpu;
use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for SyscallInstrsChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.syscall_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<SyscallInstrsGpuEvent> = events
            .iter()
            .map(|(syscall_event, r_type_record)| SyscallInstrsGpuEvent {
                clk: syscall_event.clk,
                pc: syscall_event.pc,
                arg1: syscall_event.arg1,
                arg2: syscall_event.arg2,
                exit_code: syscall_event.exit_code,
                a_value: r_type_record.a.value(),
                op_a: r_type_record.op_a,
                op_b: r_type_record.op_b,
                op_c: r_type_record.op_c,
                mem_a: memory_record_to_gpu(&r_type_record.a),
                mem_b: memory_record_to_gpu(&r_type_record.b),
                mem_c: memory_record_to_gpu(&r_type_record.c),
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
            Tensor::<F, TaskScope>::zeros_in([NUM_SYSCALL_INSTR_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_syscall_instrs_kernel(),
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

/// Convert a SyscallEvent to a SyscallGpuEvent for the SyscallChip kernel.
fn syscall_event_to_gpu(event: &sp1_core_executor::events::SyscallEvent) -> SyscallGpuEvent {
    SyscallGpuEvent {
        clk: event.clk,
        syscall_id: event.syscall_code.syscall_id(),
        arg1: event.arg1,
        arg2: event.arg2,
    }
}

impl CudaTracegenAir<F> for SyscallChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Collect events based on shard kind (same filtering as CPU)
        let gpu_events: Vec<SyscallGpuEvent> = match self.shard_kind() {
            SyscallShardKind::Core => input
                .syscall_events
                .iter()
                .map(|(event, _)| event)
                .filter(|e| e.should_send)
                .map(syscall_event_to_gpu)
                .collect(),
            SyscallShardKind::Precompile => input
                .precompile_events
                .all_events()
                .map(|(event, _)| syscall_event_to_gpu(event))
                .collect(),
        };
        let events_len = gpu_events.len();

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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_SYSCALL_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_syscall_kernel(),
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

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::{
        events::{MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord, SyscallEvent},
        ExecutionRecord, RTypeRecord, SyscallCode,
    };
    use sp1_core_machine::riscv::SyscallChip;
    use sp1_core_machine::syscall::instructions::SyscallInstrsChip;
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
    use sp1_hypercube::air::MachineAir;
    use std::time::Instant;

    use crate::{CudaTracegenAir, F};

    /// Generate a random memory read record for testing.
    fn random_read_record(
        rng: &mut StdRng,
        value: u64,
        timestamp: u64,
        base_timestamp: u64,
    ) -> MemoryRecordEnum {
        let prev_timestamp = if timestamp > base_timestamp {
            base_timestamp + rng.gen_range(0..timestamp - base_timestamp)
        } else {
            base_timestamp
        };
        MemoryRecordEnum::Read(MemoryReadRecord {
            value,
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    /// Generate a random memory write record for testing.
    fn random_write_record(
        rng: &mut StdRng,
        prev_value: u64,
        value: u64,
        timestamp: u64,
        base_timestamp: u64,
    ) -> MemoryRecordEnum {
        let prev_timestamp = if timestamp > base_timestamp {
            base_timestamp + rng.gen_range(0..timestamp - base_timestamp)
        } else {
            base_timestamp
        };
        MemoryRecordEnum::Write(MemoryWriteRecord {
            prev_timestamp,
            prev_page_prot_record: None,
            prev_value,
            timestamp,
            value,
        })
    }

    /// Generate random syscall events for testing SyscallInstrsChip.
    fn generate_syscall_events(count: usize) -> Vec<(SyscallEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5CA1_BEEF);
        let mut events = Vec::with_capacity(count);

        // clk must satisfy clk % 8 == 1 (the CPU state validation requires
        // (clk_0_16 - 1) / 8 to be valid, so clk_0_16 >= 1).
        // We use a base that's ≡ 1 (mod 8) and spans multiple 16-bit limbs.
        let base_timestamp: u64 = 0x1_0000_1001; // 0x1001 & 0x7 == 1
        let base_pc: u64 = 0x8000_4000_2000;

        let syscall_codes = [
            SyscallCode::HALT,
            SyscallCode::ENTER_UNCONSTRAINED,
            SyscallCode::HINT_LEN,
            SyscallCode::COMMIT,
            SyscallCode::COMMIT_DEFERRED_PROOFS,
            SyscallCode::HINT_LEN,
        ];

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;

            let syscall_code = syscall_codes[i % syscall_codes.len()];
            let syscall_id = syscall_code.syscall_id();

            let t0_prev_value = syscall_code as u64;
            let t0_new_value: u64 = rng.gen();

            let arg1: u64 = rng.gen();
            let arg2: u64 = rng.gen();
            let exit_code: u32 = if syscall_code == SyscallCode::HALT { rng.gen() } else { 0 };

            let b_value: u64 = if syscall_code == SyscallCode::COMMIT
                || syscall_code == SyscallCode::COMMIT_DEFERRED_PROOFS
            {
                rng.gen_range(0u64..8u64)
            } else {
                rng.gen()
            };

            let c_value: u64 = if syscall_code == SyscallCode::COMMIT {
                rng.gen::<u32>() as u64
            } else {
                rng.gen()
            };

            let syscall_event = SyscallEvent {
                pc,
                next_pc: if syscall_code == SyscallCode::HALT { 1 } else { pc + 4 },
                clk,
                op_a_0: false,
                should_send: true,
                syscall_code,
                syscall_id,
                arg1,
                arg2,
                exit_code,
            };

            let r_type_record = RTypeRecord {
                op_a: 5,
                a: random_write_record(
                    &mut rng,
                    t0_prev_value,
                    t0_new_value,
                    clk + 4,
                    base_timestamp,
                ),
                op_b: 10,
                b: random_read_record(&mut rng, b_value, clk + 1, base_timestamp),
                op_c: 11,
                c: random_read_record(&mut rng, c_value, clk + 2, base_timestamp),
                is_untrusted: false,
            };

            events.push((syscall_event, r_type_record));
        }

        events
    }

    /// Generate random SyscallEvents for testing SyscallChip (Core).
    /// These events have should_send = true to match the Core filter.
    fn generate_core_syscall_events(count: usize) -> Vec<(SyscallEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xC0DE_CAFE);
        let mut events = Vec::with_capacity(count);

        let base_timestamp: u64 = 0x1_0000_1001;
        let base_pc: u64 = 0x8000_4000_2000;

        // Use syscall codes that have should_send = true (byte 1 != 0)
        let syscall_codes = [
            SyscallCode::SHA_EXTEND,
            SyscallCode::SHA_COMPRESS,
            SyscallCode::KECCAK_PERMUTE,
            SyscallCode::SECP256K1_ADD,
        ];

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;

            let syscall_code = syscall_codes[i % syscall_codes.len()];
            let syscall_id = syscall_code.syscall_id();

            let arg1: u64 = rng.gen();
            let arg2: u64 = rng.gen();

            let syscall_event = SyscallEvent {
                pc,
                next_pc: pc + 4,
                clk,
                op_a_0: false,
                should_send: true,
                syscall_code,
                syscall_id,
                arg1,
                arg2,
                exit_code: 0,
            };

            // Create a dummy RTypeRecord (SyscallChip doesn't use it)
            let r_type_record = RTypeRecord {
                op_a: 5,
                a: random_write_record(&mut rng, 0, 0, clk + 4, base_timestamp),
                op_b: 10,
                b: random_read_record(&mut rng, arg1, clk + 1, base_timestamp),
                op_c: 11,
                c: random_read_record(&mut rng, arg2, clk + 2, base_timestamp),
                is_untrusted: false,
            };

            events.push((syscall_event, r_type_record));
        }

        events
    }

    #[tokio::test]
    async fn test_syscall_instrs_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_syscall_instrs_generate_trace).await.unwrap();
    }

    async fn inner_test_syscall_instrs_generate_trace(scope: TaskScope) {
        let events = generate_syscall_events(1000);

        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            syscall_events: events.clone(),
            ..Default::default()
        });

        let chip = SyscallInstrsChip;

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

        println!("SyscallInstrs Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    #[tokio::test]
    async fn test_syscall_core_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_syscall_core_generate_trace).await.unwrap();
    }

    async fn inner_test_syscall_core_generate_trace(scope: TaskScope) {
        let events = generate_core_syscall_events(1000);

        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            syscall_events: events.clone(),
            ..Default::default()
        });

        let chip = SyscallChip::core();

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

        println!("SyscallCore Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare: use the filtered events (should_send only) since that's what core processes
        let filtered_events: Vec<_> =
            events.iter().filter(|(e, _)| e.should_send).cloned().collect();
        crate::tests::test_traces_eq(&trace, &gpu_trace, &filtered_events, false);
    }
}
