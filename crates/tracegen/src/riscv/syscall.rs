//! GPU tracegen for syscall chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::riscv::SyscallChip;
use sp1_core_machine::syscall::instructions::columns::NUM_SYSCALL_INSTR_COLS;
use sp1_core_machine::syscall::instructions::SyscallInstrsChip;
use sp1_gpu_cudart::sys::SyscallInstrsGpuEvent;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, TracegenRiscvSyscallInstrsKernel};
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

impl CudaTracegenAir<F> for SyscallChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("SyscallChip GPU tracegen not yet implemented")
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

    /// Generate random syscall events for testing.
    /// Covers all syscall types: HALT, ENTER_UNCONSTRAINED, HINT_LEN, COMMIT,
    /// COMMIT_DEFERRED_PROOFS, and other generic syscalls.
    fn generate_syscall_events(count: usize) -> Vec<(SyscallEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5CA1_BEEF);
        let mut events = Vec::with_capacity(count);

        // clk must satisfy clk % 8 == 1 (the CPU state validation requires
        // (clk_0_16 - 1) / 8 to be valid, so clk_0_16 >= 1).
        // We use a base that's ≡ 1 (mod 8) and spans multiple 16-bit limbs.
        let base_timestamp: u64 = 0x1_0000_1001; // 0x1001 & 0x7 == 1
        let base_pc: u64 = 0x8000_4000_2000;

        // Syscall codes to test
        let syscall_codes = [
            SyscallCode::HALT,
            SyscallCode::ENTER_UNCONSTRAINED,
            SyscallCode::HINT_LEN,
            SyscallCode::COMMIT,
            SyscallCode::COMMIT_DEFERRED_PROOFS,
            // A generic syscall (SHA_EXTEND uses its own table, but the instructions
            // chip just processes the ecall). Use HINT_LEN as a stand-in for "other".
            SyscallCode::HINT_LEN,
        ];

        for i in 0..count {
            // Increment by 8 to maintain clk ≡ 1 (mod 8)
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;

            let syscall_code = syscall_codes[i % syscall_codes.len()];
            let syscall_id = syscall_code.syscall_id();

            // t0 register contains the syscall code (as a u32 value)
            // prev_value of t0 = the syscall code
            let t0_prev_value = syscall_code as u64;
            // After ecall, t0 is written with a result value
            let t0_new_value: u64 = rng.gen();

            let arg1: u64 = rng.gen();
            let arg2: u64 = rng.gen();
            let exit_code: u32 = if syscall_code == SyscallCode::HALT { rng.gen() } else { 0 };

            // For COMMIT / COMMIT_DEFERRED_PROOFS, b holds the digest index (0..8)
            let b_value: u64 = if syscall_code == SyscallCode::COMMIT
                || syscall_code == SyscallCode::COMMIT_DEFERRED_PROOFS
            {
                rng.gen_range(0u64..8u64)
            } else {
                rng.gen()
            };

            // For COMMIT, c holds the digest word value (as u32)
            let c_value: u64 = if syscall_code == SyscallCode::COMMIT {
                rng.gen::<u32>() as u64
            } else {
                rng.gen()
            };

            let op_a: u8 = 5; // t0 is typically x5
            let op_b_reg: u64 = 10;
            let op_c_reg: u64 = 11;

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
                op_a,
                a: random_write_record(
                    &mut rng,
                    t0_prev_value,
                    t0_new_value,
                    clk + 4,
                    base_timestamp,
                ),
                op_b: op_b_reg,
                b: random_read_record(&mut rng, b_value, clk + 1, base_timestamp),
                op_c: op_c_reg,
                c: random_read_record(&mut rng, c_value, clk + 2, base_timestamp),
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
        // Generate realistic syscall events
        let events = generate_syscall_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            syscall_events: events.clone(),
            ..Default::default()
        });

        let chip = SyscallInstrsChip;

        // GPU warmup: run once to avoid cold-start overhead in timing
        let _ = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("warmup should succeed");
        scope.synchronize().await.unwrap();

        // CPU timing: synchronize, generate host traces, allocate and copy to device
        scope.synchronize().await.unwrap();
        let cpu_start = Instant::now();
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
        let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
        let cpu_duration = cpu_start.elapsed();

        // GPU timing: synchronize, copy events to device + launch kernels, synchronize
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

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }
}
