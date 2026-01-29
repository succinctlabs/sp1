//! GPU tracegen for control flow chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::Opcode;
use sp1_core_machine::control_flow::{BranchChip, JalChip, JalrChip};
use sp1_core_machine::utype::{UTypeChip, NUM_UTYPE_COLS};
use sp1_gpu_cudart::sys::UTypeGpuEvent;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, TracegenRiscvUTypeKernel};
use sp1_hypercube::air::MachineAir;

use crate::riscv::alu::memory_record_to_gpu;
use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for UTypeChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.utype_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<UTypeGpuEvent> = events
            .iter()
            .map(|(utype_event, j_type_record)| UTypeGpuEvent {
                clk: utype_event.clk,
                pc: utype_event.pc,
                a: utype_event.a,
                b: utype_event.b,
                c: utype_event.c,
                is_auipc: utype_event.opcode == Opcode::AUIPC,
                op_a_0: utype_event.op_a_0,
                op_a: j_type_record.op_a,
                op_b: j_type_record.op_b,
                op_c: j_type_record.op_c,
                mem_a: memory_record_to_gpu(&j_type_record.a),
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_UTYPE_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_utype_kernel(),
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

impl CudaTracegenAir<F> for BranchChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("BranchChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for JalChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("JalChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for JalrChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("JalrChip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::{
        events::{MemoryRecordEnum, MemoryWriteRecord, UTypeEvent},
        ExecutionRecord, JTypeRecord, Opcode,
    };
    use sp1_core_machine::control_flow::{BranchChip, JalChip, JalrChip};
    use sp1_core_machine::utype::UTypeChip;
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
    use sp1_hypercube::air::MachineAir;
    use std::time::Instant;

    use crate::{CudaTracegenAir, F};

    /// Generate a random memory write record for testing.
    fn random_write_record(
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
        MemoryRecordEnum::Write(MemoryWriteRecord {
            prev_timestamp,
            prev_page_prot_record: None,
            prev_value: rng.gen(),
            timestamp,
            value,
        })
    }

    /// Generate random UType events (LUI and AUIPC) for testing.
    fn generate_utype_events(count: usize) -> Vec<(UTypeEvent, JTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xB1FE_BEEF);
        let mut events = Vec::with_capacity(count);

        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;

            // Alternate between LUI and AUIPC, with some op_a_0 cases
            let variant = i % 5;
            let opcode = if variant < 2 { Opcode::LUI } else { Opcode::AUIPC };
            let op_a_0 = variant == 4;

            // Generate immediate value (b is the upper immediate, c is typically 0 for UType)
            // In RISC-V, LUI/AUIPC use a 20-bit immediate shifted left by 12
            let imm_20: u64 = rng.gen_range(0..(1u64 << 20));
            let b: u64 = imm_20 << 12; // 20-bit immediate << 12
            let c: u64 = 0; // c is typically 0 for U-type

            // Compute result
            let a = if op_a_0 {
                0
            } else {
                match opcode {
                    Opcode::LUI => b,        // LUI: result = immediate
                    Opcode::AUIPC => pc + b, // AUIPC: result = PC + immediate
                    _ => unreachable!(),
                }
            };

            let op_a: u8 = if op_a_0 { 0 } else { rng.gen_range(1..32) };

            let event = UTypeEvent { clk, pc, opcode, a, b, c, op_a_0 };

            let record = JTypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4, base_timestamp),
                op_b: b,
                op_c: c,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    #[tokio::test]
    async fn test_utype_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_utype_generate_trace).await.unwrap();
    }

    async fn inner_test_utype_generate_trace(scope: TaskScope) {
        // Generate realistic UType events
        let events = generate_utype_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            utype_events: events.clone(),
            ..Default::default()
        });

        let chip = UTypeChip;

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

        println!("UType Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_branch_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = BranchChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_jal_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = JalChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_jalr_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = JalrChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
