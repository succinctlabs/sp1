//! GPU tracegen for lookup table chips (ByteChip, RangeChip).

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::ByteOpcode;
use sp1_core_machine::bytes::columns::NUM_BYTE_MULT_COLS;
use sp1_core_machine::bytes::trace::NUM_ROWS as BYTE_NUM_ROWS;
use sp1_core_machine::range::columns::NUM_RANGE_MULT_COLS;
use sp1_core_machine::range::trace::NUM_ROWS as RANGE_NUM_ROWS;
use sp1_core_machine::range::RangeChip;
use sp1_core_machine::riscv::ByteChip;
use sp1_gpu_cudart::sys::{ByteLookupGpuEntry, RangeLookupGpuEntry};
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvByteLookupKernel, TracegenRiscvRangeLookupKernel,
};

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for ByteChip<F> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Convert HashMap entries to GPU-compatible flat array
        let gpu_entries: Vec<ByteLookupGpuEntry> = input
            .byte_lookups
            .iter()
            .filter(|(lookup, _)| lookup.opcode != ByteOpcode::Range)
            .map(|(lookup, &mult)| ByteLookupGpuEntry {
                row: ((lookup.b as u32) << 8) + lookup.c as u32,
                opcode: lookup.opcode as u32,
                mult: mult as u32,
            })
            .collect();
        let entries_len = gpu_entries.len();

        // Copy entries to device
        let entries_device = {
            let mut buf = Buffer::try_with_capacity_in(gpu_entries.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&gpu_entries)?;
            buf
        };

        // Allocate zero-initialized trace (6 columns x 65536 rows)
        let height = BYTE_NUM_ROWS;
        let mut trace =
            Tensor::<F, TaskScope>::zeros_in([NUM_BYTE_MULT_COLS, height], scope.clone());

        // Launch scatter kernel - grid covers entries, not rows
        if entries_len > 0 {
            unsafe {
                const BLOCK_DIM: usize = 256;
                let grid_dim = entries_len.div_ceil(BLOCK_DIM);

                let kernel_args =
                    args!(trace.as_mut_ptr(), height, entries_device.as_ptr(), entries_len);

                scope
                    .launch_kernel(
                        TaskScope::tracegen_riscv_byte_lookup_kernel(),
                        grid_dim,
                        BLOCK_DIM,
                        &kernel_args,
                        0,
                    )
                    .unwrap();
            }
        }

        Ok(DeviceMle::from(trace))
    }
}

impl CudaTracegenAir<F> for RangeChip<F> {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Convert HashMap entries to GPU-compatible flat array
        let gpu_entries: Vec<RangeLookupGpuEntry> = input
            .byte_lookups
            .iter()
            .filter(|(lookup, _)| lookup.opcode == ByteOpcode::Range)
            .map(|(lookup, &mult)| RangeLookupGpuEntry {
                row: (lookup.a as u32) + (1u32 << lookup.b),
                mult: mult as u32,
            })
            .collect();
        let entries_len = gpu_entries.len();

        // Copy entries to device
        let entries_device = {
            let mut buf = Buffer::try_with_capacity_in(gpu_entries.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&gpu_entries)?;
            buf
        };

        // Allocate zero-initialized trace (1 column x 131072 rows)
        let height = RANGE_NUM_ROWS;
        let mut trace =
            Tensor::<F, TaskScope>::zeros_in([NUM_RANGE_MULT_COLS, height], scope.clone());

        // Launch scatter kernel - grid covers entries, not rows
        if entries_len > 0 {
            unsafe {
                const BLOCK_DIM: usize = 256;
                let grid_dim = entries_len.div_ceil(BLOCK_DIM);

                let kernel_args =
                    args!(trace.as_mut_ptr(), height, entries_device.as_ptr(), entries_len);

                scope
                    .launch_kernel(
                        TaskScope::tracegen_riscv_range_lookup_kernel(),
                        grid_dim,
                        BLOCK_DIM,
                        &kernel_args,
                        0,
                    )
                    .unwrap();
            }
        }

        Ok(DeviceMle::from(trace))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use slop_tensor::Tensor;
    use sp1_core_executor::events::{ByteLookupEvent, ByteRecord};
    use sp1_core_executor::{ByteOpcode, ExecutionRecord};
    use sp1_core_machine::range::RangeChip;
    use sp1_core_machine::riscv::ByteChip;
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    /// Generate an ExecutionRecord with realistic byte lookup events.
    fn generate_byte_lookup_record(num_entries: usize) -> ExecutionRecord {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut record = ExecutionRecord::default();

        let byte_opcodes = [
            ByteOpcode::AND,
            ByteOpcode::OR,
            ByteOpcode::XOR,
            ByteOpcode::U8Range,
            ByteOpcode::LTU,
            ByteOpcode::MSB,
        ];

        for _ in 0..num_entries {
            let opcode = byte_opcodes[rng.gen_range(0..byte_opcodes.len())];
            let b = rng.gen::<u8>();
            let c = rng.gen::<u8>();
            let event = ByteLookupEvent {
                opcode,
                a: 0, // unused for byte operations
                b,
                c,
            };
            let count = rng.gen_range(1..=10usize);
            for _ in 0..count {
                record.add_byte_lookup_event(event);
            }
        }

        record
    }

    /// Generate an ExecutionRecord with realistic range lookup events.
    fn generate_range_lookup_record(num_entries: usize) -> ExecutionRecord {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut record = ExecutionRecord::default();

        for _ in 0..num_entries {
            let bits: u8 = rng.gen_range(0..=16);
            let max_val = if bits == 0 { 1u32 } else { 1u32 << bits };
            let a = rng.gen_range(0..max_val) as u16;
            let event = ByteLookupEvent { opcode: ByteOpcode::Range, a, b: bits, c: 0 };
            let count = rng.gen_range(1..=10usize);
            for _ in 0..count {
                record.add_byte_lookup_event(event);
            }
        }

        record
    }

    #[tokio::test]
    async fn test_byte_lookup_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_byte_lookup_generate_trace).await.unwrap();
    }

    async fn inner_test_byte_lookup_generate_trace(scope: TaskScope) {
        let shard = generate_byte_lookup_record(5000);
        let gpu_shard = shard.clone();
        let num_entries = shard.byte_lookups.len();

        let chip = ByteChip::<F>::default();

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
            .expect("should copy entries to device successfully");
        scope.synchronize().await.unwrap();
        let gpu_duration = gpu_start.elapsed();

        let gpu_trace =
            gpu_device_mle.to_host().expect("should copy trace to host successfully").into_guts();

        println!("ByteChip Tracegen timing ({num_entries} unique entries):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces - ByteChip has no "events" per row, use empty slice
        let empty: Vec<()> = vec![];
        crate::tests::test_traces_eq(&trace, &gpu_trace, &empty, false);
    }

    #[tokio::test]
    async fn test_range_lookup_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_range_lookup_generate_trace).await.unwrap();
    }

    async fn inner_test_range_lookup_generate_trace(scope: TaskScope) {
        let shard = generate_range_lookup_record(5000);
        let gpu_shard = shard.clone();
        let num_entries = shard.byte_lookups.len();

        let chip = RangeChip::<F>::default();

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
            .expect("should copy entries to device successfully");
        scope.synchronize().await.unwrap();
        let gpu_duration = gpu_start.elapsed();

        let gpu_trace =
            gpu_device_mle.to_host().expect("should copy trace to host successfully").into_guts();

        println!("RangeChip Tracegen timing ({num_entries} unique entries):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces - RangeChip has no "events" per row, use empty slice
        let empty: Vec<()> = vec![];
        crate::tests::test_traces_eq(&trace, &gpu_trace, &empty, false);
    }
}
