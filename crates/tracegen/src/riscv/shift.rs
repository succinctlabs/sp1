//! GPU tracegen for shift chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::Opcode;
use sp1_core_machine::alu::sll::NUM_SHIFT_LEFT_COLS;
use sp1_core_machine::alu::sr::NUM_SHIFT_RIGHT_COLS;
use sp1_core_machine::riscv::{ShiftLeft, ShiftRightChip};
use sp1_gpu_cudart::sys::{ShiftLeftGpuEvent, ShiftRightGpuEvent};
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvShiftLeftKernel, TracegenRiscvShiftRightKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::riscv::alu::{memory_record_to_gpu, optional_memory_record_to_gpu};
use crate::{CudaTracegenAir, F};

/// Convert Opcode to GPU opcode value for ShiftLeft variants.
/// GPU uses: SLL=0, SLLW=1.
fn opcode_to_gpu_shift_left_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::SLL => 0,
        Opcode::SLLW => 1,
        _ => 0, // Should not happen for ShiftLeft events
    }
}

/// Convert Opcode to GPU opcode value for ShiftRight variants.
/// GPU uses: SRL=0, SRA=1, SRLW=2, SRAW=3.
fn opcode_to_gpu_shift_right_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::SRL => 0,
        Opcode::SRA => 1,
        Opcode::SRLW => 2,
        Opcode::SRAW => 3,
        _ => 0, // Should not happen for ShiftRight events
    }
}

impl CudaTracegenAir<F> for ShiftLeft {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.shift_left_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<ShiftLeftGpuEvent> = events
            .iter()
            .map(|(alu_event, alu_type_record)| ShiftLeftGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                a: alu_event.a,
                opcode: opcode_to_gpu_shift_left_variant(alu_event.opcode),
                op_a: alu_type_record.op_a,
                op_b: alu_type_record.op_b,
                op_c: alu_type_record.op_c,
                is_imm: alu_type_record.is_imm,
                mem_a: memory_record_to_gpu(&alu_type_record.a),
                mem_b: memory_record_to_gpu(&alu_type_record.b),
                mem_c: optional_memory_record_to_gpu(alu_type_record.c.as_ref()),
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
            Tensor::<F, TaskScope>::zeros_in([NUM_SHIFT_LEFT_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_shift_left_kernel(),
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

impl CudaTracegenAir<F> for ShiftRightChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.shift_right_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<ShiftRightGpuEvent> = events
            .iter()
            .map(|(alu_event, alu_type_record)| ShiftRightGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                a: alu_event.a,
                opcode: opcode_to_gpu_shift_right_variant(alu_event.opcode),
                op_a: alu_type_record.op_a,
                op_b: alu_type_record.op_b,
                op_c: alu_type_record.op_c,
                is_imm: alu_type_record.is_imm,
                mem_a: memory_record_to_gpu(&alu_type_record.a),
                mem_b: memory_record_to_gpu(&alu_type_record.b),
                mem_c: optional_memory_record_to_gpu(alu_type_record.c.as_ref()),
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
            Tensor::<F, TaskScope>::zeros_in([NUM_SHIFT_RIGHT_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_shift_right_kernel(),
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
    use std::time::Instant;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::events::{
        AluEvent, MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord,
    };
    use sp1_core_executor::{ALUTypeRecord, ExecutionRecord, Opcode};
    use sp1_core_machine::riscv::{ShiftLeft, ShiftRightChip};
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
    use sp1_hypercube::air::MachineAir;

    use crate::CudaTracegenAir;
    use crate::F;

    /// Create a random memory read record for testing.
    fn random_read_record(
        rng: &mut StdRng,
        value: u64,
        timestamp: u64,
        base_timestamp: u64,
    ) -> MemoryRecordEnum {
        let prev_timestamp = if timestamp > base_timestamp {
            base_timestamp + rng.gen_range(0..(timestamp - base_timestamp))
        } else {
            timestamp.saturating_sub(1)
        };
        MemoryRecordEnum::Read(MemoryReadRecord {
            value,
            timestamp,
            prev_timestamp,
            prev_page_prot_record: None,
        })
    }

    /// Create a random memory write record for testing.
    fn random_write_record(
        rng: &mut StdRng,
        value: u64,
        timestamp: u64,
        base_timestamp: u64,
    ) -> MemoryRecordEnum {
        let prev_timestamp = if timestamp > base_timestamp {
            base_timestamp + rng.gen_range(0..(timestamp - base_timestamp))
        } else {
            timestamp.saturating_sub(1)
        };
        MemoryRecordEnum::Write(MemoryWriteRecord {
            prev_value: rng.gen(),
            prev_timestamp,
            prev_page_prot_record: None,
            timestamp,
            value,
        })
    }

    /// Generate random ShiftLeft events for testing.
    /// Tests SLL (64-bit) and SLLW (32-bit with sign extension).
    fn generate_shift_left_events(count: usize) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5EEDFEED);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        // Test 4 combinations: SLL reg, SLL imm, SLLW reg, SLLW imm
        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

            // Cycle through different variants
            let variant = i % 4;
            let opcode = if variant < 2 { Opcode::SLL } else { Opcode::SLLW };
            let is_imm = (variant % 2) == 1;

            // Generate random operands
            let b: u64 = rng.gen();
            // Shift amount: 0-63 for SLL, 0-31 for SLLW
            let max_shift = if opcode == Opcode::SLL { 64 } else { 32 };
            let shift_amount: u64 = rng.gen_range(0..max_shift);
            let c: u64 = shift_amount;

            // Compute result based on opcode
            let a = match opcode {
                Opcode::SLL => b << (c & 0x3F), // 64-bit shift
                Opcode::SLLW => {
                    // 32-bit shift with sign extension
                    let result_32 = (b as u32).wrapping_shl((c & 0x1F) as u32);
                    (result_32 as i32) as i64 as u64
                }
                _ => 0,
            };

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, opcode, a, b, c, op_a_0);

            // Create ALUTypeRecord with memory access records
            let record = ALUTypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4, base_timestamp), // Write to rd
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1, base_timestamp), // Read from rs1
                op_c: c,
                c: if is_imm {
                    None // Immediate mode - no register read
                } else {
                    Some(random_read_record(&mut rng, c, clk + 2, base_timestamp))
                },
                is_imm,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    #[tokio::test]
    async fn test_shift_left_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_shift_left_generate_trace).await.unwrap();
    }

    async fn inner_test_shift_left_generate_trace(scope: TaskScope) {
        let events = generate_shift_left_events(1000);

        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            shift_left_events: events.clone(),
            ..Default::default()
        });

        let chip = ShiftLeft;

        // GPU warmup
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

        println!("ShiftLeft Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random ShiftRight events for testing.
    /// Tests SRL, SRA (64-bit) and SRLW, SRAW (32-bit with sign extension).
    fn generate_shift_right_events(count: usize) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5F1F7B16);
        let mut events = Vec::with_capacity(count);

        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        // Test 8 combinations: SRL reg, SRL imm, SRA reg, SRA imm, SRLW reg, SRLW imm, SRAW reg, SRAW imm
        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;

            let variant = i % 8;
            let opcode = match variant / 2 {
                0 => Opcode::SRL,
                1 => Opcode::SRA,
                2 => Opcode::SRLW,
                3 => Opcode::SRAW,
                _ => unreachable!(),
            };
            let is_imm = (variant % 2) == 1;
            let is_word = matches!(opcode, Opcode::SRLW | Opcode::SRAW);

            let b: u64 = rng.gen();
            let max_shift = if is_word { 32 } else { 64 };
            let shift_amount: u64 = rng.gen_range(0..max_shift);
            let c: u64 = shift_amount;

            let a = match opcode {
                Opcode::SRL => b >> (c & 0x3F),
                Opcode::SRA => ((b as i64) >> (c & 0x3F)) as u64,
                Opcode::SRLW => {
                    let result_32 = (b as u32) >> (c & 0x1F) as u32;
                    (result_32 as i32) as i64 as u64
                }
                Opcode::SRAW => {
                    let result_32 = ((b as u32 as i32) >> (c & 0x1F) as u32) as u32;
                    (result_32 as i32) as i64 as u64
                }
                _ => 0,
            };

            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, opcode, a, b, c, op_a_0);

            let record = ALUTypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4, base_timestamp),
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1, base_timestamp),
                op_c: c,
                c: if is_imm {
                    None
                } else {
                    Some(random_read_record(&mut rng, c, clk + 2, base_timestamp))
                },
                is_imm,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    #[tokio::test]
    async fn test_shift_right_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_shift_right_generate_trace).await.unwrap();
    }

    async fn inner_test_shift_right_generate_trace(scope: TaskScope) {
        let events = generate_shift_right_events(1000);

        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            shift_right_events: events.clone(),
            ..Default::default()
        });

        let chip = ShiftRightChip;

        // GPU warmup
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

        println!("ShiftRight Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }
}
