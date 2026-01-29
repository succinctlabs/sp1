//! GPU tracegen for shift chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::Opcode;
use sp1_core_machine::alu::sll::NUM_SHIFT_LEFT_COLS;
use sp1_core_machine::riscv::{ShiftLeft, ShiftRightChip};
use sp1_gpu_cudart::sys::ShiftLeftGpuEvent;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, TracegenRiscvShiftLeftKernel};
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
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("ShiftRightChip GPU tracegen not yet implemented")
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
    use sp1_gpu_cudart::TaskScope;
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
        // Generate realistic ShiftLeft events
        let events = generate_shift_left_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            shift_left_events: events.clone(),
            ..Default::default()
        });

        let chip = ShiftLeft;

        // Time CPU trace generation
        let cpu_start = Instant::now();
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
        let cpu_duration = cpu_start.elapsed();

        // Time GPU trace generation
        let gpu_start = Instant::now();
        let gpu_trace = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("should copy events to device successfully")
            .to_host()
            .expect("should copy trace to host successfully")
            .into_guts();
        let gpu_duration = gpu_start.elapsed();

        println!("ShiftLeft Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_shift_right_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ShiftRightChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
