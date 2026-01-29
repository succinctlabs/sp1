//! GPU tracegen for BitwiseChip.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::Opcode;
use sp1_core_machine::alu::bitwise::NUM_BITWISE_COLS;
use sp1_core_machine::riscv::BitwiseChip;
use sp1_gpu_cudart::sys::BitwiseGpuEvent;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope, TracegenRiscvBitwiseKernel};
use sp1_hypercube::air::MachineAir;

use crate::riscv::alu::{memory_record_to_gpu, optional_memory_record_to_gpu};
use crate::{CudaTracegenAir, F};

/// Convert Opcode to GPU opcode value for Bitwise variants.
/// GPU uses: XOR=0, OR=1, AND=2.
fn opcode_to_gpu_bitwise_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::XOR => 0,
        Opcode::OR => 1,
        Opcode::AND => 2,
        _ => 0, // Should not happen for BitwiseChip events
    }
}

impl CudaTracegenAir<F> for BitwiseChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.bitwise_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<BitwiseGpuEvent> = events
            .iter()
            .map(|(alu_event, alu_type_record)| BitwiseGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                a: alu_event.a,
                opcode: opcode_to_gpu_bitwise_variant(alu_event.opcode),
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_BITWISE_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_bitwise_kernel(),
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
    use sp1_core_machine::riscv::BitwiseChip;
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

    /// Generate random Bitwise events for testing.
    /// Tests XOR, OR, AND (and their immediate variants).
    fn generate_bitwise_events(count: usize) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xB17_FEED);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        // Test 6 combinations: XOR reg, XOR imm, OR reg, OR imm, AND reg, AND imm
        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

            // Cycle through different variants
            let variant = i % 6;
            let opcode = match variant / 2 {
                0 => Opcode::XOR,
                1 => Opcode::OR,
                _ => Opcode::AND,
            };
            let is_imm = (variant % 2) == 1;

            // Generate random operands
            let b: u64 = rng.gen();
            let c: u64 = if is_imm {
                // For immediate variants, c is a sign-extended 12-bit value
                (rng.gen::<i16>() as i64 as u64) & 0xFFF
            } else {
                rng.gen()
            };

            // Compute result based on opcode
            let a = match opcode {
                Opcode::XOR => b ^ c,
                Opcode::OR => b | c,
                Opcode::AND => b & c,
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
    async fn test_bitwise_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_bitwise_generate_trace).await.unwrap();
    }

    async fn inner_test_bitwise_generate_trace(scope: TaskScope) {
        // Generate realistic Bitwise events
        let events = generate_bitwise_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            bitwise_events: events.clone(),
            ..Default::default()
        });

        let chip = BitwiseChip;

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

        println!("Bitwise Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
    }
}
