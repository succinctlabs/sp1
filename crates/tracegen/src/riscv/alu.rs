//! GPU tracegen stubs for ALU chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_multilinear::Mle;
use slop_tensor::Tensor;
use sp1_core_machine::alu::add::NUM_ADD_COLS;
use sp1_core_machine::alu::add_sub::addi::NUM_ADDI_COLS;
use sp1_core_machine::alu::addw::NUM_ADDW_COLS;
use sp1_core_machine::riscv::{
    AddChip, AddiChip, AddwChip, DivRemChip, LtChip, MulChip, SubChip, SubwChip,
};
use sp1_gpu_cudart::sys::{AddiGpuEvent, AddGpuEvent, AddwGpuEvent, GpuMemoryAccess};
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvAddKernel, TracegenRiscvAddiKernel,
    TracegenRiscvAddwKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Convert a `MemoryRecordEnum` to a `GpuMemoryAccess`.
fn memory_record_to_gpu(record: &sp1_core_executor::events::MemoryRecordEnum) -> GpuMemoryAccess {
    let prev = record.previous_record();
    let curr = record.current_record();
    GpuMemoryAccess {
        prev_value: prev.value,
        prev_timestamp: prev.timestamp,
        current_timestamp: curr.timestamp,
    }
}

/// Convert an optional `MemoryRecordEnum` to a `GpuMemoryAccess`.
/// When the record is None (immediate mode), returns a default/zeroed GpuMemoryAccess.
fn optional_memory_record_to_gpu(
    record: Option<&sp1_core_executor::events::MemoryRecordEnum>,
) -> GpuMemoryAccess {
    match record {
        Some(r) => memory_record_to_gpu(r),
        None => GpuMemoryAccess::default(),
    }
}

impl CudaTracegenAir<F> for AddChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.add_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<AddGpuEvent> = events
            .iter()
            .map(|(alu_event, r_type_record)| AddGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_ADD_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_add_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::new(Mle::new(trace)))
    }
}

impl CudaTracegenAir<F> for AddwChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.addw_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<AddwGpuEvent> = events
            .iter()
            .map(|(alu_event, alu_type_record)| AddwGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_ADDW_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_addw_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::new(Mle::new(trace)))
    }
}

impl CudaTracegenAir<F> for AddiChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.addi_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<AddiGpuEvent> = events
            .iter()
            .map(|(alu_event, i_type_record)| AddiGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                op_a: i_type_record.op_a,
                op_b: i_type_record.op_b,
                op_c: i_type_record.op_c,
                mem_a: memory_record_to_gpu(&i_type_record.a),
                mem_b: memory_record_to_gpu(&i_type_record.b),
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_ADDI_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_addi_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::new(Mle::new(trace)))
    }
}

impl CudaTracegenAir<F> for SubChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("SubChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for SubwChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("SubwChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for MulChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("MulChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for DivRemChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("DivRemChip GPU tracegen not yet implemented")
    }
}

impl CudaTracegenAir<F> for LtChip {
    fn supports_device_main_tracegen(&self) -> bool {
        false // TODO: implement GPU tracegen
    }

    async fn generate_trace_device(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
        _scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        unimplemented!("LtChip GPU tracegen not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use slop_tensor::Tensor;
    use sp1_core_executor::{
        events::{AluEvent, MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord},
        ALUTypeRecord, ExecutionRecord, ITypeRecord, Opcode, RTypeRecord,
    };
    use sp1_core_machine::riscv::{
        AddChip, AddiChip, AddwChip, DivRemChip, LtChip, MulChip, SubChip, SubwChip,
    };
    use sp1_gpu_cudart::TaskScope;
    use sp1_hypercube::air::MachineAir;
    use std::time::Instant;

    use crate::{CudaTracegenAir, F};

    /// Generate a random memory read record for testing.
    /// Uses a base_timestamp to ensure prev_timestamp calculations don't underflow.
    fn random_read_record(
        rng: &mut StdRng,
        value: u64,
        timestamp: u64,
        base_timestamp: u64,
    ) -> MemoryRecordEnum {
        // Ensure prev_timestamp is always valid (>= base_timestamp but < timestamp)
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

    /// Generate random ADD events for testing.
    fn generate_add_events(count: usize) -> Vec<(AluEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xADD_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a base timestamp offset to avoid underflow issues
        let base_timestamp: u64 = 1000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = 0x1000 + (i as u64) * 4;

            // Generate random operands and compute result
            let b: u64 = rng.gen();
            let c: u64 = rng.gen();
            let a = b.wrapping_add(c); // ADD result

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, Opcode::ADD, a, b, c, op_a_0);

            // Create RTypeRecord with memory access records
            // Timestamps for memory accesses are offset from the instruction clock
            let record = RTypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4, base_timestamp), // Write to rd
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1, base_timestamp), // Read from rs1
                op_c: rng.gen_range(0..32),
                c: random_read_record(&mut rng, c, clk + 2, base_timestamp), // Read from rs2
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    /// Generate random ADDW events for testing.
    /// ADDW computes 32-bit addition and sign-extends the result.
    fn generate_addw_events(count: usize) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xADD0_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a base timestamp offset to avoid underflow issues
        let base_timestamp: u64 = 1000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = 0x1000 + (i as u64) * 4;

            // Generate random operands (use lower 32 bits for ADDW semantics)
            let b: u64 = rng.gen::<u32>() as u64;
            let c: u64 = rng.gen::<u32>() as u64;
            // ADDW: 32-bit add, result is sign-extended
            let result_32 = (b as u32).wrapping_add(c as u32);
            let a = result_32 as i32 as i64 as u64; // Sign-extend

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, Opcode::ADDW, a, b, c, op_a_0);

            // Randomly choose between register (is_imm=false) and immediate (is_imm=true) mode
            let is_imm = rng.gen_bool(0.5);

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
                    // Read from rs2
                },
                is_imm,
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    #[tokio::test]
    async fn test_add_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_add_generate_trace).await.unwrap();
    }

    async fn inner_test_add_generate_trace(scope: TaskScope) {
        // Generate realistic ADD events
        let events = generate_add_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            add_events: events.clone(),
            ..Default::default()
        });

        let chip = AddChip;

        // Generate CPU trace for comparison
        let trace = Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));

        // Generate GPU trace
        let gpu_trace = chip
            .generate_trace_device(&gpu_shard, &mut ExecutionRecord::default(), &scope)
            .await
            .expect("should copy events to device successfully")
            .to_host()
            .expect("should copy trace to host successfully")
            .into_guts();

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
    }

    #[tokio::test]
    async fn test_addw_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_addw_generate_trace).await.unwrap();
    }

    async fn inner_test_addw_generate_trace(scope: TaskScope) {
        // Generate realistic ADDW events
        let events = generate_addw_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            addw_events: events.clone(),
            ..Default::default()
        });

        let chip = AddwChip;

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

        println!("ADDW Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
    }

    /// Generate random ADDI events for testing.
    /// ADDI adds a register value and an immediate value.
    fn generate_addi_events(count: usize) -> Vec<(AluEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xADD1_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a base timestamp offset to avoid underflow issues
        let base_timestamp: u64 = 1000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = 0x1000 + (i as u64) * 4;

            // Generate random operands
            let b: u64 = rng.gen();
            // For ADDI, c is an immediate value (sign-extended 12-bit)
            let c: u64 = (rng.gen::<i16>() as i64 as u64) & 0xFFF;
            let a = b.wrapping_add(c); // ADDI result

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, Opcode::ADDI, a, b, c, op_a_0);

            // Create ITypeRecord with memory access records
            // For I-type, op_c is the immediate value (no memory access for it)
            let record = ITypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4, base_timestamp), // Write to rd
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1, base_timestamp), // Read from rs1
                op_c: c,                                                      // Immediate value
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    #[tokio::test]
    async fn test_addi_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_addi_generate_trace).await.unwrap();
    }

    async fn inner_test_addi_generate_trace(scope: TaskScope) {
        // Generate realistic ADDI events
        let events = generate_addi_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            addi_events: events.clone(),
            ..Default::default()
        });

        let chip = AddiChip;

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

        println!("ADDI Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events);
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_sub_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = SubChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_subw_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = SubwChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_mul_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = MulChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_divrem_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = DivRemChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "GPU tracegen not yet implemented"]
    async fn test_lt_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = LtChip;
            let record = ExecutionRecord::default();
            let mut output = ExecutionRecord::default();
            let _ = chip.generate_trace_device(&record, &mut output, &scope).await;
        })
        .await
        .unwrap();
    }
}
