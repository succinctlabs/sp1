//! GPU tracegen stubs for ALU chips.

use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_executor::Opcode;
use sp1_core_machine::alu::add::NUM_ADD_COLS;
use sp1_core_machine::alu::add_sub::addi::NUM_ADDI_COLS;
use sp1_core_machine::alu::add_sub::sub::NUM_SUB_COLS;
use sp1_core_machine::alu::add_sub::subw::NUM_SUBW_COLS;
use sp1_core_machine::alu::addw::NUM_ADDW_COLS;
use sp1_core_machine::alu::divrem::NUM_DIVREM_COLS;
use sp1_core_machine::alu::lt::NUM_LT_COLS;
use sp1_core_machine::alu::mul::NUM_MUL_COLS;
use sp1_core_machine::riscv::{
    AddChip, AddiChip, AddwChip, DivRemChip, LtChip, MulChip, SubChip, SubwChip,
};
use sp1_gpu_cudart::sys::{
    AddGpuEvent, AddiGpuEvent, AddwGpuEvent, DivRemGpuEvent, GpuMemoryAccess, LtGpuEvent,
    MulGpuEvent, SubGpuEvent, SubwGpuEvent,
};
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvAddKernel, TracegenRiscvAddiKernel,
    TracegenRiscvAddwKernel, TracegenRiscvDivRemKernel, TracegenRiscvLtKernel,
    TracegenRiscvMulKernel, TracegenRiscvSubKernel, TracegenRiscvSubwKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Convert a `MemoryRecordEnum` to a `GpuMemoryAccess`.
pub(crate) fn memory_record_to_gpu(
    record: &sp1_core_executor::events::MemoryRecordEnum,
) -> GpuMemoryAccess {
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
pub(crate) fn optional_memory_record_to_gpu(
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

        Ok(DeviceMle::from(trace))
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

        tracing::warn!("generate trace w device");

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

        Ok(DeviceMle::from(trace))
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
        tracing::warn!("generate trace device");
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

        Ok(DeviceMle::from(trace))
    }
}

impl CudaTracegenAir<F> for SubChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.sub_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        // SubGpuEvent is a type alias for AddGpuEvent since both use RTypeRecord
        let gpu_events: Vec<SubGpuEvent> = events
            .iter()
            .map(|(alu_event, r_type_record)| SubGpuEvent {
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_SUB_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_sub_kernel(),
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

impl CudaTracegenAir<F> for SubwChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.subw_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        // SubwGpuEvent is a type alias for AddGpuEvent since SubwChip uses RTypeRecord
        let gpu_events: Vec<SubwGpuEvent> = events
            .iter()
            .map(|(alu_event, r_type_record)| SubwGpuEvent {
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_SUBW_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_subw_kernel(),
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

/// Convert Opcode to GPU opcode value for MUL variants.
/// GPU uses: MUL=0, MULH=1, MULHU=2, MULHSU=3, MULW=4
fn opcode_to_gpu_mul_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::MUL => 0,
        Opcode::MULH => 1,
        Opcode::MULHU => 2,
        Opcode::MULHSU => 3,
        Opcode::MULW => 4,
        _ => 0, // Should not happen for MulChip events
    }
}

/// Convert Opcode to GPU opcode value for Lt variants.
/// GPU uses: SLT=0 (signed), SLTU=1 (unsigned)
/// Note: SLTI and SLTIU share opcodes with SLT/SLTU (distinguished by is_imm flag).
fn opcode_to_gpu_lt_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::SLT => 0,  // Signed comparison
        Opcode::SLTU => 1, // Unsigned comparison
        _ => 0,            // Should not happen for LtChip events
    }
}

impl CudaTracegenAir<F> for MulChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.mul_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<MulGpuEvent> = events
            .iter()
            .map(|(alu_event, r_type_record)| MulGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                a: alu_event.a,
                opcode: opcode_to_gpu_mul_variant(alu_event.opcode),
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_MUL_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_mul_kernel(),
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

/// Convert Opcode to GPU opcode value for DivRem variants.
/// GPU uses: DIV=0, DIVU=1, REM=2, REMU=3, DIVW=4, DIVUW=5, REMW=6, REMUW=7
fn opcode_to_gpu_divrem_variant(opcode: Opcode) -> u8 {
    match opcode {
        Opcode::DIV => 0,
        Opcode::DIVU => 1,
        Opcode::REM => 2,
        Opcode::REMU => 3,
        Opcode::DIVW => 4,
        Opcode::DIVUW => 5,
        Opcode::REMW => 6,
        Opcode::REMUW => 7,
        _ => 0, // Should not happen for DivRemChip events
    }
}

impl CudaTracegenAir<F> for DivRemChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.divrem_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<DivRemGpuEvent> = events
            .iter()
            .map(|(alu_event, r_type_record)| DivRemGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                a: alu_event.a,
                opcode: opcode_to_gpu_divrem_variant(alu_event.opcode),
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_DIVREM_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_divrem_kernel(),
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

impl CudaTracegenAir<F> for LtChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.lt_events;
        let events_len = events.len();

        // Convert Rust events to GPU-compatible format
        let gpu_events: Vec<LtGpuEvent> = events
            .iter()
            .map(|(alu_event, alu_type_record)| LtGpuEvent {
                clk: alu_event.clk,
                pc: alu_event.pc,
                b: alu_event.b,
                c: alu_event.c,
                a: alu_event.a,
                opcode: opcode_to_gpu_lt_variant(alu_event.opcode),
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
        let mut trace = Tensor::<F, TaskScope>::zeros_in([NUM_LT_COLS, height], scope.clone());

        // Launch kernel
        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events_len);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_lt_kernel(),
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
        events::{AluEvent, MemoryReadRecord, MemoryRecordEnum, MemoryWriteRecord},
        ALUTypeRecord, ExecutionRecord, ITypeRecord, Opcode, RTypeRecord,
    };
    use sp1_core_machine::riscv::{
        AddChip, AddiChip, AddwChip, DivRemChip, LtChip, MulChip, SubChip, SubwChip,
    };
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
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
    ///
    /// Uses large PC and clock values that span multiple 16-bit limbs to catch
    /// encoding bugs (e.g., using wrong limb sizes like 22-bit instead of 16-bit).
    fn generate_add_events(count: usize) -> Vec<(AluEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xADD_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        // This ensures we catch bugs in timestamp/clock encoding
        let base_timestamp: u64 = 0x1_0000_1000; // Bits set in both high and low 16-bit regions

        // Start PC at a large value that spans multiple 16-bit limbs
        // This ensures we catch bugs like using 22-bit limbs instead of 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000; // Bits set across all three 16-bit limbs

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

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
    ///
    /// Uses large PC and clock values that span multiple 16-bit limbs to catch encoding bugs.
    fn generate_addw_events(count: usize) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xADD0_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

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

        println!("ADD Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
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

        println!("ADDW Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random ADDI events for testing.
    /// ADDI adds a register value and an immediate value.
    fn generate_addi_events(count: usize) -> Vec<(AluEvent, ITypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xADD1_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

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
                op_c: c,                                                     // Immediate value
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

        println!("ADDI Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random SUB events for testing.
    fn generate_sub_events(count: usize) -> Vec<(AluEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x50B_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

            // Generate random operands and compute result
            let b: u64 = rng.gen();
            let c: u64 = rng.gen();
            let a = b.wrapping_sub(c); // SUB result

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, Opcode::SUB, a, b, c, op_a_0);

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

    #[tokio::test]
    async fn test_sub_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_sub_generate_trace).await.unwrap();
    }

    async fn inner_test_sub_generate_trace(scope: TaskScope) {
        // Generate realistic SUB events
        let events = generate_sub_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            sub_events: events.clone(),
            ..Default::default()
        });

        let chip = SubChip;

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

        println!("SUB Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random SUBW events for testing.
    /// SUBW computes 32-bit subtraction and sign-extends the result.
    fn generate_subw_events(count: usize) -> Vec<(AluEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x50B0_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

            // Generate random operands (use lower 32 bits for SUBW semantics)
            let b: u64 = rng.gen::<u32>() as u64;
            let c: u64 = rng.gen::<u32>() as u64;
            // SUBW: 32-bit sub, result is sign-extended
            let result_32 = (b as u32).wrapping_sub(c as u32);
            let a = result_32 as i32 as i64 as u64; // Sign-extend

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, Opcode::SUBW, a, b, c, op_a_0);

            // Create RTypeRecord with memory access records
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

    #[tokio::test]
    async fn test_subw_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_subw_generate_trace).await.unwrap();
    }

    async fn inner_test_subw_generate_trace(scope: TaskScope) {
        // Generate realistic SUBW events
        let events = generate_subw_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            subw_events: events.clone(),
            ..Default::default()
        });

        let chip = SubwChip;

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

        println!("SUBW Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random MUL events for testing.
    /// Tests all MUL variants: MUL, MULH, MULHU, MULHSU, MULW.
    fn generate_mul_events(count: usize) -> Vec<(AluEvent, RTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0xABC_0100);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        // Opcodes to test
        let opcodes = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU, Opcode::MULW];

        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

            // Cycle through different opcodes
            let opcode = opcodes[i % opcodes.len()];

            // Generate random operands
            let b: u64 = rng.gen();
            let c: u64 = rng.gen();

            // Compute result based on opcode
            let a = match opcode {
                Opcode::MUL => {
                    // Lower 64 bits of 64x64 multiplication
                    b.wrapping_mul(c)
                }
                Opcode::MULH => {
                    // Upper 64 bits of signed 64x64 multiplication
                    let b_signed = b as i64;
                    let c_signed = c as i64;
                    let result = (b_signed as i128) * (c_signed as i128);
                    (result >> 64) as u64
                }
                Opcode::MULHU => {
                    // Upper 64 bits of unsigned 64x64 multiplication
                    let result = (b as u128) * (c as u128);
                    (result >> 64) as u64
                }
                Opcode::MULHSU => {
                    // Upper 64 bits of signed-unsigned 64x64 multiplication
                    let b_signed = b as i64;
                    let result = (b_signed as i128) * (c as i128);
                    (result >> 64) as u64
                }
                Opcode::MULW => {
                    // 32-bit signed multiplication, result sign-extended
                    let b32 = b as i32;
                    let c32 = c as i32;
                    let result = b32.wrapping_mul(c32);
                    result as i64 as u64
                }
                _ => 0,
            };

            // Random destination register (1-31, not x0)
            let op_a: u8 = rng.gen_range(1..32);
            let op_a_0 = false;

            let event = AluEvent::new(clk, pc, opcode, a, b, c, op_a_0);

            // Create RTypeRecord with memory access records
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

    #[tokio::test]
    async fn test_mul_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_mul_generate_trace).await.unwrap();
    }

    async fn inner_test_mul_generate_trace(scope: TaskScope) {
        // Generate realistic MUL events
        let events = generate_mul_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            mul_events: events.clone(),
            ..Default::default()
        });

        let chip = MulChip;

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

        println!("MUL Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random Lt events for testing.
    /// Tests SLT (signed) and SLTU (unsigned) comparisons.
    /// Note: SLTI and SLTIU share opcodes with SLT/SLTU (distinguished by is_imm flag).
    fn generate_lt_events(count: usize) -> Vec<(AluEvent, ALUTypeRecord)> {
        let mut rng = StdRng::seed_from_u64(0x5171_BEEF);
        let mut events = Vec::with_capacity(count);

        // Start with a large base timestamp that spans multiple 16-bit limbs
        let base_timestamp: u64 = 0x1_0000_1000;

        // Start PC at a large value that spans multiple 16-bit limbs
        let base_pc: u64 = 0x8000_4000_2000;

        // Test 4 combinations: SLT register, SLTU register, SLT imm (SLTI), SLTU imm (SLTIU)
        for i in 0..count {
            // Clock increments by 8 per instruction
            let clk = base_timestamp + (i as u64) * 8;
            // PC increments by 4 per instruction
            let pc = base_pc + (i as u64) * 4;

            // Cycle through different variants: SLT reg, SLTU reg, SLT imm, SLTU imm
            let variant = i % 4;
            let opcode = if variant < 2 { Opcode::SLT } else { Opcode::SLTU };
            let is_signed = variant < 2;
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
            let a = if is_signed {
                // Signed comparison
                if (b as i64) < (c as i64) {
                    1
                } else {
                    0
                }
            } else {
                // Unsigned comparison
                if b < c {
                    1
                } else {
                    0
                }
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
    async fn test_lt_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_lt_generate_trace).await.unwrap();
    }

    async fn inner_test_lt_generate_trace(scope: TaskScope) {
        // Generate realistic Lt events
        let events = generate_lt_events(1000);

        // Create two identical records - one for CPU, one for GPU
        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            lt_events: events.clone(),
            ..Default::default()
        });

        let chip = LtChip;

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

        println!("LT Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }

    /// Generate random DivRem events for testing.
    /// Tests all 8 DivRem variants: DIV, DIVU, REM, REMU, DIVW, DIVUW, REMW, REMUW.
    /// Includes edge cases: division by zero and signed overflow.
    fn generate_divrem_events(count: usize) -> Vec<(AluEvent, RTypeRecord)> {
        use sp1_core_executor::{get_quotient_and_remainder, is_word_operation};

        let mut rng = StdRng::seed_from_u64(0xD1F_BEEF);
        let mut events = Vec::with_capacity(count);

        let base_timestamp: u64 = 0x1_0000_1000;
        let base_pc: u64 = 0x8000_4000_2000;

        let opcodes = [
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
            Opcode::DIVW,
            Opcode::DIVUW,
            Opcode::REMW,
            Opcode::REMUW,
        ];

        for i in 0..count {
            let clk = base_timestamp + (i as u64) * 8;
            let pc = base_pc + (i as u64) * 4;

            let opcode = opcodes[i % opcodes.len()];

            // Generate b and c, with some edge cases injected
            let (b, c) = match i % 40 {
                // Division by zero
                0..4 => (rng.gen::<u64>(), 0u64),
                // Signed overflow: -2^63 / -1 (for DIV/REM)
                4 => (i64::MIN as u64, u64::MAX), // -1 as u64
                // Signed word overflow: -2^31 / -1 (for DIVW/REMW)
                5 => (i32::MIN as u32 as u64, u32::MAX as u64), // -1 as u32 stored in u64
                // Normal random cases
                _ => (rng.gen::<u64>(), rng.gen_range(1..u64::MAX)),
            };

            let (quotient, remainder) = get_quotient_and_remainder(b, c, opcode);

            // Result: a = quotient for DIV/DIVU/DIVW/DIVUW, a = remainder for REM/REMU/REMW/REMUW
            let a = match opcode {
                Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW => {
                    if is_word_operation(opcode) {
                        (quotient as i32) as i64 as u64
                    } else {
                        quotient
                    }
                }
                _ => {
                    if is_word_operation(opcode) {
                        (remainder as i32) as i64 as u64
                    } else {
                        remainder
                    }
                }
            };

            let op_a: u8 = rng.gen_range(1..32);

            let event = AluEvent::new(clk, pc, opcode, a, b, c, false);

            let record = RTypeRecord {
                op_a,
                a: random_write_record(&mut rng, a, clk + 4, base_timestamp),
                op_b: rng.gen_range(0..32),
                b: random_read_record(&mut rng, b, clk + 1, base_timestamp),
                op_c: rng.gen_range(0..32),
                c: random_read_record(&mut rng, c, clk + 2, base_timestamp),
                is_untrusted: false,
            };

            events.push((event, record));
        }

        events
    }

    #[tokio::test]
    async fn test_divrem_generate_trace() {
        sp1_gpu_cudart::spawn(inner_test_divrem_generate_trace).await.unwrap();
    }

    async fn inner_test_divrem_generate_trace(scope: TaskScope) {
        let events = generate_divrem_events(1000);

        let [shard, gpu_shard] = core::array::from_fn(|_| ExecutionRecord {
            divrem_events: events.clone(),
            ..Default::default()
        });

        let chip = DivRemChip;

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

        println!("DIVREM Tracegen timing (1000 events):");
        println!("  CPU: {:?}", cpu_duration);
        println!("  GPU: {:?}", gpu_duration);
        println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

        // Compare traces
        crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
    }
}
