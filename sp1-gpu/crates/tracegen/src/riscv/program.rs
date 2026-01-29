//! GPU tracegen for ProgramChip.
//!
//! ProgramChip has two traces:
//! 1. Preprocessed trace (16 columns): PC[3] + InstructionCols (opcode, op_a, op_b[4], op_c[4],
//!    op_a_0, imm_b, imm_c) - one row per instruction.
//! 2. Main trace (1 column): multiplicity count per instruction.

use std::collections::HashMap;

use slop_air::BaseAir;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_core_machine::riscv::ProgramChip;
use sp1_gpu_cudart::sys::ProgramGpuInstruction;
use sp1_gpu_cudart::{
    args, DeviceMle, TaskScope, TracegenRiscvProgramKernel, TracegenRiscvProgramPreprocessedKernel,
};
use sp1_hypercube::air::MachineAir;

use crate::{CudaTracegenAir, F};

/// Number of preprocessed columns for ProgramChip.
const NUM_PROGRAM_PREPROCESSED_COLS: usize =
    std::mem::size_of::<sp1_core_machine::program::ProgramPreprocessedCols<u8>>();

impl CudaTracegenAir<F> for ProgramChip {
    fn supports_device_preprocessed_tracegen(&self) -> bool {
        true
    }

    async fn generate_preprocessed_trace_device(
        &self,
        program: &Self::Program,
        scope: &TaskScope,
    ) -> Result<Option<DeviceMle<F>>, CopyError> {
        let nb_instructions = program.instructions.len();
        if nb_instructions == 0 {
            return Ok(None);
        }

        // Convert instructions to GPU-friendly format.
        let gpu_instructions: Vec<ProgramGpuInstruction> = program
            .instructions
            .iter()
            .map(|instr| ProgramGpuInstruction {
                opcode: instr.opcode as u32,
                op_a: instr.op_a as u32,
                op_b: instr.op_b,
                op_c: instr.op_c,
                op_a_0: u32::from(instr.op_a == 0), // Register::X0 = 0
                imm_b: u32::from(instr.imm_b),
                imm_c: u32::from(instr.imm_c),
            })
            .collect();

        // Copy instructions to device.
        let instrs_device = {
            let mut buf =
                Buffer::try_with_capacity_in(gpu_instructions.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&gpu_instructions)?;
            buf
        };

        let width = NUM_PROGRAM_PREPROCESSED_COLS;
        let height = MachineAir::<F>::preprocessed_num_rows(self, program)
            .expect("preprocessed_num_rows should be Some");

        let mut trace = Tensor::<F, TaskScope>::zeros_in([width, height], scope.clone());

        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let pc_base = program.pc_base;
            let kernel_args =
                args!(trace.as_mut_ptr(), height, instrs_device.as_ptr(), nb_instructions, pc_base);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_program_preprocessed_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &kernel_args,
                    0,
                )
                .unwrap();
        }

        Ok(Some(DeviceMle::from(trace)))
    }

    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        // Collect instruction execution counts from all CPU events.
        let mut instruction_counts: HashMap<u64, u32> = HashMap::new();

        macro_rules! count_events {
            ($events:expr) => {
                for event in $events.iter() {
                    let pc = event.0.pc;
                    *instruction_counts.entry(pc).or_insert(0) += 1;
                }
            };
        }

        count_events!(input.add_events);
        count_events!(input.addw_events);
        count_events!(input.addi_events);
        count_events!(input.sub_events);
        count_events!(input.subw_events);
        count_events!(input.bitwise_events);
        count_events!(input.mul_events);
        count_events!(input.divrem_events);
        count_events!(input.lt_events);
        count_events!(input.shift_left_events);
        count_events!(input.shift_right_events);
        count_events!(input.branch_events);
        count_events!(input.memory_load_byte_events);
        count_events!(input.memory_load_half_events);
        count_events!(input.memory_load_word_events);
        count_events!(input.memory_load_x0_events);
        count_events!(input.memory_load_double_events);
        count_events!(input.memory_store_byte_events);
        count_events!(input.memory_store_half_events);
        count_events!(input.memory_store_word_events);
        count_events!(input.memory_store_double_events);
        count_events!(input.jal_events);
        count_events!(input.jalr_events);
        count_events!(input.utype_events);
        count_events!(input.syscall_events);

        // Build flat multiplicity array (one per instruction, indexed by instruction index).
        let nb_instructions = input.program.instructions.len();
        let multiplicities: Vec<u32> = (0..nb_instructions)
            .map(|idx| {
                let pc = input.program.pc_base + idx as u64 * 4;
                *instruction_counts.get(&pc).unwrap_or(&0)
            })
            .collect();

        // Copy multiplicities to device.
        let mult_device = {
            let mut buf =
                Buffer::try_with_capacity_in(multiplicities.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&multiplicities)?;
            buf
        };

        let width = <ProgramChip as BaseAir<F>>::width(self);
        let height = MachineAir::<F>::num_rows(self, input).expect("num_rows should be Some");

        let mut trace = Tensor::<F, TaskScope>::zeros_in([width, height], scope.clone());

        unsafe {
            const BLOCK_DIM: usize = 256;
            let grid_dim = height.div_ceil(BLOCK_DIM);

            let kernel_args =
                args!(trace.as_mut_ptr(), height, mult_device.as_ptr(), nb_instructions);

            scope
                .launch_kernel(
                    TaskScope::tracegen_riscv_program_kernel(),
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
    use std::sync::Arc;
    use std::time::Instant;

    use slop_tensor::Tensor;
    use sp1_core_executor::{ExecutionRecord, Instruction, Opcode, Program};
    use sp1_core_machine::riscv::ProgramChip;
    use sp1_gpu_cudart::{DeviceTensor, TaskScope};
    use sp1_hypercube::air::MachineAir;

    use crate::{CudaTracegenAir, F};

    /// Generate a test program with a variety of instructions.
    fn make_test_program(nb_instructions: usize) -> Arc<Program> {
        let instructions: Vec<Instruction> = (0..nb_instructions)
            .map(|i| {
                let variant = i % 5;
                match variant {
                    0 => Instruction::new(
                        Opcode::ADD,
                        (i % 31 + 1) as u8,
                        (i % 31) as u64,
                        (i % 30) as u64,
                        false,
                        false,
                    ),
                    1 => Instruction::new(
                        Opcode::ADDI,
                        (i % 31 + 1) as u8,
                        (i % 31) as u64,
                        (i as u64) & 0xFFF,
                        false,
                        true,
                    ),
                    2 => Instruction::new(
                        Opcode::LW,
                        (i % 31 + 1) as u8,
                        (i % 31) as u64,
                        0,
                        false,
                        true,
                    ),
                    3 => Instruction::new(
                        Opcode::SW,
                        (i % 31 + 1) as u8,
                        (i % 31) as u64,
                        0,
                        false,
                        true,
                    ),
                    _ => Instruction::new(
                        Opcode::BEQ,
                        (i % 31 + 1) as u8,
                        (i % 31) as u64,
                        0,
                        false,
                        true,
                    ),
                }
            })
            .collect();
        Arc::new(Program::new(instructions, 0, 0))
    }

    #[tokio::test]
    async fn test_program_generate_preprocessed_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ProgramChip;
            let program = make_test_program(1000);

            // GPU warmup
            {
                let small_program = make_test_program(10);
                let _ =
                    chip.generate_preprocessed_trace_device(&small_program, &scope).await.unwrap();
                scope.synchronize().await.unwrap();
            }

            // CPU timing
            scope.synchronize().await.unwrap();
            let cpu_start = Instant::now();
            let trace = Tensor::<F>::from(
                chip.generate_preprocessed_trace(&program)
                    .expect("preprocessed trace should be Some"),
            );
            let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
            let cpu_duration = cpu_start.elapsed();

            // GPU timing
            scope.synchronize().await.unwrap();
            let gpu_start = Instant::now();
            let gpu_trace = chip
                .generate_preprocessed_trace_device(&program, &scope)
                .await
                .expect("should copy instructions to device successfully")
                .expect("preprocessed trace should be Some");
            scope.synchronize().await.unwrap();
            let gpu_duration = gpu_start.elapsed();

            println!("Program Preprocessed Tracegen timing (1000 instructions):");
            println!("  CPU: {:?}", cpu_duration);
            println!("  GPU: {:?}", gpu_duration);
            println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

            let gpu_trace =
                gpu_trace.to_host().expect("should copy trace to host successfully").into_guts();

            // Create dummy events for test_traces_eq (one per instruction).
            let events: Vec<u64> = (0..program.instructions.len() as u64).collect();
            crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_program_generate_trace() {
        sp1_gpu_cudart::spawn(|scope: TaskScope| async move {
            let chip = ProgramChip;
            let program = make_test_program(1000);

            // Use an empty record (all multiplicities = 0) for fair comparison.
            let shard = ExecutionRecord { program: program.clone(), ..Default::default() };

            // GPU warmup
            {
                let small_program = make_test_program(10);
                let small_shard = ExecutionRecord { program: small_program, ..Default::default() };
                let _ = chip
                    .generate_trace_device(&small_shard, &mut ExecutionRecord::default(), &scope)
                    .await
                    .unwrap();
                scope.synchronize().await.unwrap();
            }

            // CPU timing
            scope.synchronize().await.unwrap();
            let cpu_start = Instant::now();
            let trace =
                Tensor::<F>::from(chip.generate_trace(&shard, &mut ExecutionRecord::default()));
            let _cpu_device_trace = DeviceTensor::from_host(&trace, &scope).unwrap();
            let cpu_duration = cpu_start.elapsed();

            // GPU timing
            scope.synchronize().await.unwrap();
            let gpu_start = Instant::now();
            let gpu_trace = chip
                .generate_trace_device(&shard, &mut ExecutionRecord::default(), &scope)
                .await
                .expect("should copy multiplicities to device successfully");
            scope.synchronize().await.unwrap();
            let gpu_duration = gpu_start.elapsed();

            println!("Program Main Tracegen timing (1000 instructions, 0 events):");
            println!("  CPU: {:?}", cpu_duration);
            println!("  GPU: {:?}", gpu_duration);
            println!("  Speedup: {:.2}x", cpu_duration.as_secs_f64() / gpu_duration.as_secs_f64());

            let gpu_trace =
                gpu_trace.to_host().expect("should copy trace to host successfully").into_guts();

            let events: Vec<u64> = (0..program.instructions.len() as u64).collect();
            crate::tests::test_traces_eq(&trace, &gpu_trace, &events, false);
        })
        .await
        .unwrap();
    }
}
