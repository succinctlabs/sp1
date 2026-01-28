use slop_air::BaseAir;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope};
use sp1_gpu_cudart::{TracegenPreprocessedRecursionExtAluKernel, TracegenRecursionExtAluKernel};
use sp1_hypercube::air::MachineAir;
use sp1_recursion_executor::Instruction;
use sp1_recursion_machine::chips::alu_ext::ExtAluChip;

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for ExtAluChip {
    fn supports_device_preprocessed_tracegen(&self) -> bool {
        true
    }

    async fn generate_preprocessed_trace_device(
        &self,
        program: &Self::Program,
        scope: &TaskScope,
    ) -> Result<Option<DeviceMle<F>>, CopyError> {
        let instrs = program
            .inner
            .iter() // Faster than using `rayon` for some reason. Maybe vectorization?
            .filter_map(|instruction| match instruction.inner() {
                Instruction::ExtAlu(instr) => Some(*instr),
                _ => None,
            })
            .collect::<Vec<_>>();

        let instrs_device = {
            let mut buf = Buffer::try_with_capacity_in(instrs.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(&instrs)?;
            buf
        };

        let width = MachineAir::<F>::preprocessed_width(self);

        let height =
            MachineAir::<F>::preprocessed_num_rows_with_instrs_len(self, program, instrs.len())
                .expect("preprocessed_num_rows_with_instrs_len(...) should be Some(_)");

        let mut trace = Tensor::<F, TaskScope>::zeros_in([width, height], scope.clone());

        unsafe {
            const BLOCK_DIM: usize = 64;
            let grid_dim = height.div_ceil(BLOCK_DIM);
            // args:
            // T *trace,
            // uintptr_t trace_height,
            // const sp1_gpu_sys::ExtAluInstr<T> *instructions,
            // uintptr_t nb_instructions
            let args = args!(trace.as_mut_ptr(), height, instrs_device.as_ptr(), instrs.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_preprocessed_recursion_ext_alu_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &args,
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
        _: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.ext_alu_events;

        let events_device = {
            let mut buf = Buffer::try_with_capacity_in(events.len(), scope.clone()).unwrap();
            buf.extend_from_host_slice(events)?;
            buf
        };

        let width = <Self as BaseAir<F>>::width(self);

        let height = <Self as MachineAir<F>>::num_rows(self, input)
            .expect("num_rows(...) should be Some(_)");

        let mut trace = Tensor::<F, TaskScope>::zeros_in([width, height], scope.clone());

        unsafe {
            const BLOCK_DIM: usize = 64;
            let grid_dim = height.div_ceil(BLOCK_DIM);
            // args:
            // T *trace,
            // uintptr_t trace_height,
            // const sp1_gpu_sys::ExtAluEvent<T> *events,
            // uintptr_t nb_events
            let args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_recursion_ext_alu_kernel(),
                    grid_dim,
                    BLOCK_DIM,
                    &args,
                    0,
                )
                .unwrap();
        }

        Ok(DeviceMle::from(trace))
    }
}

#[cfg(test)]
mod tests {

    use rand::Rng;

    use slop_algebra::extension::BinomialExtensionField;
    use slop_algebra::{AbstractExtensionField, AbstractField, Field};
    use sp1_recursion_executor::{
        Address, AnalyzedInstruction, Block, ExecutionRecord, ExtAluEvent, ExtAluInstr, ExtAluIo,
        ExtAluOpcode, Instruction,
    };
    use sp1_recursion_machine::chips::alu_ext::ExtAluChip;

    use crate::F;

    type EF = BinomialExtensionField<F, 4>;

    #[tokio::test]
    async fn test_ext_alu_generate_preprocessed_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::recursion::tests::test_preprocessed_tracegen(
                ExtAluChip,
                |rng| {
                    let opcode = match rng.gen_range(0..4) {
                        0 => ExtAluOpcode::AddE,
                        1 => ExtAluOpcode::SubE,
                        2 => ExtAluOpcode::MulE,
                        _ => ExtAluOpcode::DivE,
                    };
                    AnalyzedInstruction::new(
                        Instruction::ExtAlu(ExtAluInstr {
                            opcode,
                            mult: rng.gen(),
                            addrs: ExtAluIo {
                                out: Address(rng.gen()),
                                in1: Address(rng.gen()),
                                in2: Address(rng.gen()),
                            },
                        }),
                        rng.gen(),
                    )
                },
                scope,
            )
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_ext_alu_generate_main_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::tests::test_main_tracegen(
                ExtAluChip,
                |rng| {
                    let b1 = Block(rng.gen());
                    let b2 = Block(rng.gen());
                    let in1: EF = b1.ext();
                    let in2: EF = b2.ext();
                    let out = Block::from(
                        match rng.gen_range(0..4) {
                            0 => in1 + in2, // Add
                            1 => in1 - in2, // Sub
                            2 => in1 * in2, // Mul
                            _ => {
                                let ef2 = if in2.is_zero() { EF::one() } else { in2 };
                                in1 / ef2
                            }
                        }
                        .as_base_slice(),
                    );
                    ExtAluEvent { out, in1: b1, in2: b2 }
                },
                |ext_alu_events| ExecutionRecord { ext_alu_events, ..Default::default() },
                scope,
            )
        })
        .await
        .unwrap();
    }
}
