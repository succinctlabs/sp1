use slop_air::BaseAir;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope};
use sp1_gpu_cudart::{TracegenPreprocessedRecursionConvertKernel, TracegenRecursionConvertKernel};
use sp1_hypercube::air::MachineAir;
use sp1_recursion_executor::Instruction;
use sp1_recursion_machine::chips::poseidon2_helper::convert::ConvertChip;

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for ConvertChip {
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
            .iter()
            .filter_map(|instruction| match instruction.inner() {
                Instruction::ExtFelt(instr) => Some(*instr),
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
            // const sp1_gpu_sys::ExtFeltInstr<T> *instructions,
            // uintptr_t nb_instructions
            let args = args!(trace.as_mut_ptr(), height, instrs_device.as_ptr(), instrs.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_preprocessed_recursion_convert_kernel(),
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
        let events = &input.ext_felt_conversion_events;

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
            // const sp1_gpu_sys::ExtFeltEvent<T> *events,
            // uintptr_t nb_events
            let args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_recursion_convert_kernel(),
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

    use sp1_recursion_executor::{
        Address, AnalyzedInstruction, Block, ExecutionRecord, ExtFeltEvent, ExtFeltInstr,
        Instruction,
    };
    use sp1_recursion_machine::chips::poseidon2_helper::convert::ConvertChip;

    #[tokio::test]
    async fn test_convert_generate_preprocessed_trace() {
        sp1_gpu_cudart::spawn(|scope| {
            crate::recursion::tests::test_preprocessed_tracegen(
                ConvertChip,
                |rng| {
                    AnalyzedInstruction::new(
                        Instruction::ExtFelt(ExtFeltInstr {
                            addrs: [
                                Address(rng.gen()),
                                Address(rng.gen()),
                                Address(rng.gen()),
                                Address(rng.gen()),
                                Address(rng.gen()),
                            ],
                            mults: [rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen()],
                            ext2felt: rng.gen(),
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
    async fn test_convert_generate_main_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::tests::test_main_tracegen(
                ConvertChip,
                |rng| ExtFeltEvent { input: Block(rng.gen()) },
                |ext_felt_conversion_events| ExecutionRecord {
                    ext_felt_conversion_events,
                    ..Default::default()
                },
                scope,
            )
        })
        .await
        .unwrap();
    }
}
