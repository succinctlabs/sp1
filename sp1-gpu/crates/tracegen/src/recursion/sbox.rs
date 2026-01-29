use slop_air::BaseAir;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope};
use sp1_gpu_cudart::{TracegenPreprocessedRecursionSBoxKernel, TracegenRecursionSBoxKernel};
use sp1_hypercube::air::MachineAir;
use sp1_recursion_executor::Instruction;
use sp1_recursion_machine::chips::poseidon2_helper::sbox::Poseidon2SBoxChip;

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for Poseidon2SBoxChip {
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
                Instruction::Poseidon2SBox(instr) => Some(*instr),
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
            // const sp1_gpu_sys::Poseidon2SBoxInstr<T> *instructions,
            // uintptr_t nb_instructions
            let args = args!(trace.as_mut_ptr(), height, instrs_device.as_ptr(), instrs.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_preprocessed_recursion_sbox_kernel(),
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
        let events = &input.poseidon2_sbox_events;

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
            // const sp1_gpu_sys::Poseidon2SBoxIo<T> *events,
            // uintptr_t nb_events
            let args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_recursion_sbox_kernel(),
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

    use slop_algebra::AbstractField;
    use sp1_recursion_executor::{
        Address, AnalyzedInstruction, Block, ExecutionRecord, Instruction, Poseidon2SBoxInstr,
        Poseidon2SBoxIo,
    };
    use sp1_recursion_machine::chips::poseidon2_helper::sbox::Poseidon2SBoxChip;

    use crate::F;

    #[tokio::test]
    async fn test_sbox_generate_preprocessed_trace() {
        sp1_gpu_cudart::spawn(|scope| {
            crate::recursion::tests::test_preprocessed_tracegen(
                Poseidon2SBoxChip,
                |rng| {
                    let addrs =
                        Poseidon2SBoxIo { input: Address(rng.gen()), output: Address(rng.gen()) };
                    AnalyzedInstruction::new(
                        Instruction::Poseidon2SBox(Poseidon2SBoxInstr {
                            addrs,
                            mults: F::one(),
                            external: rng.gen(),
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
    async fn test_sbox_generate_main_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::tests::test_main_tracegen(
                Poseidon2SBoxChip,
                |rng| {
                    let input = Block(rng.gen());
                    // Compute output: x^7 = x^3 * x^3 * x (SBox operation)
                    let input_cubed =
                        Block(core::array::from_fn(|i| input.0[i] * input.0[i] * input.0[i]));
                    let output = Block(core::array::from_fn(|i| {
                        input.0[i] * input_cubed.0[i] * input_cubed.0[i]
                    }));
                    Poseidon2SBoxIo { input, output }
                },
                |poseidon2_sbox_events| ExecutionRecord {
                    poseidon2_sbox_events,
                    ..Default::default()
                },
                scope,
            )
        })
        .await
        .unwrap();
    }
}
