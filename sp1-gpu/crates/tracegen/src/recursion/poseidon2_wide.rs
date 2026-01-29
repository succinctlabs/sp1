use slop_air::BaseAir;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope};
use sp1_gpu_cudart::{
    TracegenPreprocessedRecursionPoseidon2WideKernel, TracegenRecursionPoseidon2WideKernel,
};
use sp1_hypercube::air::MachineAir;
use sp1_recursion_executor::Instruction;
use sp1_recursion_machine::chips::poseidon2_wide::Poseidon2WideChip;

use crate::{CudaTracegenAir, F};

impl<const DEGREE: usize> CudaTracegenAir<F> for Poseidon2WideChip<DEGREE> {
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
                Instruction::Poseidon2(instr) => Some(**instr),
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
            // const sp1_gpu_sys::Poseidon2Instr<T> *instructions,
            // uintptr_t nb_instructions
            let args = args!(trace.as_mut_ptr(), height, instrs_device.as_ptr(), instrs.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_preprocessed_recursion_poseidon2_wide_kernel(),
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
        debug_assert!(DEGREE == 3 || DEGREE == 9);
        let sbox_state = DEGREE == 3;

        let events = &input.poseidon2_events;

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
            // kb31_t *trace,
            // uintptr_t trace_height,
            // const sp1_gpu_sys::Poseidon2Event<kb31_t> *events,
            // uintptr_t nb_events,
            // bool sbox_state
            let args =
                args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events.len(), sbox_state);
            scope
                .launch_kernel(
                    TaskScope::tracegen_recursion_poseidon2_wide_kernel(),
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

    use rand::{rngs::StdRng, Rng};

    use slop_symmetric::Permutation;

    use sp1_recursion_executor::{
        Address, AnalyzedInstruction, ExecutionRecord, Instruction, Poseidon2Event, Poseidon2Instr,
        Poseidon2Io, PERMUTATION_WIDTH,
    };
    use sp1_recursion_machine::chips::poseidon2_wide::Poseidon2WideChip;

    use crate::F;

    fn make_poseidon2_instr(rng: &mut StdRng) -> AnalyzedInstruction<F> {
        AnalyzedInstruction::new(
            Instruction::Poseidon2(Box::new(Poseidon2Instr {
                addrs: Poseidon2Io {
                    input: rng.gen::<[F; PERMUTATION_WIDTH]>().map(Address),
                    output: rng.gen::<[F; PERMUTATION_WIDTH]>().map(Address),
                },
                mults: rng.gen(),
            })),
            rng.gen(),
        )
    }

    #[tokio::test]
    async fn test_poseidon2_wide_deg_3_generate_preprocessed_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::recursion::tests::test_preprocessed_tracegen(
                Poseidon2WideChip::<3>,
                make_poseidon2_instr,
                scope,
            )
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_poseidon2_wide_deg_3_generate_main_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::tests::test_main_tracegen(
                Poseidon2WideChip::<3>,
                |rng| {
                    let input = rng.gen();
                    let permuter = sp1_hypercube::inner_perm();
                    let output = permuter.permute(input);

                    Poseidon2Event { input, output }
                },
                |poseidon2_events| ExecutionRecord { poseidon2_events, ..Default::default() },
                scope,
            )
        })
        .await
        .unwrap();
    }
}
