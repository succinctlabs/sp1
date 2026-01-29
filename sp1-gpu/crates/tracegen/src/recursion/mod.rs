mod alu_base;
mod alu_ext;
mod convert;
mod linear_layer;
mod poseidon2_wide;
mod prefix_sum_checks;
mod sbox;
mod select;

use slop_alloc::mem::CopyError;
use sp1_gpu_cudart::{DeviceMle, TaskScope};
use sp1_recursion_machine::RecursionAir;

use crate::{CudaTracegenAir, F};

impl<const DEGREE: usize, const VAR_EVENTS_PER_ROW: usize> CudaTracegenAir<F>
    for RecursionAir<F, DEGREE, VAR_EVENTS_PER_ROW>
{
    fn supports_device_preprocessed_tracegen(&self) -> bool {
        match self {
            Self::BaseAlu(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::ExtAlu(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Poseidon2Wide(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Poseidon2LinearLayer(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Poseidon2SBox(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::ExtFeltConvert(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::Select(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::PrefixSumChecks(chip) => chip.supports_device_preprocessed_tracegen(),
            Self::PublicValues(_) => false,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => false,
        }
    }

    async fn generate_preprocessed_trace_device(
        &self,
        program: &Self::Program,
        scope: &TaskScope,
    ) -> Result<Option<DeviceMle<F>>, CopyError> {
        match self {
            Self::BaseAlu(chip) => chip.generate_preprocessed_trace_device(program, scope).await,
            Self::ExtAlu(chip) => chip.generate_preprocessed_trace_device(program, scope).await,
            Self::Poseidon2Wide(chip) => {
                chip.generate_preprocessed_trace_device(program, scope).await
            }
            Self::Poseidon2LinearLayer(chip) => {
                chip.generate_preprocessed_trace_device(program, scope).await
            }
            Self::Poseidon2SBox(chip) => {
                chip.generate_preprocessed_trace_device(program, scope).await
            }
            Self::ExtFeltConvert(chip) => {
                chip.generate_preprocessed_trace_device(program, scope).await
            }
            Self::Select(chip) => chip.generate_preprocessed_trace_device(program, scope).await,
            Self::PrefixSumChecks(chip) => {
                chip.generate_preprocessed_trace_device(program, scope).await
            }
            Self::PublicValues(_) => unimplemented!(),
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }

    fn supports_device_main_tracegen(&self) -> bool {
        match self {
            Self::BaseAlu(chip) => chip.supports_device_main_tracegen(),
            Self::ExtAlu(chip) => chip.supports_device_main_tracegen(),
            Self::Poseidon2Wide(chip) => chip.supports_device_main_tracegen(),
            Self::Poseidon2LinearLayer(chip) => chip.supports_device_main_tracegen(),
            Self::Poseidon2SBox(chip) => chip.supports_device_main_tracegen(),
            Self::ExtFeltConvert(chip) => chip.supports_device_main_tracegen(),
            Self::Select(chip) => chip.supports_device_main_tracegen(),
            Self::PrefixSumChecks(chip) => chip.supports_device_main_tracegen(),
            Self::PublicValues(_) => false,
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => false,
        }
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        match self {
            Self::BaseAlu(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::ExtAlu(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Poseidon2Wide(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Poseidon2LinearLayer(chip) => {
                chip.generate_trace_device(input, output, scope).await
            }
            Self::Poseidon2SBox(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::ExtFeltConvert(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::Select(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::PrefixSumChecks(chip) => chip.generate_trace_device(input, output, scope).await,
            Self::PublicValues(_) => unimplemented!(),
            // Other chips don't have `CudaTracegenAir` implemented yet.
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use sp1_gpu_cudart::TaskScope;

    use rand::{rngs::StdRng, SeedableRng};

    use slop_tensor::Tensor;

    use sp1_hypercube::air::MachineAir;
    use sp1_recursion_executor::{
        AnalyzedInstruction, BasicBlock, RawProgram, RecursionProgram, RootProgram, SeqBlock,
    };

    use crate::{CudaTracegenAir, F};

    pub async fn test_preprocessed_tracegen<A>(
        chip: A,
        mut make_instr: impl FnMut(&mut StdRng) -> AnalyzedInstruction<F>,
        scope: TaskScope,
    ) where
        A: CudaTracegenAir<F> + MachineAir<F, Program = RecursionProgram<F>>,
    {
        let mut rng = StdRng::seed_from_u64(0xDEADBEEF);

        let instrs =
            core::iter::repeat_with(|| make_instr(&mut rng)).take(1000).collect::<Vec<_>>();

        // SAFETY: We don't actually execute the program, which requires that the invariants hold.
        // We only generate preprocessed traces, which do not require that the invariants hold.
        let program = unsafe {
            RecursionProgram::new_unchecked(RootProgram {
                inner: RawProgram { seq_blocks: vec![SeqBlock::Basic(BasicBlock { instrs })] },
                total_memory: 0, // Will be filled in.
                shape: None,
                event_counts: Default::default(),
            })
        };

        let trace = Tensor::<F>::from(
            chip.generate_preprocessed_trace(&program)
                .expect("should generate Some(preprocessed_trace)"),
        );

        let gpu_trace = chip
            .generate_preprocessed_trace_device(&program, &scope)
            .await
            .expect("should copy events to device successfully")
            .expect("should generate Some(preprocessed_trace)")
            .to_host()
            .expect("should copy trace to host successfully")
            .into_guts();

        let Some(SeqBlock::Basic(BasicBlock { instrs })) =
            program.into_inner().inner.seq_blocks.pop()
        else {
            unreachable!()
        };

        crate::tests::test_traces_eq(&trace, &gpu_trace, &instrs);
    }
}
