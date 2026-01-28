use slop_air::BaseAir;
use slop_alloc::mem::CopyError;
use slop_alloc::Buffer;
use slop_tensor::Tensor;
use sp1_gpu_cudart::TracegenRecursionPrefixSumChecksKernel;
use sp1_gpu_cudart::{args, DeviceMle, TaskScope};
use sp1_hypercube::air::MachineAir;
use sp1_recursion_machine::chips::prefix_sum_checks::PrefixSumChecksChip;

use crate::{CudaTracegenAir, F};

impl CudaTracegenAir<F> for PrefixSumChecksChip {
    fn supports_device_main_tracegen(&self) -> bool {
        true
    }

    async fn generate_trace_device(
        &self,
        input: &Self::Record,
        _: &mut Self::Record,
        scope: &TaskScope,
    ) -> Result<DeviceMle<F>, CopyError> {
        let events = &input.prefix_sum_checks_events;

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
            // const sp1_gpu_sys::PrefixSumChecksEvent<T> *events,
            // uintptr_t nb_events
            let args = args!(trace.as_mut_ptr(), height, events_device.as_ptr(), events.len());
            scope
                .launch_kernel(
                    TaskScope::tracegen_recursion_prefix_sum_checks_kernel(),
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

    use sp1_recursion_executor::{Block, ExecutionRecord, PrefixSumChecksEvent};
    use sp1_recursion_machine::chips::prefix_sum_checks::PrefixSumChecksChip;

    #[tokio::test]
    async fn test_prefix_sum_checks_generate_main_trace() {
        sp1_gpu_cudart::spawn(move |scope| {
            crate::tests::test_main_tracegen(
                PrefixSumChecksChip,
                |rng| PrefixSumChecksEvent {
                    x1: rng.gen(),
                    x2: Block(rng.gen()),
                    zero: rng.gen(),
                    one: Block(rng.gen()),
                    acc: Block(rng.gen()),
                    new_acc: Block(rng.gen()),
                    field_acc: rng.gen(),
                    new_field_acc: rng.gen(),
                },
                |prefix_sum_checks_events| ExecutionRecord {
                    prefix_sum_checks_events,
                    ..Default::default()
                },
                scope,
            )
        })
        .await
        .unwrap();
    }
}
