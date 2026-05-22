use slop_algebra::{ExtensionField, Field};
use slop_bn254::Bn254Fr;
use sp1_gpu_challenger::{DuplexChallenger, MultiField32Challenger};

use sp1_gpu_cudart::{
    sys::{
        jagged::{
            fusedJaggedAssistSumcheck_kernel_duplex,
            fusedJaggedAssistSumcheck_kernel_multi_field_32, precomputePrefixStates_kernel,
        },
        runtime::KernelPtr,
    },
    TaskScope,
};

/// Trait for types that can provide a mutable raw pointer representation for GPU kernels.
pub trait AsMutRawChallenger {
    type ChallengerRawMut;

    fn as_mut_raw(&mut self) -> Self::ChallengerRawMut;
}

impl<F> AsMutRawChallenger for DuplexChallenger<F, TaskScope> {
    type ChallengerRawMut = sp1_gpu_challenger::DuplexChallengerRawMut<F>;

    fn as_mut_raw(&mut self) -> Self::ChallengerRawMut {
        DuplexChallenger::as_mut_raw(self)
    }
}

impl<F, PF> AsMutRawChallenger for MultiField32Challenger<F, PF, TaskScope> {
    type ChallengerRawMut = sp1_gpu_challenger::MultiField32ChallengerRawMut<F, PF>;

    fn as_mut_raw(&mut self) -> Self::ChallengerRawMut {
        MultiField32Challenger::as_mut_raw(self)
    }
}

/// # Safety
///
pub unsafe trait BranchingProgramKernel<F: Field, EF: ExtensionField<F>, Challenger> {
    fn precompute_prefix_states_kernel() -> KernelPtr;

    fn fused_sumcheck_kernel() -> KernelPtr;
}

/// # Safety
///
unsafe impl<F: Field, EF: ExtensionField<F>>
    BranchingProgramKernel<F, EF, DuplexChallenger<F, TaskScope>> for TaskScope
{
    fn precompute_prefix_states_kernel() -> KernelPtr {
        unsafe { precomputePrefixStates_kernel() }
    }

    fn fused_sumcheck_kernel() -> KernelPtr {
        unsafe { fusedJaggedAssistSumcheck_kernel_duplex() }
    }
}

unsafe impl<F: Field, EF: ExtensionField<F>>
    BranchingProgramKernel<F, EF, MultiField32Challenger<F, Bn254Fr, TaskScope>> for TaskScope
{
    fn precompute_prefix_states_kernel() -> KernelPtr {
        unsafe { precomputePrefixStates_kernel() }
    }

    fn fused_sumcheck_kernel() -> KernelPtr {
        unsafe { fusedJaggedAssistSumcheck_kernel_multi_field_32() }
    }
}

#[cfg(test)]
mod tests {

    use slop_alloc::{Buffer, CpuBackend};

    use slop_jagged::{
        all_memory_states, transition, BitState, MemoryState,
        StateOrFail::{Fail, State},
    };

    use slop_tensor::Tensor;

    use sp1_gpu_cudart::{
        args,
        sys::{
            jagged::{transition_kernel, transition_w8_kernel},
            runtime::KernelPtr,
        },
        DeviceBuffer, TaskScope,
    };

    pub trait TransitionKernel {
        fn transition_kernel() -> KernelPtr;
        fn transition_w8_kernel() -> KernelPtr;
    }

    impl TransitionKernel for TaskScope {
        fn transition_kernel() -> KernelPtr {
            unsafe { transition_kernel() }
        }
        fn transition_w8_kernel() -> KernelPtr {
            unsafe { transition_w8_kernel() }
        }
    }

    #[test]
    fn test_transition() {
        // Generate all 16 combined bit states in the GPU's bit ordering:
        // bit 0 = next_ps, bit 1 = curr_ps, bit 2 = index, bit 3 = row
        let bit_states: Vec<BitState> = (0..16)
            .map(|i| BitState::Combined {
                next_col_prefix_sum_bit: (i & 1) != 0,
                curr_col_prefix_sum_bit: ((i >> 1) & 1) != 0,
                index_bit: ((i >> 2) & 1) != 0,
                row_bit: ((i >> 3) & 1) != 0,
            })
            .collect();
        // Use width-4 memory states (no saved_index_bit) to match the GPU's
        // TRANSITIONS table which has 4 real states + FAIL.
        let memory_states = MemoryState::width4_states().to_vec();

        let mut cpu_transition_results = Vec::new();
        for bit_state in bit_states.iter() {
            let mut bit_state_results = Vec::new();
            for output_memory_state in memory_states.iter() {
                bit_state_results.push(transition(*bit_state, *output_memory_state));
            }
            cpu_transition_results.push(bit_state_results);
        }

        let gpu_transition_results: Buffer<usize, CpuBackend> =
            sp1_gpu_cudart::run_sync_in_place(|t| {
                unsafe {
                    // The +1 is for the FAIL state.
                    let mut gpu_transition_results: Tensor<usize, TaskScope> =
                        Tensor::with_sizes_in(
                            [bit_states.len(), memory_states.len() + 1],
                            t.clone(),
                        );

                    let args = args!(gpu_transition_results.as_mut_ptr());

                    gpu_transition_results.assume_init();

                    t.launch_kernel(
                        <TaskScope as TransitionKernel>::transition_kernel(),
                        (1usize, 1usize, 1usize),
                        (1usize, 1usize, 1usize),
                        &args,
                        0,
                    )
                    .unwrap();

                    DeviceBuffer::from_raw(gpu_transition_results.storage).to_host().unwrap()
                }
            })
            .unwrap()
            .into();

        // Need to retrieve these again, because they are moved into the cuda task.
        let memory_states = MemoryState::width4_states().to_vec();

        let mut gpu_transition_results: Tensor<usize, CpuBackend> = gpu_transition_results.into();
        gpu_transition_results.reshape_in_place([bit_states.len(), memory_states.len() + 1]);
        for (cpu_transition_mem_results, gpu_transition_mem_results) in
            cpu_transition_results.iter().zip(gpu_transition_results.split())
        {
            for (cpu_transition_result, gpu_transition_result) in
                cpu_transition_mem_results
                    .iter()
                    .zip::<&[usize]>(gpu_transition_mem_results.clone().as_slice())
            {
                match cpu_transition_result {
                    State(cpu_transition_result) => {
                        assert_eq!(cpu_transition_result.get_index(), *gpu_transition_result);
                    }
                    Fail => {
                        assert_eq!(*gpu_transition_result, 4);
                    }
                }
            }

            // Verify that the transition from the FAIL state is FAIL.
            assert_eq!(gpu_transition_mem_results.as_slice()[4], 4);
        }

        // ---- Width-8 transition table checks ----
        // Fetch CURR_TRANSITIONS_W8[8][8] and NEXT_TRANSITIONS_W8[2][8] from GPU.
        const WIDE_BP_WIDTH: usize = 8;
        const WIDE_FAIL: usize = 8;
        const CURR_ROWS: usize = 8;
        const NEXT_ROWS: usize = 2;
        let total_entries = CURR_ROWS * WIDE_BP_WIDTH + NEXT_ROWS * WIDE_BP_WIDTH;

        let gpu_w8_results: Buffer<usize, CpuBackend> =
            sp1_gpu_cudart::run_sync_in_place(|t| unsafe {
                let mut output: Tensor<usize, TaskScope> =
                    Tensor::with_sizes_in([total_entries], t.clone());
                let args = args!(output.as_mut_ptr());
                output.assume_init();
                t.launch_kernel(
                    <TaskScope as TransitionKernel>::transition_w8_kernel(),
                    (1usize, 1usize, 1usize),
                    (1usize, 1usize, 1usize),
                    &args,
                    0,
                )
                .unwrap();
                DeviceBuffer::from_raw(output.storage).to_host().unwrap()
            })
            .unwrap()
            .into();

        let gpu_w8: &[usize] = gpu_w8_results.as_slice();
        let gpu_curr = &gpu_w8[..CURR_ROWS * WIDE_BP_WIDTH];
        let gpu_next = &gpu_w8[CURR_ROWS * WIDE_BP_WIDTH..];

        let w8_states = all_memory_states();
        assert_eq!(w8_states.len(), WIDE_BP_WIDTH);

        // Check Curr (even layer) transitions: 8 bit states × 8 memory states.
        for row in [false, true] {
            for index in [false, true] {
                for curr_ps in [false, true] {
                    let bit_state_idx =
                        (curr_ps as usize) << 2 | (index as usize) << 1 | row as usize;
                    let bit_state = BitState::Curr {
                        row_bit: row,
                        index_bit: index,
                        curr_col_prefix_sum_bit: curr_ps,
                    };

                    for mem_state in &w8_states {
                        let mem_idx = mem_state.get_index();
                        let gpu_val = gpu_curr[bit_state_idx * WIDE_BP_WIDTH + mem_idx];
                        let cpu_result = transition(bit_state, *mem_state);

                        match cpu_result {
                            State(new_state) => {
                                assert_eq!(
                                    gpu_val,
                                    new_state.get_index(),
                                    "Curr W8 mismatch: bs={bit_state_idx}, ms={mem_idx}, \
                                     CPU={}, GPU={gpu_val}",
                                    new_state.get_index()
                                );
                            }
                            Fail => {
                                assert_eq!(
                                    gpu_val, WIDE_FAIL,
                                    "Curr W8 mismatch: bs={bit_state_idx}, ms={mem_idx}, \
                                     CPU=Fail, GPU={gpu_val}"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Check Next (odd layer) transitions: 2 bit states × 8 memory states.
        for next_ps in [false, true] {
            let bit_state_idx = next_ps as usize;
            let bit_state = BitState::Next { next_col_prefix_sum_bit: next_ps };

            for mem_state in &w8_states {
                let mem_idx = mem_state.get_index();
                let gpu_val = gpu_next[bit_state_idx * WIDE_BP_WIDTH + mem_idx];
                let cpu_result = transition(bit_state, *mem_state);

                match cpu_result {
                    State(new_state) => {
                        assert_eq!(
                            gpu_val,
                            new_state.get_index(),
                            "Next W8 mismatch: bs={bit_state_idx}, ms={mem_idx}, \
                             CPU={}, GPU={gpu_val}",
                            new_state.get_index()
                        );
                    }
                    Fail => {
                        assert_eq!(
                            gpu_val, WIDE_FAIL,
                            "Next W8 mismatch: bs={bit_state_idx}, ms={mem_idx}, \
                             CPU=Fail, GPU={gpu_val}"
                        );
                    }
                }
            }
        }
    }
}
