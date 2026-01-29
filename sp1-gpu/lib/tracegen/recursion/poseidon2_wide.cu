#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

#include "poseidon2/poseidon2_kb31_16.cuh"

#include "tracegen/poseidon2_wide.cuh"

constexpr static const uintptr_t POSEIDON2_WIDTH = poseidon2_kb31_16::constants::WIDTH;

template <class T>
__global__ void recursion_poseidon2_wide_generate_preprocessed_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::Poseidon2Instr<T>* instructions,
    uintptr_t nb_instructions) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::Poseidon2PreprocessedColsWide<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_instructions; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::Poseidon2PreprocessedColsWide<T> cols;

        const auto& instr = instructions[i];
        for (size_t j = 0; j < POSEIDON2_WIDTH; j++) {
            cols.input[j] = instr.addrs.input[j];
            cols.output[j] = sp1_gpu_sys::MemoryAccessColsChips<T>{
                .addr = instr.addrs.output[j],
                .mult = instr.mults[j]};
        }
        cols.is_real = T::one();

        const T* arr = reinterpret_cast<T*>(&cols);
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[i + j * trace_height] = arr[j];
        }
    }
}

__global__ void recursion_poseidon2_wide_generate_trace_koala_bear_kernel(
    kb31_t* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::Poseidon2Event<kb31_t>* events,
    uintptr_t nb_events) {
    kb31_t dummy_input[POSEIDON2_WIDTH];
    for (size_t i = 0; i < POSEIDON2_WIDTH; ++i) {
        dummy_input[i] = kb31_t::zero();
    }

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        if (i < nb_events) {
            poseidon2_wide::event_to_row(events[i].input, trace, i, trace_height);
        } else {
            poseidon2_wide::event_to_row(dummy_input, trace, i, trace_height);
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr recursion_poseidon2_wide_generate_preprocessed_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_poseidon2_wide_generate_preprocessed_trace_kernel<kb31_t>;
}
extern KernelPtr recursion_poseidon2_wide_generate_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_poseidon2_wide_generate_trace_koala_bear_kernel;
}
} // namespace sp1_gpu_sys
