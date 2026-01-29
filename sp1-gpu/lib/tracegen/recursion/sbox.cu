#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

template <class T>
__global__ void recursion_sbox_generate_preprocessed_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::Poseidon2SBoxInstr<T>* instructions,
    uintptr_t nb_instructions) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::Poseidon2SBoxAccessCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_instructions; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::Poseidon2SBoxAccessCols<T> cols;
        const auto& instr = instructions[i];
        cols.addrs = instr.addrs;

        if (instr.external) {
            cols.external = instr.mults;
            cols.internal = T::zero();
        } else {
            cols.external = T::zero();
            cols.internal = instr.mults;
        }

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_SBOX_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_SBOX_ENTRIES_PER_ROW) + (j + start) * trace_height] = arr[j];
        }
    }
}

template <class T>
__global__ void recursion_sbox_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::Poseidon2SBoxIo<sp1_gpu_sys::Block<T>>* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::Poseidon2SBoxValueCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_events; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::Poseidon2SBoxValueCols<T> cols;
        cols.vals.input = events[i].input;
        cols.vals.output = events[i].output;

        // Compute output values for the x^3 sbox.
        for (int j = 0; j < sp1_gpu_sys::D; ++j) {
            cols.vals.output._0[j] =
                events[i].input._0[j] * events[i].input._0[j] * events[i].input._0[j];
        }

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_SBOX_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_SBOX_ENTRIES_PER_ROW) + (j + start) * trace_height] = arr[j];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr recursion_sbox_generate_preprocessed_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_sbox_generate_preprocessed_trace_kernel<kb31_t>;
}
extern KernelPtr recursion_sbox_generate_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_sbox_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys