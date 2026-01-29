#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// Manual struct definition for missing Poseidon2LinearLayerInstr
// namespace sp1_gpu_sys {
//     template<typename F>
//     struct Poseidon2LinearLayerInstr {
//         Poseidon2LinearLayerIo<Address<F>> addrs;
//         F mults[4];  // PERMUTATION_WIDTH / D = 16 / 4 = 4
//         F external;
//     };
// }

template <class T>
__global__ void recursion_linear_layer_generate_preprocessed_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::Poseidon2LinearLayerInstr<T>* instructions,
    uintptr_t nb_instructions) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::Poseidon2LinearLayerAccessCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_instructions; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::Poseidon2LinearLayerAccessCols<T> cols;
        const auto& instr = instructions[i];
        cols.addrs = instr.addrs;

        if (instr.external) {
            cols.external = T::one();
            cols.internal = T::zero();
        } else {
            cols.external = T::zero();
            cols.internal = T::one();
        }

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_LINEAR_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_LINEAR_ENTRIES_PER_ROW) + (j + start) * trace_height] = arr[j];
        }
    }
}

template <class T>
__global__ void recursion_linear_layer_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::Poseidon2LinearLayerIo<sp1_gpu_sys::Block<T>>* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::Poseidon2LinearLayerValueCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_events; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::Poseidon2LinearLayerValueCols<T> cols;
        // Copy input blocks directly
        for (int j = 0; j < 4; ++j) {
            cols.input[j] = events[i].input[j];
        }

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_LINEAR_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_LINEAR_ENTRIES_PER_ROW) + (j + start) * trace_height] = arr[j];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr recursion_linear_layer_generate_preprocessed_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_linear_layer_generate_preprocessed_trace_kernel<kb31_t>;
}
extern KernelPtr recursion_linear_layer_generate_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_linear_layer_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys