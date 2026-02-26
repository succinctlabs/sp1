#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// // Manual struct definition for ExtFeltInstr (cbindgen has issues with this)
// namespace sp1_gpu_sys {
//     template<typename F>
//     struct ExtFeltInstr {
//         Address<F> addrs[5];  // D + 1 = 4 + 1 = 5
//         F mults[5];
//         F ext2felt;
//     };
// }

template <class T>
__global__ void recursion_convert_generate_preprocessed_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::ExtFeltInstr<T>* instructions,
    uintptr_t nb_instructions) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::ConvertAccessCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_instructions; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::ConvertAccessCols<T> cols;
        const auto& instr = instructions[i];
        cols.addrs[0] = instr.addrs[0];
        cols.addrs[1] = instr.addrs[1];
        cols.addrs[2] = instr.addrs[2];
        cols.addrs[3] = instr.addrs[3];
        cols.addrs[4] = instr.addrs[4];

        if (instr.ext2felt) {
            cols.mults[0] = T::one();
            cols.mults[1] = instr.mults[1];
            cols.mults[2] = instr.mults[2];
            cols.mults[3] = instr.mults[3];
            cols.mults[4] = instr.mults[4];
        } else {
            cols.mults[0] = -instr.mults[0];
            cols.mults[1] = -T::one();
            cols.mults[2] = -T::one();
            cols.mults[3] = -T::one();
            cols.mults[4] = -T::one();
        }

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_CONVERT_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_CONVERT_ENTRIES_PER_ROW) + (j + start) * trace_height] = arr[j];
        }
    }
}

template <class T>
__global__ void recursion_convert_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::ExtFeltEvent<T>* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::ConvertValueCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_events; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::ConvertValueCols<T> cols;
        cols.input = events[i].input;

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_CONVERT_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_CONVERT_ENTRIES_PER_ROW) + (j + start) * trace_height] = arr[j];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr recursion_convert_generate_preprocessed_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_convert_generate_preprocessed_trace_kernel<kb31_t>;
}
extern KernelPtr recursion_convert_generate_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_convert_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys