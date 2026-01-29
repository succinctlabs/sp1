#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

template <class T>
__global__ void recursion_base_alu_generate_preprocessed_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::BaseAluInstr<T>* instructions,
    uintptr_t nb_instructions) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::BaseAluAccessCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_instructions; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::BaseAluAccessCols<T> cols;
        const auto& instr = instructions[i];
        cols.addrs = instr.addrs;
        cols.is_add = T::zero();
        cols.is_sub = T::zero();
        cols.is_mul = T::zero();
        cols.is_div = T::zero();
        cols.mult = instr.mult;

        switch (instr.opcode) {
        case sp1_gpu_sys::BaseAluOpcode::AddF:
            cols.is_add = T::one();
            break;
        case sp1_gpu_sys::BaseAluOpcode::SubF:
            cols.is_sub = T::one();
            break;
        case sp1_gpu_sys::BaseAluOpcode::MulF:
            cols.is_mul = T::one();
            break;
        case sp1_gpu_sys::BaseAluOpcode::DivF:
            cols.is_div = T::one();
            break;
        }

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_BASE_ALU_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_BASE_ALU_ENTRIES_PER_ROW) + (j + start) * trace_height] =
                arr[j];
        }
    }
}

template <class T>
__global__ void recursion_base_alu_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::BaseAluEvent<T>* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::BaseAluValueCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < nb_events; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::BaseAluValueCols<T> cols;
        cols.vals = events[i];

        const T* arr = reinterpret_cast<T*>(&cols);
        size_t start = (i % sp1_gpu_sys::NUM_BASE_ALU_ENTRIES_PER_ROW) * COLUMNS;
        for (size_t j = 0; j < COLUMNS; ++j) {
            trace[(i / sp1_gpu_sys::NUM_BASE_ALU_ENTRIES_PER_ROW) + (j + start) * trace_height] =
                arr[j];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr recursion_base_alu_generate_preprocessed_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_base_alu_generate_preprocessed_trace_kernel<kb31_t>;
}
extern KernelPtr recursion_base_alu_generate_trace_koala_bear_kernel() {
    return (KernelPtr)::recursion_base_alu_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
