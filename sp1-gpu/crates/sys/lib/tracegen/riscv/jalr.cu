/// GPU trace generation for RISC-V JalrChip (JALR instruction).

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

/// JalrColumns: column layout for JALR instruction.
/// Matches: sp1-wip/crates/core/machine/src/control_flow/jalr/columns.rs
template <class T>
struct JalrCols {
    sp1_gpu_sys::CPUState<T> state;
    sp1_gpu_sys::ITypeReader<T> adapter;
    sp1_gpu_sys::Word<T> op_a_value; // return address value
    T is_real;
    sp1_gpu_sys::AddOperation<T> add_operation;  // next_pc = op_b + imm
    sp1_gpu_sys::AddOperation<T> op_a_operation; // return_addr = pc + 4
};

/// Populate AddOperation from operands a and b.
/// The add operation stores value = a + b (wrapping).
template <class T>
__device__ void populate_add_operation(sp1_gpu_sys::AddOperation<T>& op, uint64_t a, uint64_t b) {
    uint64_t result = a + b; // wrapping add
    u64_to_word(result, op.value);
}

/// Main kernel for JalrChip trace generation.
template <class T>
__global__ void riscv_jalr_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::JalrGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(JalrCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        JalrCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate is_real
            cols.is_real = T::one();

            // Populate op_a_value (return address)
            u64_to_word(event.a, cols.op_a_value);

            // Populate add_operation: next_pc = op_b_value (event.b) + imm (event.op_c)
            populate_add_operation(cols.add_operation, event.b, event.op_c);

            // Populate op_a_operation: return_addr = pc + 4
            if (!event.op_a_0) {
                populate_add_operation(cols.op_a_operation, event.pc, 4);
            } else {
                // op_a == 0 (x0 register): return address is 0
                u64_to_word(0, cols.op_a_operation.value);
            }

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ITypeReader from event
            populate_i_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_jalr_generate_trace_kernel() {
    return (KernelPtr)::riscv_jalr_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
