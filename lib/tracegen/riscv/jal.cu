/// GPU trace generation for RISC-V JalChip (JAL instruction).

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

/// JTypeReader: adapter for J-type instructions where op_b and op_c are immediates.
/// Manually defined because cbindgen can't resolve the dependent types in this context.
/// Matches: sp1-wip/crates/core/machine/src/adapter/register/j_type.rs
template <class T>
struct JTypeReader {
    T op_a;
    sp1_gpu_sys::RegisterAccessCols<T> op_a_memory;
    T op_a_0;
    sp1_gpu_sys::Word<T> op_b_imm;
    sp1_gpu_sys::Word<T> op_c_imm;
};

/// JalColumns: column layout for JAL instruction.
/// Matches: sp1-wip/crates/core/machine/src/control_flow/jal/columns.rs
template <class T>
struct JalCols {
    sp1_gpu_sys::CPUState<T> state;
    JTypeReader<T> adapter;
    sp1_gpu_sys::AddOperation<T> add_operation;  // next_pc = pc + b
    sp1_gpu_sys::AddOperation<T> op_a_operation; // return_addr = pc + 4
    T is_real;
};

/// Populate JTypeReader from JalGpuEvent.
template <class T>
__device__ void
populate_j_type_reader(JTypeReader<T>& adapter, const sp1_gpu_sys::JalGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);
    u64_to_word(event.op_b, adapter.op_b_imm);
    u64_to_word(event.op_c, adapter.op_c_imm);
}

/// Populate AddOperation from operands a and b.
/// The add operation stores value = a + b (wrapping).
template <class T>
__device__ void populate_add_operation(sp1_gpu_sys::AddOperation<T>& op, uint64_t a, uint64_t b) {
    uint64_t result = a + b; // wrapping add
    u64_to_word(result, op.value);
}

/// Main kernel for JalChip trace generation.
template <class T>
__global__ void riscv_jal_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::JalGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(JalCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        JalCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate is_real
            cols.is_real = T::one();

            // Populate add_operation: next_pc = pc + b (jump offset)
            populate_add_operation(cols.add_operation, event.pc, event.b);

            // Populate op_a_operation: return_addr = pc + 4
            if (!event.op_a_0) {
                populate_add_operation(cols.op_a_operation, event.pc, 4);
            } else {
                // op_a == 0 (x0 register): return address is 0
                u64_to_word(0, cols.op_a_operation.value);
            }

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate JTypeReader from event
            populate_j_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_jal_generate_trace_kernel() {
    return (KernelPtr)::riscv_jal_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
