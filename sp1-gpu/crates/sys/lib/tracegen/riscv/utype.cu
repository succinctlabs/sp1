/// GPU trace generation for RISC-V UTypeChip (LUI, AUIPC).

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

/// UTypeColumns: column layout for UType instructions.
/// Manually defined because cbindgen can't resolve `WORD_SIZE - 1` constant expression.
/// Matches: sp1-wip/crates/core/machine/src/utype/mod.rs
template <class T>
struct UTypeCols {
    sp1_gpu_sys::CPUState<T> state;
    JTypeReader<T> adapter;
    T addend[3]; // WORD_SIZE - 1 = 3
    sp1_gpu_sys::AddOperation<T> add_operation;
    T is_auipc;
    T is_real;
};

/// Populate JTypeReader from UTypeGpuEvent.
template <class T>
__device__ void
populate_j_type_reader(JTypeReader<T>& adapter, const sp1_gpu_sys::UTypeGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);
    u64_to_word(event.op_b, adapter.op_b_imm);
    u64_to_word(event.op_c, adapter.op_c_imm);
}

/// Populate AddOperation from operands a (addend) and b.
/// The add operation stores value = a + b.
template <class T>
__device__ void populate_add_operation(sp1_gpu_sys::AddOperation<T>& op, uint64_t a, uint64_t b) {
    uint64_t result = a + b; // wrapping add
    u64_to_word(result, op.value);
}

/// Main kernel for UTypeChip trace generation.
template <class T>
__global__ void riscv_utype_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::UTypeGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(UTypeCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        UTypeCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate is_real and is_auipc
            cols.is_real = T::one();
            cols.is_auipc = T::from_bool(event.is_auipc);

            // Populate addend and add_operation
            if (event.op_a != 0) {
                // For AUIPC: addend = lower 48 bits of PC (3 x u16 limbs)
                // For LUI: addend = 0
                uint64_t a = event.is_auipc ? event.pc : 0;
                cols.addend[0] = T::from_canonical_u32(a & 0xFFFF);
                cols.addend[1] = T::from_canonical_u32((a >> 16) & 0xFFFF);
                cols.addend[2] = T::from_canonical_u32((a >> 32) & 0xFFFF);
                populate_add_operation(cols.add_operation, a, event.b);
            } else {
                // op_a == 0: addend = [0, 0, 0], add_operation.value = 0
                cols.addend[0] = T::zero();
                cols.addend[1] = T::zero();
                cols.addend[2] = T::zero();
                u64_to_word(0, cols.add_operation.value);
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
extern KernelPtr riscv_utype_generate_trace_kernel() {
    return (KernelPtr)::riscv_utype_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
