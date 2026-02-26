/// GPU trace generation for RISC-V BitwiseChip.
///
/// Handles XOR, OR, AND (and their immediate variants XORI, ORI, ANDI) instructions.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define BitwiseOperation and related types since cbindgen can't handle
// constant expression array sizes like [T; WORD_BYTE_SIZE].
namespace sp1_gpu_sys {

// WORD_BYTE_SIZE = 8 (8 bytes = 64 bits)
static constexpr size_t WORD_BYTE_SIZE = 8;

template <typename T>
struct BitwiseOperation {
    /// The result of the bitwise operation in bytes.
    T result[WORD_BYTE_SIZE];
};

template <typename T>
struct U16toU8Operation {
    /// Lower bytes of the u16 limbs.
    T low_bytes[WORD_SIZE];
};

template <typename T>
struct BitwiseU16Operation {
    /// Lower byte of the limbs of `b`.
    U16toU8Operation<T> b_low_bytes;

    /// Lower byte of the limbs of `c`.
    U16toU8Operation<T> c_low_bytes;

    /// The bitwise operation over bytes.
    BitwiseOperation<T> bitwise_operation;
};

template <typename T>
struct BitwiseCols {
    /// The current shard, timestamp, program counter of the CPU.
    CPUState<T> state;
    /// The adapter to read program and register information.
    ALUTypeReader<T> adapter;
    /// Instance of BitwiseU16Operation to handle bitwise logic.
    BitwiseU16Operation<T> bitwise_operation;
    /// If the opcode is XOR.
    T is_xor;
    /// If the opcode is OR.
    T is_or;
    /// If the opcode is AND.
    T is_and;
};

} // namespace sp1_gpu_sys

// Opcode values for Bitwise operations
enum BitwiseOpcode : uint8_t {
    XOR_OP = 0,
    OR_OP = 1,
    AND_OP = 2,
};

/// GPU event structure for BitwiseChip.
/// Uses ALUTypeReader format since it supports immediate mode (XORI, ORI, ANDI).
struct BitwiseGpuEvent {
    // From AluEvent
    uint64_t clk;
    uint64_t pc;
    uint64_t b;
    uint64_t c;
    uint64_t a; // Result

    // Opcode: XOR=0, OR=1, AND=2
    uint8_t opcode;

    // From ALUTypeRecord
    uint8_t op_a;
    uint64_t op_b;
    uint64_t op_c;
    bool is_imm;

    sp1_gpu_sys::GpuMemoryAccess mem_a;
    sp1_gpu_sys::GpuMemoryAccess mem_b;
    sp1_gpu_sys::GpuMemoryAccess mem_c;
};

/// Populate U16toU8Operation from a u64 value.
/// Stores the low byte of each u16 limb.
template <class T>
__device__ void populate_u16_to_u8(sp1_gpu_sys::U16toU8Operation<T>& op, uint64_t value) {
    op.low_bytes[0] = T::from_canonical_u32(value & 0xFF);
    op.low_bytes[1] = T::from_canonical_u32((value >> 16) & 0xFF);
    op.low_bytes[2] = T::from_canonical_u32((value >> 32) & 0xFF);
    op.low_bytes[3] = T::from_canonical_u32((value >> 48) & 0xFF);
}

/// Populate BitwiseOperation from the result value.
/// The result is stored as 8 bytes.
template <class T>
__device__ void populate_bitwise_operation(sp1_gpu_sys::BitwiseOperation<T>& op, uint64_t a_u64) {
    op.result[0] = T::from_canonical_u32(a_u64 & 0xFF);
    op.result[1] = T::from_canonical_u32((a_u64 >> 8) & 0xFF);
    op.result[2] = T::from_canonical_u32((a_u64 >> 16) & 0xFF);
    op.result[3] = T::from_canonical_u32((a_u64 >> 24) & 0xFF);
    op.result[4] = T::from_canonical_u32((a_u64 >> 32) & 0xFF);
    op.result[5] = T::from_canonical_u32((a_u64 >> 40) & 0xFF);
    op.result[6] = T::from_canonical_u32((a_u64 >> 48) & 0xFF);
    op.result[7] = T::from_canonical_u32((a_u64 >> 56) & 0xFF);
}

/// Populate BitwiseU16Operation from operands and result.
template <class T>
__device__ void populate_bitwise_u16_operation(
    sp1_gpu_sys::BitwiseU16Operation<T>& op,
    uint64_t a_u64,
    uint64_t b_u64,
    uint64_t c_u64) {
    populate_u16_to_u8(op.b_low_bytes, b_u64);
    populate_u16_to_u8(op.c_low_bytes, c_u64);
    populate_bitwise_operation(op.bitwise_operation, a_u64);
}

/// Populate ALUTypeReader from BitwiseGpuEvent.
template <class T>
__device__ void populate_bitwise_alu_type_reader(
    sp1_gpu_sys::ALUTypeReader<T>& adapter,
    const BitwiseGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    // op_b is a register specifier
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    // op_c is stored as a Word (4 x u16 limbs)
    u64_to_word(event.op_c, adapter.op_c);

    // Handle immediate vs register for op_c
    adapter.imm_c = T::from_bool(event.is_imm);
    if (event.is_imm) {
        // When it's an immediate, op_c_memory.prev_value = op_c, and timestamps are zero
        adapter.op_c_memory.prev_value = adapter.op_c;
        adapter.op_c_memory.access_timestamp.diff_low_limb = T::zero();
        adapter.op_c_memory.access_timestamp.prev_low = T::zero();
    } else {
        // When it's a register read, populate from memory access
        populate_register_access_cols(adapter.op_c_memory, event.mem_c);
    }
}

/// Main kernel for BitwiseChip trace generation.
template <class T>
__global__ void riscv_bitwise_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const BitwiseGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::BitwiseCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::BitwiseCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate opcode flags
            cols.is_xor = T::from_bool(event.opcode == XOR_OP);
            cols.is_or = T::from_bool(event.opcode == OR_OP);
            cols.is_and = T::from_bool(event.opcode == AND_OP);

            // Populate bitwise_operation
            populate_bitwise_u16_operation(cols.bitwise_operation, event.a, event.b, event.c);

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ALUTypeReader from event
            populate_bitwise_alu_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_bitwise_generate_trace_kernel() {
    return (KernelPtr)::riscv_bitwise_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
