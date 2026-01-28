/// GPU trace generation for RISC-V MulChip.

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// Constants matching Rust definitions
static constexpr size_t BYTE_SIZE = 8;  // bits in a byte
static constexpr size_t WORD_SIZE_MUL = 4;  // u16 limbs in a Word (renamed to avoid conflict with header)
static constexpr size_t WORD_BYTE_SIZE = 8;  // bytes in a 64-bit word
static constexpr size_t LONG_WORD_BYTE_SIZE = 16;  // bytes in a 128-bit product
static constexpr uint8_t BYTE_MASK = 0xFF;

// Manually define types that cbindgen can't resolve due to constant expressions like LONG_WORD_BYTE_SIZE.
// These must match the Rust struct layouts exactly.
namespace sp1_gpu_sys {

// U16toU8Operation: stores low bytes of each u16 limb
template<typename T>
struct U16toU8Operation {
    T low_bytes[WORD_SIZE];  // WORD_SIZE = 4
};

// MulOperation: multiplication operation columns
template<typename T>
struct MulOperation {
    /// The carry values (16 elements).
    T carry[LONG_WORD_BYTE_SIZE];
    /// The product bytes after carry propagation (16 elements).
    T product[LONG_WORD_BYTE_SIZE];
    /// The lower byte of two limbs of b (4 elements for WORD_SIZE u16 limbs).
    U16toU8Operation<T> b_lower_byte;
    /// The lower byte of two limbs of c.
    U16toU8Operation<T> c_lower_byte;
    /// The most significant bit of b.
    T b_msb;
    /// The most significant bit of c.
    T c_msb;
    /// The most significant bit of the product (for MULW).
    U16MSBOperation<T> product_msb;
    /// The sign extension of b.
    T b_sign_extend;
    /// The sign extension of c.
    T c_sign_extend;
};

// MulCols: column layout for MulChip
template<typename T>
struct MulCols {
    /// The current shard, timestamp, program counter of the CPU.
    CPUState<T> state;
    /// The adapter to read program and register information.
    RTypeReader<T> adapter;
    /// The output operand.
    Word<T> a;
    /// Instance of MulOperation to handle multiplication logic.
    MulOperation<T> mul_operation;
    /// Whether the operation is MUL.
    T is_mul;
    /// Whether the operation is MULH.
    T is_mulh;
    /// Whether the operation is MULHU.
    T is_mulhu;
    /// Whether the operation is MULHSU.
    T is_mulhsu;
    /// Whether the operation is MULW.
    T is_mulw;
};

} // namespace sp1_gpu_sys

/// Opcode enum values for MUL variants.
enum MulOpcode : uint8_t {
    MUL = 0,
    MULH = 1,
    MULHU = 2,
    MULHSU = 3,
    MULW = 4
};

/// Helper to convert a u64 value to a Word<T> (4 x u16 limbs stored as field elements).
template <class T>
__device__ void u64_to_word(const uint64_t value, sp1_gpu_sys::Word<T>& word) {
    word._0[0] = T::from_canonical_u32(value & 0xFFFF);
    word._0[1] = T::from_canonical_u32((value >> 16) & 0xFFFF);
    word._0[2] = T::from_canonical_u32((value >> 32) & 0xFFFF);
    word._0[3] = T::from_canonical_u32((value >> 48) & 0xFFFF);
}

/// Populate RegisterAccessTimestamp from prev_timestamp and current_timestamp.
template <class T>
__device__ void populate_register_access_timestamp(
    sp1_gpu_sys::RegisterAccessTimestamp<T>& ts,
    uint64_t prev_timestamp,
    uint64_t current_timestamp) {
    // Extract high and low parts of timestamps
    uint32_t prev_high = prev_timestamp >> 24;
    uint32_t prev_low_val = prev_timestamp & 0xFFFFFF;
    uint32_t current_high = current_timestamp >> 24;
    uint32_t current_low_val = current_timestamp & 0xFFFFFF;

    // If in same high region, use actual prev_low; otherwise use 0
    uint32_t old_timestamp = (prev_high == current_high) ? prev_low_val : 0;
    ts.prev_low = T::from_canonical_u32(old_timestamp);

    // Compute diff_low_limb
    uint32_t diff_minus_one = current_low_val - old_timestamp - 1;
    uint16_t diff_low_limb = diff_minus_one & 0xFFFF;
    ts.diff_low_limb = T::from_canonical_u32(diff_low_limb);
}

/// Populate RegisterAccessCols from GpuMemoryAccess.
template <class T>
__device__ void populate_register_access_cols(
    sp1_gpu_sys::RegisterAccessCols<T>& cols,
    const sp1_gpu_sys::GpuMemoryAccess& mem) {
    u64_to_word(mem.prev_value, cols.prev_value);
    populate_register_access_timestamp(cols.access_timestamp, mem.prev_timestamp, mem.current_timestamp);
}

/// Populate CPUState from clock and program counter.
template <class T>
__device__ void populate_cpu_state(sp1_gpu_sys::CPUState<T>& state, uint64_t clk, uint64_t pc) {
    uint32_t clk_high = clk >> 24;
    uint8_t clk_16_24 = (clk >> 16) & 0xFF;
    uint16_t clk_0_16 = clk & 0xFFFF;

    state.clk_high = T::from_canonical_u32(clk_high);
    state.clk_16_24 = T::from_canonical_u32(clk_16_24);
    state.clk_0_16 = T::from_canonical_u32(clk_0_16);

    // PC is stored as 3 x 16-bit limbs
    state.pc[0] = T::from_canonical_u32(pc & 0xFFFF);
    state.pc[1] = T::from_canonical_u32((pc >> 16) & 0xFFFF);
    state.pc[2] = T::from_canonical_u32((pc >> 32) & 0xFFFF);
}

/// Populate RTypeReader from the GPU event data.
template <class T>
__device__ void populate_r_type_reader(sp1_gpu_sys::RTypeReader<T>& adapter, const sp1_gpu_sys::MulGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    // op_b and op_c are register specifiers, which are small values
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    adapter.op_c = T::from_canonical_u32(static_cast<uint32_t>(event.op_c));
    populate_register_access_cols(adapter.op_c_memory, event.mem_c);
}

/// Get MSB of a 64-bit value (the sign bit).
__device__ uint8_t get_msb(uint64_t val) {
    return (val >> 63) & 1;
}

/// Populate U16toU8Operation - stores low bytes of each u16 limb.
template <class T>
__device__ void populate_u16_to_u8(sp1_gpu_sys::U16toU8Operation<T>& op, uint64_t val) {
    // val is stored as 4 x u16 limbs, we need the low byte of each limb
    op.low_bytes[0] = T::from_canonical_u32(val & 0xFF);
    op.low_bytes[1] = T::from_canonical_u32((val >> 16) & 0xFF);
    op.low_bytes[2] = T::from_canonical_u32((val >> 32) & 0xFF);
    op.low_bytes[3] = T::from_canonical_u32((val >> 48) & 0xFF);
}

/// Populate MulOperation from operands b and c and opcode.
/// This implements the full multiplication logic with sign extension handling.
template <class T>
__device__ void populate_mul_operation(
    sp1_gpu_sys::MulOperation<T>& op,
    uint64_t b_u64,
    uint64_t c_u64,
    uint8_t opcode) {

    bool is_mulh = (opcode == MULH);
    bool is_mulhsu = (opcode == MULHSU);
    bool is_mulw = (opcode == MULW);

    // Handle MULW product MSB
    if (is_mulw) {
        // MULW: 32-bit signed multiply, result sign-extended
        int32_t b32 = static_cast<int32_t>(b_u64);
        int32_t c32 = static_cast<int32_t>(c_u64);
        int64_t mulw_result = static_cast<int64_t>(b32) * static_cast<int64_t>(c32);
        uint64_t mulw_value = static_cast<uint64_t>(mulw_result);
        // Get limbs[1] (second u16 limb) and compute its MSB
        uint16_t limb1 = (mulw_value >> 16) & 0xFFFF;
        op.product_msb.msb = T::from_canonical_u32((limb1 >> 15) & 1);
    } else {
        op.product_msb.msb = T::zero();
    }

    // Populate b_lower_byte and c_lower_byte
    populate_u16_to_u8(op.b_lower_byte, b_u64);
    populate_u16_to_u8(op.c_lower_byte, c_u64);

    // Get MSBs of b and c
    uint8_t b_msb = get_msb(b_u64);
    uint8_t c_msb = get_msb(c_u64);
    op.b_msb = T::from_canonical_u32(b_msb);
    op.c_msb = T::from_canonical_u32(c_msb);

    // Prepare byte arrays for b and c
    uint8_t b[LONG_WORD_BYTE_SIZE];
    uint8_t c[LONG_WORD_BYTE_SIZE];

    // Initialize with the 8 bytes of b and c
    for (int i = 0; i < WORD_BYTE_SIZE; i++) {
        b[i] = (b_u64 >> (i * 8)) & 0xFF;
        c[i] = (c_u64 >> (i * 8)) & 0xFF;
    }

    // Sign extension for MULH and MULHSU
    // b is signed for MULH and MULHSU, c is signed only for MULH
    bool b_sign_extend = (is_mulh || is_mulhsu) && (b_msb == 1);
    bool c_sign_extend = is_mulh && (c_msb == 1);

    op.b_sign_extend = b_sign_extend ? T::one() : T::zero();
    op.c_sign_extend = c_sign_extend ? T::one() : T::zero();

    // Fill upper bytes with sign extension
    for (int i = WORD_BYTE_SIZE; i < LONG_WORD_BYTE_SIZE; i++) {
        b[i] = b_sign_extend ? BYTE_MASK : 0;
        c[i] = c_sign_extend ? BYTE_MASK : 0;
    }

    // Compute the uncarried product: b * c
    uint32_t product[LONG_WORD_BYTE_SIZE] = {0};
    for (int i = 0; i < (b_sign_extend || c_sign_extend ? LONG_WORD_BYTE_SIZE : WORD_BYTE_SIZE); i++) {
        for (int j = 0; j < (b_sign_extend || c_sign_extend ? LONG_WORD_BYTE_SIZE : WORD_BYTE_SIZE); j++) {
            if (i + j < LONG_WORD_BYTE_SIZE) {
                product[i + j] += static_cast<uint32_t>(b[i]) * static_cast<uint32_t>(c[j]);
            }
        }
    }

    // For non-signed multiplication, only iterate over WORD_BYTE_SIZE
    if (!b_sign_extend && !c_sign_extend) {
        // Already done above with WORD_BYTE_SIZE
    }

    // Carry propagation
    uint32_t base = 1 << BYTE_SIZE; // 256
    uint32_t carry[LONG_WORD_BYTE_SIZE] = {0};

    for (int i = 0; i < LONG_WORD_BYTE_SIZE; i++) {
        carry[i] = product[i] / base;
        product[i] = product[i] % base;
        if (i + 1 < LONG_WORD_BYTE_SIZE) {
            product[i + 1] += carry[i];
        }
        op.carry[i] = T::from_canonical_u32(carry[i]);
    }

    // Store the final product
    for (int i = 0; i < LONG_WORD_BYTE_SIZE; i++) {
        op.product[i] = T::from_canonical_u32(product[i]);
    }
}

/// Main kernel for MulChip trace generation.
template <class T>
__global__ void riscv_mul_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::MulGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::MulCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::MulCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate opcode flags
            cols.is_mul = T::from_bool(event.opcode == MUL);
            cols.is_mulh = T::from_bool(event.opcode == MULH);
            cols.is_mulhu = T::from_bool(event.opcode == MULHU);
            cols.is_mulhsu = T::from_bool(event.opcode == MULHSU);
            cols.is_mulw = T::from_bool(event.opcode == MULW);

            // Populate 'a' (result) word
            u64_to_word(event.a, cols.a);

            // Populate mul_operation
            populate_mul_operation(cols.mul_operation, event.b, event.c, event.opcode);

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate RTypeReader from event
            populate_r_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_mul_generate_trace_kernel() {
    return (KernelPtr)::riscv_mul_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
