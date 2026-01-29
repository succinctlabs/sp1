/// GPU trace generation for RISC-V ShiftLeftChip.
///
/// Handles SLL, SLLI (shift left logical) and SLLW, SLLIW (shift left word) instructions.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define ShiftLeftCols since cbindgen can't handle
// constant expression array sizes.
namespace sp1_gpu_sys {

// Number of bits representing shift amount in lower byte
static constexpr size_t SHIFT_BITS = 6;

// U16MSBOperation is already defined in cbindgen header

template <typename T>
struct ShiftLeftCols {
    /// The current shard, timestamp, program counter of the CPU.
    CPUState<T> state;

    /// The adapter to read program and register information.
    ALUTypeReader<T> adapter;

    /// The output operand.
    Word<T> a;

    /// The lowest 6 bits of `c` (shift amount bits).
    T c_bits[SHIFT_BITS];

    /// v01 = (c0 + 1) * (3c1 + 1)
    T v_01;

    /// v012 = (c0 + 1) * (3c1 + 1) * (15c2 + 1)
    T v_012;

    /// v012 * c3
    T v_0123;

    /// Flags representing c4 + 2c5 (which u16 limb to start from).
    T shift_u16[WORD_SIZE];

    /// The lower bits of each limb.
    Word<T> lower_limb;

    /// The higher bits of each limb.
    Word<T> higher_limb;

    /// The limb results.
    Word<T> limb_result;

    /// The most significant byte of the result of SLLW.
    U16MSBOperation<T> sllw_msb;

    /// If the opcode is SLL.
    T is_sll;

    /// If the opcode is SLLW.
    T is_sllw;

    /// If the opcode is SLLW and immediate.
    T is_sllw_imm;
};

} // namespace sp1_gpu_sys

// Opcode values for ShiftLeft operations
enum ShiftLeftOpcode : uint8_t {
    SLL_OP = 0,
    SLLW_OP = 1,
};

/// GPU event structure for ShiftLeftChip.
/// Uses ALUTypeReader format since it supports immediate mode (SLLI, SLLIW).
struct ShiftLeftGpuEvent {
    // From AluEvent
    uint64_t clk;
    uint64_t pc;
    uint64_t b;
    uint64_t c;
    uint64_t a; // Result

    // Opcode: SLL=0, SLLW=1
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

/// Populate ALUTypeReader from ShiftLeftGpuEvent.
template <class T>
__device__ void populate_shift_left_alu_type_reader(
    sp1_gpu_sys::ALUTypeReader<T>& adapter,
    const ShiftLeftGpuEvent& event) {
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

/// Populate U16MSBOperation from the second u16 limb of a 32-bit value.
template <class T>
__device__ void populate_sllw_msb(sp1_gpu_sys::U16MSBOperation<T>& op, uint16_t limb1) {
    op.msb = T::from_canonical_u32((limb1 >> 15) & 1);
}

/// Main kernel for ShiftLeftChip trace generation.
template <class T>
__global__ void riscv_shift_left_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const ShiftLeftGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::ShiftLeftCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::ShiftLeftCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        // For padding rows, set v_01, v_012, v_0123 to 1
        cols.v_01 = T::one();
        cols.v_012 = T::one();
        cols.v_0123 = T::one();

        if (i < nb_events) {
            const auto& event = events[i];

            // Get the shift amount from the lower 16 bits of c
            uint16_t c = static_cast<uint16_t>(event.c & 0xFFFF);

            // Populate opcode flags
            bool is_sll = (event.opcode == SLL_OP);
            bool is_sllw = (event.opcode == SLLW_OP);
            cols.is_sll = T::from_bool(is_sll);
            cols.is_sllw = T::from_bool(is_sllw);
            cols.is_sllw_imm = T::from_bool(is_sllw && event.is_imm);

            // Populate the result a
            u64_to_word(event.a, cols.a);

            // Populate c_bits (lowest 6 bits of c)
            for (size_t j = 0; j < 6; j++) {
                cols.c_bits[j] = T::from_canonical_u32((c >> j) & 1);
            }

            // Compute v_01 = 1 << (c & 3)
            // v_01 = (c0 + 1) * (3*c1 + 1)
            cols.v_01 = T::from_canonical_u32(1 << (c & 3));

            // Compute v_012 = 1 << (c & 7)
            // v_012 = v_01 * (15*c2 + 1)
            cols.v_012 = T::from_canonical_u32(1 << (c & 7));

            // Compute v_0123 = 1 << (c & 15)
            // v_0123 = v_012 * (255*c3 + 1)
            cols.v_0123 = T::from_canonical_u32(1 << (c & 15));

            // Compute shift_amount for u16 limb shifting
            // For SLL: use bits 4-5 (values 0-3)
            // For SLLW: only use bit 4 (values 0-1, since 32-bit uses 2 limbs)
            uint16_t shift_amount = ((c >> 4) & 1) + 2 * ((c >> 5) & 1) * (is_sll ? 1 : 0);

            // Set shift_u16 flags (one-hot encoding)
            for (size_t j = 0; j < 4; j++) {
                cols.shift_u16[j] = T::from_bool(j == shift_amount);
            }

            // Get b as u16 limbs
            uint64_t b = event.b;
            uint16_t b_limbs[4];
            b_limbs[0] = b & 0xFFFF;
            b_limbs[1] = (b >> 16) & 0xFFFF;
            b_limbs[2] = (b >> 32) & 0xFFFF;
            b_limbs[3] = (b >> 48) & 0xFFFF;

            // Bit shift within limbs (c & 0xF)
            uint8_t bit_shift = c & 0xF;

            // Compute lower_limb and higher_limb for each limb
            for (size_t j = 0; j < 4; j++) {
                uint32_t limb = b_limbs[j];
                // lower_limb has the bits that stay in this position (lower 16-bit_shift bits)
                uint16_t lower_limb = (limb & ((1 << (16 - bit_shift)) - 1)) & 0xFFFF;
                // higher_limb has the bits that overflow to the next limb (upper bit_shift bits)
                uint16_t higher_limb = (limb >> (16 - bit_shift)) & 0xFFFF;

                cols.lower_limb._0[j] = T::from_canonical_u32(lower_limb);
                cols.higher_limb._0[j] = T::from_canonical_u32(higher_limb);
            }

            // Compute limb_result
            // limb_result[i] = lower_limb[i] * (1 << bit_shift) + higher_limb[i-1]
            for (size_t j = 0; j < 4; j++) {
                uint16_t lower_val = (j == 0) ? (b_limbs[0] & ((1 << (16 - bit_shift)) - 1))
                                              : (b_limbs[j] & ((1 << (16 - bit_shift)) - 1));
                uint32_t limb_result = (static_cast<uint32_t>(lower_val) << bit_shift);
                if (j != 0) {
                    // Add the overflow from the previous limb
                    uint16_t prev_higher = (b_limbs[j - 1] >> (16 - bit_shift)) & 0xFFFF;
                    limb_result += prev_higher;
                }
                cols.limb_result._0[j] = T::from_canonical_u32(limb_result & 0xFFFF);
            }

            // For SLLW, populate sllw_msb
            if (is_sllw) {
                // SLLW shifts the lower 32 bits and sign-extends to 64 bits
                // The shift is only by the lower 5 bits of c (0-31 for 32-bit)
                uint32_t sllw_val = (static_cast<uint32_t>(event.b) << (c & 0x1f)) & 0xFFFFFFFF;
                uint16_t sllw_limb1 = (sllw_val >> 16) & 0xFFFF;
                populate_sllw_msb(cols.sllw_msb, sllw_limb1);
            } else {
                cols.sllw_msb.msb = T::zero();
            }

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ALUTypeReader from event
            populate_shift_left_alu_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_shift_left_generate_trace_kernel() {
    return (KernelPtr)::riscv_shift_left_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
