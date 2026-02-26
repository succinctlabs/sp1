/// GPU trace generation for RISC-V ShiftRightChip.
///
/// Handles SRL, SRLI (shift right logical), SRA, SRAI (shift right arithmetic),
/// and their 32-bit variants SRLW, SRLIW, SRAW, SRAIW.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define ShiftRightCols since cbindgen can't handle
// constant expression array sizes.
namespace sp1_gpu_sys {

// Number of bits representing shift amount in lower byte
static constexpr size_t SR_SHIFT_BITS = 6;

template <typename T>
struct ShiftRightCols {
    /// The current shard, timestamp, program counter of the CPU.
    CPUState<T> state;

    /// The adapter to read program and register information.
    ALUTypeReader<T> adapter;

    /// The output operand.
    Word<T> a;

    /// The most significant bit of `b`.
    U16MSBOperation<T> b_msb;

    /// The most significant byte of the result of SRLW/SRAW/SRLIW/SRAIW
    U16MSBOperation<T> srw_msb;

    /// The bottom 6 bits of `c`.
    T c_bits[SR_SHIFT_BITS];

    /// SRA msb * v0123
    T sra_msb_v0123;

    /// v0123
    T v_0123;

    /// v012
    T v_012;

    /// v01
    T v_01;

    /// The lower bits of each limb.
    Word<T> lower_limb;

    /// The higher bits of each limb.
    Word<T> higher_limb;

    /// The result of the byte-shift.
    T limb_result[WORD_SIZE];

    /// The shift amount.
    T shift_u16[WORD_SIZE];

    /// If the opcode is SRL.
    T is_srl;

    /// If the opcode is SRA.
    T is_sra;

    /// If the opcode is SRLW.
    T is_srlw;

    /// If the opcode is SRAW.
    T is_sraw;

    /// If the opcode is W and immediate.
    T is_w_imm;
};

} // namespace sp1_gpu_sys

// Opcode values for ShiftRight operations
enum ShiftRightOpcode : uint8_t {
    SRL_OP = 0,
    SRA_OP = 1,
    SRLW_OP = 2,
    SRAW_OP = 3,
};

/// GPU event structure for ShiftRightChip.
/// Uses ALUTypeReader format since it supports immediate mode.
struct ShiftRightGpuEvent {
    // From AluEvent
    uint64_t clk;
    uint64_t pc;
    uint64_t b;
    uint64_t c;
    uint64_t a; // Result

    // Opcode: SRL=0, SRA=1, SRLW=2, SRAW=3
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

/// Populate ALUTypeReader from ShiftRightGpuEvent.
template <class T>
__device__ void populate_shift_right_alu_type_reader(
    sp1_gpu_sys::ALUTypeReader<T>& adapter,
    const ShiftRightGpuEvent& event) {
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
        adapter.op_c_memory.prev_value = adapter.op_c;
        adapter.op_c_memory.access_timestamp.diff_low_limb = T::zero();
        adapter.op_c_memory.access_timestamp.prev_low = T::zero();
    } else {
        populate_register_access_cols(adapter.op_c_memory, event.mem_c);
    }
}

/// Main kernel for ShiftRightChip trace generation.
template <class T>
__global__ void riscv_shift_right_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const ShiftRightGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::ShiftRightCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::ShiftRightCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        // For padding rows, set v_01, v_012, v_0123 to their padding values
        // v_01 = 1 << (4 - 0) = 16
        // v_012 = 1 << (8 - 0) = 256
        // v_0123 = 1 << (16 - 0) = 65536
        cols.v_01 = T::from_canonical_u32(16);
        cols.v_012 = T::from_canonical_u32(256);
        cols.v_0123 = T::from_canonical_u32(65536);

        if (i < nb_events) {
            const auto& event = events[i];

            // Get the shift amount from the lower 16 bits of c
            uint16_t c = static_cast<uint16_t>(event.c & 0xFFFF);

            // Populate opcode flags
            bool is_srl = (event.opcode == SRL_OP);
            bool is_sra = (event.opcode == SRA_OP);
            bool is_srlw = (event.opcode == SRLW_OP);
            bool is_sraw = (event.opcode == SRAW_OP);
            bool is_word = is_srlw || is_sraw;
            bool not_word = is_srl || is_sra;

            cols.is_srl = T::from_bool(is_srl);
            cols.is_sra = T::from_bool(is_sra);
            cols.is_srlw = T::from_bool(is_srlw);
            cols.is_sraw = T::from_bool(is_sraw);
            cols.is_w_imm = T::from_bool(is_word && event.is_imm);

            // Populate the result a
            u64_to_word(event.a, cols.a);

            // Populate c_bits (lowest 6 bits of c)
            for (size_t j = 0; j < 6; j++) {
                cols.c_bits[j] = T::from_canonical_u32((c >> j) & 1);
            }

            // Compute v_01 = 1 << (4 - (c & 3))  [inverse of ShiftLeft]
            cols.v_01 = T::from_canonical_u32(1 << (4 - (c & 3)));

            // Compute v_012 = 1 << (8 - (c & 7))
            cols.v_012 = T::from_canonical_u32(1 << (8 - (c & 7)));

            // Compute v_0123 = 1 << (16 - (c & 15))
            cols.v_0123 = T::from_canonical_u32(1 << (16 - (c & 15)));

            // Get b as u16 limbs, zeroing upper limbs for word ops
            uint64_t b_val = event.b;
            uint16_t b_limbs[4];
            b_limbs[0] = b_val & 0xFFFF;
            b_limbs[1] = (b_val >> 16) & 0xFFFF;
            b_limbs[2] = (b_val >> 32) & 0xFFFF;
            b_limbs[3] = (b_val >> 48) & 0xFFFF;

            // Populate b_msb
            if (is_sra) {
                // For SRA, MSB of full 64-bit b (limb 3)
                cols.b_msb.msb = T::from_canonical_u32((b_limbs[3] >> 15) & 1);
            } else if (is_sraw) {
                // For SRAW, MSB of 32-bit b (limb 1)
                cols.b_msb.msb = T::from_canonical_u32((b_limbs[1] >> 15) & 1);
            } else {
                cols.b_msb.msb = T::zero();
            }

            // Compute sra_msb_v0123 = b_msb.msb * v_0123
            // For field multiplication, we need to compute this properly
            uint32_t b_msb_val = 0;
            if (is_sra) {
                b_msb_val = (b_limbs[3] >> 15) & 1;
            } else if (is_sraw) {
                b_msb_val = (b_limbs[1] >> 15) & 1;
            }
            uint32_t v0123_val = 1u << (16 - (c & 15));
            cols.sra_msb_v0123 = T::from_canonical_u32(b_msb_val * v0123_val);

            // For word operations, zero the upper limbs
            if (is_word) {
                b_limbs[2] = 0;
                b_limbs[3] = 0;
            }

            // Populate srw_msb for word operations
            if (is_word) {
                uint16_t a_limbs[4];
                a_limbs[0] = event.a & 0xFFFF;
                a_limbs[1] = (event.a >> 16) & 0xFFFF;
                cols.srw_msb.msb = T::from_canonical_u32((a_limbs[1] >> 15) & 1);
            } else {
                cols.srw_msb.msb = T::zero();
            }

            // Bit shift within limbs (c & 0xF) - note: for right shift, lower/higher are swapped
            uint8_t bit_shift = c & 0xF;

            // Compute lower_limb and higher_limb for each limb
            // For right shift: lower_limb = bits below bit_shift, higher_limb = bits at/above
            // bit_shift
            for (size_t j = 0; j < 4; j++) {
                uint32_t limb = b_limbs[j];
                uint16_t lower_limb = (limb & ((1 << bit_shift) - 1)) & 0xFFFF;
                uint16_t higher_limb = (limb >> bit_shift) & 0xFFFF;

                cols.lower_limb._0[j] = T::from_canonical_u32(lower_limb);
                cols.higher_limb._0[j] = T::from_canonical_u32(higher_limb);
            }

            // Compute limb_result
            // For right shift: limb_result[i] = higher_limb[i] + lower_limb[i+1] * (1 << (16 -
            // bit_shift))
            for (size_t j = 0; j < 4; j++) {
                uint16_t higher_val = (b_limbs[j] >> bit_shift) & 0xFFFF;
                uint32_t limb_result = higher_val;
                if (j != 3) {
                    uint16_t next_lower = b_limbs[j + 1] & ((1 << bit_shift) - 1);
                    limb_result += static_cast<uint32_t>(next_lower) << (16 - bit_shift);
                }
                cols.limb_result[j] = T::from_canonical_u32(limb_result & 0xFFFF);
            }

            // Compute shift_amount for u16 limb shifting
            // For SRL/SRA (64-bit): use bits 4-5
            // For SRLW/SRAW (32-bit): only use bit 4
            uint16_t shift_amount = ((c >> 4) & 1) + 2 * ((c >> 5) & 1) * (not_word ? 1 : 0);

            // Set shift_u16 flags (one-hot encoding)
            for (size_t j = 0; j < 4; j++) {
                cols.shift_u16[j] = T::from_bool(j == shift_amount);
            }

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ALUTypeReader from event
            populate_shift_right_alu_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_shift_right_generate_trace_kernel() {
    return (KernelPtr)::riscv_shift_right_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
