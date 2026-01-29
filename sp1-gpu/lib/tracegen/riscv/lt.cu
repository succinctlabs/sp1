/// GPU trace generation for RISC-V LtChip.
///
/// Handles SLT (set less than, signed) and SLTU (set less than, unsigned) instructions.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define LtOperationSigned and related types since cbindgen can't handle
// constant expression array sizes like [T; WORD_SIZE].
namespace sp1_gpu_sys {

template <typename T>
struct U16CompareOperation {
    /// The result of the compare operation (1 if b < c, 0 if b >= c).
    T bit;
};

template <typename T>
struct LtOperationUnsigned {
    /// Instance of the U16CompareOperation.
    U16CompareOperation<T> u16_compare_operation;
    /// Boolean flag to indicate which limb pair differs if the operands are not equal.
    T u16_flags[WORD_SIZE];
    /// An inverse of differing limb if b_comp != c_comp.
    T not_eq_inv;
    /// The comparison limbs to be looked up.
    T comparison_limbs[2];
};

template <typename T>
struct LtOperationSigned {
    /// The result of the SLTU operation.
    LtOperationUnsigned<T> result;
    /// The most significant bit of operand b if is_signed is true.
    U16MSBOperation<T> b_msb;
    /// The most significant bit of operand c if is_signed is true.
    U16MSBOperation<T> c_msb;
};

template <typename T>
struct LtCols {
    /// The current shard, timestamp, program counter of the CPU.
    CPUState<T> state;
    /// The adapter to read program and register information.
    ALUTypeReader<T> adapter;
    /// If the opcode is SLT.
    T is_slt;
    /// If the opcode is SLTU.
    T is_sltu;
    /// Instance of LtOperationSigned to handle comparison logic.
    LtOperationSigned<T> lt_operation;
};

} // namespace sp1_gpu_sys

// Opcode values for Lt operations
enum LtOpcode : uint8_t {
    SLT = 0,  // Signed less than
    SLTU = 1, // Unsigned less than
};

/// GPU event structure for LtChip.
/// Uses ALUTypeReader format (same as AddwChip) since it supports immediate mode (SLTI, SLTIU).
struct LtGpuEvent {
    // From AluEvent
    uint64_t clk;
    uint64_t pc;
    uint64_t b;
    uint64_t c;
    uint64_t a; // Result (0 or 1)

    // Opcode: SLT=0, SLTU=1
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

/// Extract u16 limbs from a u64 value.
__device__ void u64_to_u16_limbs(uint64_t value, uint16_t limbs[WORD_SIZE]) {
    limbs[0] = value & 0xFFFF;
    limbs[1] = (value >> 16) & 0xFFFF;
    limbs[2] = (value >> 32) & 0xFFFF;
    limbs[3] = (value >> 48) & 0xFFFF;
}

/// Compute modular inverse (reciprocal) of (b_limb - c_limb) in the KoalaBear field.
/// Uses the field's built-in reciprocal() method which computes a^(p-2) mod p.
__device__ kb31_t compute_field_inverse(uint32_t b_limb, uint32_t c_limb) {
    // Convert to field elements and compute subtraction in the field
    kb31_t b_field = kb31_t::from_canonical_u32(b_limb);
    kb31_t c_field = kb31_t::from_canonical_u32(c_limb);
    kb31_t diff = b_field - c_field;

    // Compute multiplicative inverse (reciprocal) in the field
    return diff.reciprocal();
}

/// Populate LtOperationSigned from operands and opcode.
template <class T>
__device__ void populate_lt_operation(
    sp1_gpu_sys::LtOperationSigned<T>& op,
    uint64_t a_u64,
    uint64_t b_u64,
    uint64_t c_u64,
    bool is_signed) {

    // Get the u16 limbs of b and c
    uint16_t b_limbs[WORD_SIZE];
    uint16_t c_limbs[WORD_SIZE];
    u64_to_u16_limbs(b_u64, b_limbs);
    u64_to_u16_limbs(c_u64, c_limbs);

    // For signed comparison, we XOR the sign bit (bit 63) to convert signed to unsigned comparison
    uint64_t b_comp = b_u64;
    uint64_t c_comp = c_u64;

    if (is_signed) {
        // Populate MSB operations for signed comparison
        uint16_t b_high = b_limbs[WORD_SIZE - 1];
        uint16_t c_high = c_limbs[WORD_SIZE - 1];
        op.b_msb.msb = T::from_canonical_u32((b_high >> 15) & 1);
        op.c_msb.msb = T::from_canonical_u32((c_high >> 15) & 1);

        // XOR with 1 << 63 to convert signed comparison to unsigned
        b_comp = b_u64 ^ (1ULL << 63);
        c_comp = c_u64 ^ (1ULL << 63);
    } else {
        // For unsigned, MSB operations are zero
        op.b_msb.msb = T::zero();
        op.c_msb.msb = T::zero();
    }

    // Get comparison limbs
    uint16_t b_comp_limbs[WORD_SIZE];
    uint16_t c_comp_limbs[WORD_SIZE];
    u64_to_u16_limbs(b_comp, b_comp_limbs);
    u64_to_u16_limbs(c_comp, c_comp_limbs);

    // Initialize all u16_flags to zero
    for (int i = 0; i < WORD_SIZE; i++) {
        op.result.u16_flags[i] = T::zero();
    }
    op.result.not_eq_inv = T::zero();
    op.result.comparison_limbs[0] = T::zero();
    op.result.comparison_limbs[1] = T::zero();

    // Find the most significant differing limb (iterate from high to low)
    uint16_t comp_b_limb = 0;
    uint16_t comp_c_limb = 0;
    for (int i = WORD_SIZE - 1; i >= 0; i--) {
        if (b_comp_limbs[i] != c_comp_limbs[i]) {
            op.result.u16_flags[i] = T::one();
            comp_b_limb = b_comp_limbs[i];
            comp_c_limb = c_comp_limbs[i];

            // Compute inverse of (b_limb - c_limb) in the field
            op.result.not_eq_inv = compute_field_inverse(comp_b_limb, comp_c_limb);
            op.result.comparison_limbs[0] = T::from_canonical_u32(comp_b_limb);
            op.result.comparison_limbs[1] = T::from_canonical_u32(comp_c_limb);
            break;
        }
    }

    // The result of the comparison (0 or 1)
    uint16_t a_u16 = (uint16_t)(a_u64 & 1);
    op.result.u16_compare_operation.bit = T::from_canonical_u32(a_u16);
}

/// Populate ALUTypeReader from LtGpuEvent.
/// This is similar to addw but uses LtGpuEvent structure.
template <class T>
__device__ void
populate_lt_alu_type_reader(sp1_gpu_sys::ALUTypeReader<T>& adapter, const LtGpuEvent& event) {
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

/// Main kernel for LtChip trace generation.
template <class T>
__global__ void riscv_lt_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const LtGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::LtCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::LtCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            bool is_slt = (event.opcode == SLT);

            // Populate opcode flags
            cols.is_slt = T::from_bool(is_slt);
            cols.is_sltu = T::from_bool(!is_slt);

            // Populate lt_operation
            populate_lt_operation(cols.lt_operation, event.a, event.b, event.c, is_slt);

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ALUTypeReader from event
            populate_lt_alu_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_lt_generate_trace_kernel() {
    return (KernelPtr)::riscv_lt_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
