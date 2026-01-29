/// GPU trace generation for RISC-V BranchChip.
///
/// Handles BEQ, BNE, BLT, BGE, BLTU, BGEU instructions.

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

/// BranchColumns: column layout for branch instructions.
/// Matches: sp1-wip/crates/core/machine/src/control_flow/branch/columns.rs
template <typename T>
struct BranchCols {
    /// The current shard, timestamp, program counter of the CPU.
    CPUState<T> state;
    /// The adapter to read program and register information.
    ITypeReader<T> adapter;
    /// The next program counter (3 x u16 limbs).
    T next_pc[3];
    /// Branch instruction opcode flags.
    T is_beq;
    T is_bne;
    T is_blt;
    T is_bge;
    T is_bltu;
    T is_bgeu;
    /// Whether the branch is taken.
    T is_branching;
    /// The comparison between a and b.
    LtOperationSigned<T> compare_operation;
};

} // namespace sp1_gpu_sys

// Opcode values for Branch operations
enum BranchOpcode : uint8_t {
    BEQ = 0,
    BNE = 1,
    BLT = 2,
    BGE = 3,
    BLTU = 4,
    BGEU = 5,
};

/// Extract u16 limbs from a u64 value.
__device__ void branch_u64_to_u16_limbs(uint64_t value, uint16_t limbs[WORD_SIZE]) {
    limbs[0] = value & 0xFFFF;
    limbs[1] = (value >> 16) & 0xFFFF;
    limbs[2] = (value >> 32) & 0xFFFF;
    limbs[3] = (value >> 48) & 0xFFFF;
}

/// Compute modular inverse (reciprocal) of (b_limb - c_limb) in the KoalaBear field.
__device__ kb31_t branch_compute_field_inverse(uint32_t b_limb, uint32_t c_limb) {
    kb31_t b_field = kb31_t::from_canonical_u32(b_limb);
    kb31_t c_field = kb31_t::from_canonical_u32(c_limb);
    kb31_t diff = b_field - c_field;
    return diff.reciprocal();
}

/// Populate LtOperationSigned from operands.
/// `a_lt_b` is 1 if a < b (the comparison result), 0 otherwise.
template <class T>
__device__ void populate_branch_lt_operation(
    sp1_gpu_sys::LtOperationSigned<T>& op,
    uint64_t a_lt_b,
    uint64_t a_u64,
    uint64_t b_u64,
    bool is_signed) {
    // Get the u16 limbs of a and b
    uint16_t a_limbs[WORD_SIZE];
    uint16_t b_limbs[WORD_SIZE];
    branch_u64_to_u16_limbs(a_u64, a_limbs);
    branch_u64_to_u16_limbs(b_u64, b_limbs);

    // For signed comparison, we XOR the sign bit (bit 63) to convert signed to unsigned comparison
    uint64_t a_comp = a_u64;
    uint64_t b_comp = b_u64;

    if (is_signed) {
        // Populate MSB operations for signed comparison
        uint16_t a_high = a_limbs[WORD_SIZE - 1];
        uint16_t b_high = b_limbs[WORD_SIZE - 1];
        op.b_msb.msb = T::from_canonical_u32((a_high >> 15) & 1);
        op.c_msb.msb = T::from_canonical_u32((b_high >> 15) & 1);

        // XOR with 1 << 63 to convert signed comparison to unsigned
        a_comp = a_u64 ^ (1ULL << 63);
        b_comp = b_u64 ^ (1ULL << 63);
    } else {
        op.b_msb.msb = T::zero();
        op.c_msb.msb = T::zero();
    }

    // Get comparison limbs
    uint16_t a_comp_limbs[WORD_SIZE];
    uint16_t b_comp_limbs[WORD_SIZE];
    branch_u64_to_u16_limbs(a_comp, a_comp_limbs);
    branch_u64_to_u16_limbs(b_comp, b_comp_limbs);

    // Initialize all u16_flags to zero
    for (int i = 0; i < WORD_SIZE; i++) {
        op.result.u16_flags[i] = T::zero();
    }
    op.result.not_eq_inv = T::zero();
    op.result.comparison_limbs[0] = T::zero();
    op.result.comparison_limbs[1] = T::zero();

    // Find the most significant differing limb (iterate from high to low)
    for (int i = WORD_SIZE - 1; i >= 0; i--) {
        if (a_comp_limbs[i] != b_comp_limbs[i]) {
            op.result.u16_flags[i] = T::one();

            // Compute inverse of (a_limb - b_limb) in the field
            op.result.not_eq_inv = branch_compute_field_inverse(a_comp_limbs[i], b_comp_limbs[i]);
            op.result.comparison_limbs[0] = T::from_canonical_u32(a_comp_limbs[i]);
            op.result.comparison_limbs[1] = T::from_canonical_u32(b_comp_limbs[i]);
            break;
        }
    }

    // The result of the comparison (0 or 1)
    op.result.u16_compare_operation.bit = T::from_canonical_u32((uint32_t)(a_lt_b & 1));
}

/// Populate ITypeReader from BranchGpuEvent.
template <class T>
__device__ void populate_branch_i_type_reader(
    sp1_gpu_sys::ITypeReader<T>& adapter,
    const sp1_gpu_sys::BranchGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a_0);

    // op_b is a register specifier
    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    // op_c is an immediate value stored as a Word
    u64_to_word(event.op_c, adapter.op_c_imm);
}

/// Main kernel for BranchChip trace generation.
template <class T>
__global__ void riscv_branch_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::BranchGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::BranchCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::BranchCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            uint8_t opcode = event.opcode;

            // Populate opcode flags
            cols.is_beq = T::from_bool(opcode == BEQ);
            cols.is_bne = T::from_bool(opcode == BNE);
            cols.is_blt = T::from_bool(opcode == BLT);
            cols.is_bge = T::from_bool(opcode == BGE);
            cols.is_bltu = T::from_bool(opcode == BLTU);
            cols.is_bgeu = T::from_bool(opcode == BGEU);

            // Determine if the comparison is signed
            bool use_signed_comparison = (opcode == BLT) || (opcode == BGE);

            // Compute a_eq_b and a_lt_b
            bool a_eq_b = (event.a == event.b);
            bool a_lt_b;
            if (use_signed_comparison) {
                a_lt_b = ((int64_t)event.a < (int64_t)event.b);
            } else {
                a_lt_b = (event.a < event.b);
            }

            // Compute branching flag
            bool branching;
            switch (opcode) {
            case BEQ:
                branching = a_eq_b;
                break;
            case BNE:
                branching = !a_eq_b;
                break;
            case BLT:
            case BLTU:
                branching = a_lt_b;
                break;
            case BGE:
            case BGEU:
                branching = !a_lt_b;
                break;
            default:
                branching = false;
                break;
            }

            cols.is_branching = T::from_bool(branching);

            // Populate compare_operation
            // Note: The CPU code calls populate_signed(a_lt_b, event.a, event.b, is_signed)
            // where the first arg is the comparison result as u64.
            populate_branch_lt_operation(
                cols.compare_operation,
                (uint64_t)a_lt_b,
                event.a,
                event.b,
                use_signed_comparison);

            // Populate next_pc as 3 x u16 limbs
            cols.next_pc[0] = T::from_canonical_u32(event.next_pc & 0xFFFF);
            cols.next_pc[1] = T::from_canonical_u32((event.next_pc >> 16) & 0xFFFF);
            cols.next_pc[2] = T::from_canonical_u32((event.next_pc >> 32) & 0xFFFF);

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate ITypeReader from event
            populate_branch_i_type_reader(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_branch_generate_trace_kernel() {
    return (KernelPtr)::riscv_branch_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
