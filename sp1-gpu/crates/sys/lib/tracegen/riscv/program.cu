/// GPU trace generation for RISC-V ProgramChip.
///
/// ProgramChip has two traces:
/// 1. Preprocessed trace (16 columns): PC[3] + InstructionCols (opcode, op_a, op_b[4], op_c[4],
///    op_a_0, imm_b, imm_c).
/// 2. Main trace (1 column): multiplicity count per instruction.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Manually define ProgramPreprocessedCols since cbindgen can't resolve [T; 3] and Word<T>.
namespace sp1_gpu_sys {

template <typename T>
struct InstructionColsProgram {
    T opcode;
    T op_a;
    T op_b[4]; // Word<T> = 4 x u16 limbs
    T op_c[4]; // Word<T> = 4 x u16 limbs
    T op_a_0;
    T imm_b;
    T imm_c;
};

template <typename T>
struct ProgramPreprocessedCols {
    T pc[3];
    InstructionColsProgram<T> instruction;
};

template <typename T>
struct ProgramMultiplicityCols {
    T multiplicity;
};

} // namespace sp1_gpu_sys

/// Preprocessed trace kernel: populates PC + InstructionCols for each instruction.
///
/// Parameters:
///   trace: output trace buffer (column-major)
///   trace_height: padded height of the trace
///   instructions: array of ProgramGpuInstruction
///   nb_instructions: number of actual instructions
///   pc_base: base program counter value
template <class T>
__global__ void riscv_program_generate_preprocessed_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::ProgramGpuInstruction* instructions,
    uintptr_t nb_instructions,
    uint64_t pc_base) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::ProgramPreprocessedCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::ProgramPreprocessedCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // For padding rows (i >= nb_instructions), use index 0 to match CPU behavior.
        uintptr_t idx = (i < nb_instructions) ? i : 0;

        uint64_t pc = pc_base + idx * 4;
        cols.pc[0] = T::from_canonical_u32((uint32_t)(pc & 0xFFFF));
        cols.pc[1] = T::from_canonical_u32((uint32_t)((pc >> 16) & 0xFFFF));
        cols.pc[2] = T::from_canonical_u32((uint32_t)((pc >> 32) & 0xFFFF));

        const auto& instr = instructions[idx];
        cols.instruction.opcode = T::from_canonical_u32(instr.opcode);
        cols.instruction.op_a = T::from_canonical_u32(instr.op_a);

        // op_b as Word<T> (4 x u16 limbs)
        cols.instruction.op_b[0] = T::from_canonical_u32((uint32_t)(instr.op_b & 0xFFFF));
        cols.instruction.op_b[1] = T::from_canonical_u32((uint32_t)((instr.op_b >> 16) & 0xFFFF));
        cols.instruction.op_b[2] = T::from_canonical_u32((uint32_t)((instr.op_b >> 32) & 0xFFFF));
        cols.instruction.op_b[3] = T::from_canonical_u32((uint32_t)((instr.op_b >> 48) & 0xFFFF));

        // op_c as Word<T> (4 x u16 limbs)
        cols.instruction.op_c[0] = T::from_canonical_u32((uint32_t)(instr.op_c & 0xFFFF));
        cols.instruction.op_c[1] = T::from_canonical_u32((uint32_t)((instr.op_c >> 16) & 0xFFFF));
        cols.instruction.op_c[2] = T::from_canonical_u32((uint32_t)((instr.op_c >> 32) & 0xFFFF));
        cols.instruction.op_c[3] = T::from_canonical_u32((uint32_t)((instr.op_c >> 48) & 0xFFFF));

        cols.instruction.op_a_0 = T::from_canonical_u32(instr.op_a_0);
        cols.instruction.imm_b = T::from_canonical_u32(instr.imm_b);
        cols.instruction.imm_c = T::from_canonical_u32(instr.imm_c);

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

/// Main trace kernel: writes multiplicity counts.
///
/// Parameters:
///   trace: output trace buffer (column-major, 1 column)
///   trace_height: padded height of the trace
///   multiplicities: array of multiplicity counts (one per instruction)
///   nb_instructions: number of actual instructions
template <class T>
__global__ void riscv_program_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const uint32_t* multiplicities,
    uintptr_t nb_instructions) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        if (i < nb_instructions) {
            trace[i] = T::from_canonical_u32(multiplicities[i]);
        } else {
            trace[i] = T::zero();
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_program_generate_preprocessed_trace_kernel() {
    return (KernelPtr)::riscv_program_generate_preprocessed_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_program_generate_trace_kernel() {
    return (KernelPtr)::riscv_program_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
