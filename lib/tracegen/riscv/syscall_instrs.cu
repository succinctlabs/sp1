/// GPU trace generation for RISC-V SyscallInstrsChip.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Syscall IDs (byte 0 of the syscall code).
// From sp1-wip/crates/core/executor/src/syscall_code.rs
static constexpr uint32_t SYSCALL_HALT = 0x00;
static constexpr uint32_t SYSCALL_ENTER_UNCONSTRAINED = 0x03;
static constexpr uint32_t SYSCALL_HINT_LEN = 0xF0;
static constexpr uint32_t SYSCALL_COMMIT = 0x10;
static constexpr uint32_t SYSCALL_COMMIT_DEFERRED_PROOFS = 0x1A;

// HALT_PC = 1 (an invalid PC since it's not a multiple of 4)
static constexpr uint64_t HALT_PC_VAL = 1;

// PV_DIGEST_NUM_WORDS = 8
static constexpr size_t PV_DIGEST_NUM_WORDS = 8;

// TOP_LIMB for SP1FieldWordRangeChecker = 127 * 256 = 32512
static constexpr uint32_t TOP_LIMB = 32512;

// Manually define types that cbindgen can't handle.

template <class T>
struct IsZeroOperation {
    T inverse;
    T result;
};

template <class T>
struct U16CompareOperation {
    T bit;
};

template <class T>
struct SP1FieldWordRangeChecker {
    U16CompareOperation<T> most_sig_limb_lt_top_limb;
};

template <class T>
struct U16toU8Operation {
    T low_bytes[WORD_SIZE];
};

template <class T>
struct SyscallInstrColumns {
    sp1_gpu_sys::CPUState<T> state;
    sp1_gpu_sys::RTypeReader<T> adapter;
    T next_pc[3];
    T is_halt;
    sp1_gpu_sys::Word<T> op_a_value;
    U16toU8Operation<T> a_low_bytes;
    IsZeroOperation<T> is_enter_unconstrained;
    IsZeroOperation<T> is_hint_len;
    IsZeroOperation<T> is_halt_check;
    IsZeroOperation<T> is_commit;
    IsZeroOperation<T> is_commit_deferred_proofs;
    T index_bitmap[PV_DIGEST_NUM_WORDS];
    T expected_public_values_digest[4];
    SP1FieldWordRangeChecker<T> op_b_range_check;
    SP1FieldWordRangeChecker<T> op_c_range_check;
    T is_real;
};

/// Populate an IsZeroOperation from a field element.
/// If a == 0: result = 1, inverse = 0
/// If a != 0: result = 0, inverse = a^(-1)
template <class T>
__device__ void populate_is_zero_operation(IsZeroOperation<T>& op, T a) {
    if (a == T::zero()) {
        op.inverse = T::zero();
        op.result = T::one();
    } else {
        op.inverse = a.reciprocal();
        op.result = T::zero();
    }
}

/// Populate SP1FieldWordRangeChecker from a Word value.
template <class T>
__device__ void populate_sp1_field_word_range_checker(
    SP1FieldWordRangeChecker<T>& checker,
    const sp1_gpu_sys::Word<T>& value) {
    uint32_t ms_limb = value._0[1].as_canonical_u32();
    checker.most_sig_limb_lt_top_limb.bit = T::from_canonical_u32((ms_limb < TOP_LIMB) ? 1 : 0);
}

/// Populate U16toU8Operation: extract the low byte of each u16 limb of a u64.
template <class T>
__device__ void populate_u16_to_u8(U16toU8Operation<T>& op, uint64_t value) {
    op.low_bytes[0] = T::from_canonical_u32(value & 0xFF);
    op.low_bytes[1] = T::from_canonical_u32((value >> 16) & 0xFF);
    op.low_bytes[2] = T::from_canonical_u32((value >> 32) & 0xFF);
    op.low_bytes[3] = T::from_canonical_u32((value >> 48) & 0xFF);
}

/// Main kernel for SyscallInstrsChip trace generation.
template <class T>
__global__ void riscv_syscall_instrs_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::SyscallInstrsGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(SyscallInstrColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        SyscallInstrColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate is_real
            cols.is_real = T::one();

            // Populate CPUState
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate RTypeReader
            populate_r_type_reader(cols.adapter, event);

            // Populate op_a_value = Word::from(record.a.value())
            // a_value is the new value written to the register
            u64_to_word(event.a_value, cols.op_a_value);

            // Populate a_low_bytes from prev_value of op_a (the old register value)
            // The prev_value contains the syscall code in its low byte
            uint64_t a_prev_value = event.mem_a.prev_value;
            populate_u16_to_u8(cols.a_low_bytes, a_prev_value);

            // Extract syscall_id from the first low byte of prev_a
            // In the CPU code: a_prev_value = record.a.prev_value().to_le_bytes()
            // syscall_id = a_prev_value[0] (byte 0 as a field element)
            // The prev_value is stored as u64, byte 0 = value & 0xFF
            uint32_t syscall_id_u32 = (uint32_t)(a_prev_value & 0xFF);
            T syscall_id = T::from_canonical_u32(syscall_id_u32);

            // Populate is_halt
            T halt_id = T::from_canonical_u32(SYSCALL_HALT);
            bool is_halt = (syscall_id_u32 == SYSCALL_HALT);
            cols.is_halt = T::from_bool(is_halt);

            // Populate next_pc
            if (is_halt) {
                cols.next_pc[0] = T::from_canonical_u32((uint32_t)(HALT_PC_VAL & 0xFFFF));
                cols.next_pc[1] = T::zero();
                cols.next_pc[2] = T::zero();
            } else {
                cols.next_pc[0] = T::from_canonical_u32(((uint32_t)(event.pc & 0xFFFF)) + 4);
                cols.next_pc[1] = T::from_canonical_u32((uint32_t)((event.pc >> 16) & 0xFFFF));
                cols.next_pc[2] = T::from_canonical_u32((uint32_t)((event.pc >> 32) & 0xFFFF));
            }

            // Populate IsZeroOperation for each syscall type check.
            // IsZeroOperation checks if (syscall_id - target_id) == 0.
            // Result is 1 if equal (the syscall matches), 0 otherwise.

            // is_enter_unconstrained
            T enter_unc_diff = syscall_id;
            enter_unc_diff -= T::from_canonical_u32(SYSCALL_ENTER_UNCONSTRAINED);
            populate_is_zero_operation(cols.is_enter_unconstrained, enter_unc_diff);

            // is_hint_len
            T hint_len_diff = syscall_id;
            hint_len_diff -= T::from_canonical_u32(SYSCALL_HINT_LEN);
            populate_is_zero_operation(cols.is_hint_len, hint_len_diff);

            // is_halt_check
            T halt_diff = syscall_id;
            halt_diff -= halt_id;
            populate_is_zero_operation(cols.is_halt_check, halt_diff);

            // is_commit
            T commit_diff = syscall_id;
            commit_diff -= T::from_canonical_u32(SYSCALL_COMMIT);
            populate_is_zero_operation(cols.is_commit, commit_diff);

            // is_commit_deferred_proofs
            T commit_def_diff = syscall_id;
            commit_def_diff -= T::from_canonical_u32(SYSCALL_COMMIT_DEFERRED_PROOFS);
            populate_is_zero_operation(cols.is_commit_deferred_proofs, commit_def_diff);

            // index_bitmap and expected_public_values_digest are zero by default.
            // Set them for COMMIT and COMMIT_DEFERRED_PROOFS syscalls.
            bool is_commit = (syscall_id_u32 == SYSCALL_COMMIT);
            bool is_commit_deferred = (syscall_id_u32 == SYSCALL_COMMIT_DEFERRED_PROOFS);

            if (is_commit || is_commit_deferred) {
                // digest_idx = record.b.value() = the b register value
                // For the GPU event, b register value is in mem_b.prev_value
                // (for a read record, value() == prev_value())
                uint64_t b_value = event.mem_b.prev_value;
                uint32_t digest_idx = (uint32_t)(b_value & 0x7); // cap at 7
                cols.index_bitmap[digest_idx] = T::one();
            }

            if (is_commit) {
                // expected_public_values_digest = (record.c.value() as u32).to_le_bytes()
                // For a read record, value() = prev_value
                uint64_t c_value = event.mem_c.prev_value;
                uint32_t c_u32 = (uint32_t)(c_value & 0xFFFFFFFF);
                cols.expected_public_values_digest[0] = T::from_canonical_u32(c_u32 & 0xFF);
                cols.expected_public_values_digest[1] = T::from_canonical_u32((c_u32 >> 8) & 0xFF);
                cols.expected_public_values_digest[2] = T::from_canonical_u32((c_u32 >> 16) & 0xFF);
                cols.expected_public_values_digest[3] = T::from_canonical_u32((c_u32 >> 24) & 0xFF);
            }

            // op_b_range_check: only populated for HALT
            if (is_halt) {
                sp1_gpu_sys::Word<T> arg1_word;
                u64_to_word(event.arg1, arg1_word);
                populate_sp1_field_word_range_checker(cols.op_b_range_check, arg1_word);
            }
            // op_c_range_check: only populated for COMMIT_DEFERRED_PROOFS
            if (is_commit_deferred) {
                sp1_gpu_sys::Word<T> arg2_word;
                u64_to_word(event.arg2, arg2_word);
                populate_sp1_field_word_range_checker(cols.op_c_range_check, arg2_word);
            }
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_syscall_instrs_generate_trace_kernel() {
    return (KernelPtr)::riscv_syscall_instrs_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
