/// GPU trace generation for RISC-V DivRemChip.

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

// Constants matching Rust definitions
static constexpr size_t WORD_SIZE = 4;            // u16 limbs in a Word
static constexpr size_t LONG_WORD_SIZE = 8;       // u16 limbs in a 128-bit value
static constexpr size_t LONG_WORD_BYTE_SIZE = 16; // bytes in a 128-bit product
static constexpr size_t WORD_BYTE_SIZE = 8;       // bytes in a 64-bit word
static constexpr uint8_t BYTE_MASK = 0xFF;
static constexpr size_t BYTE_SIZE = 8; // bits in a byte

// Manually define types that cbindgen can't resolve due to constant expressions.
// These must match the Rust struct layouts exactly.
namespace sp1_gpu_sys {

// IsZeroOperation: checks if a value is zero
template <typename T>
struct IsZeroOperation {
    T inverse;
    T result;
};

// IsZeroWordOperation: checks if a Word is zero
template <typename T>
struct IsZeroWordOperation {
    IsZeroOperation<T> is_zero_limb[WORD_SIZE];
    T is_zero_first_half;
    T is_zero_second_half;
    T result;
};

// IsEqualWordOperation: checks if two Words are equal
template <typename T>
struct IsEqualWordOperation {
    IsZeroWordOperation<T> is_diff_zero;
};

// U16CompareOperation: compares two u16 values
template <typename T>
struct U16CompareOperation {
    T bit;
};

// LtOperationUnsigned: unsigned less-than comparison
template <typename T>
struct LtOperationUnsigned {
    U16CompareOperation<T> u16_compare_operation;
    T u16_flags[WORD_SIZE];
    T not_eq_inv;
    T comparison_limbs[2];
};

// U16toU8Operation: stores low bytes of each u16 limb
template <typename T>
struct U16toU8Operation {
    T low_bytes[WORD_SIZE];
};

// MulOperation: multiplication operation columns
template <typename T>
struct MulOperation {
    T carry[LONG_WORD_BYTE_SIZE];
    T product[LONG_WORD_BYTE_SIZE];
    U16toU8Operation<T> b_lower_byte;
    U16toU8Operation<T> c_lower_byte;
    T b_msb;
    T c_msb;
    U16MSBOperation<T> product_msb;
    T b_sign_extend;
    T c_sign_extend;
};

// AddOperation: addition operation columns
template <typename T>
struct AddOperation {
    Word<T> value;
};

// DivRemCols: column layout for DivRemChip
template <typename T>
struct DivRemCols {
    CPUState<T> state;
    RTypeReader<T> adapter;
    Word<T> a;
    Word<T> b;
    Word<T> c;
    Word<T> quotient;
    Word<T> quotient_comp;
    Word<T> remainder_comp;
    Word<T> remainder;
    Word<T> abs_remainder;
    Word<T> abs_c;
    Word<T> max_abs_c_or_1;
    T c_times_quotient[LONG_WORD_SIZE];
    MulOperation<T> c_times_quotient_lower;
    MulOperation<T> c_times_quotient_upper;
    AddOperation<T> c_neg_operation;
    AddOperation<T> rem_neg_operation;
    LtOperationUnsigned<T> remainder_lt_operation;
    T carry[LONG_WORD_SIZE];
    IsZeroWordOperation<T> is_c_0;
    T is_div;
    T is_divu;
    T is_rem;
    T is_remu;
    T is_divw;
    T is_remw;
    T is_divuw;
    T is_remuw;
    T is_overflow;
    IsEqualWordOperation<T> is_overflow_b;
    IsEqualWordOperation<T> is_overflow_c;
    U16MSBOperation<T> b_msb;
    U16MSBOperation<T> rem_msb;
    U16MSBOperation<T> c_msb;
    U16MSBOperation<T> quot_msb;
    T b_neg;
    T b_neg_not_overflow;
    T b_not_neg_not_overflow;
    T is_real_not_word;
    T rem_neg;
    T c_neg;
    T abs_c_alu_event;
    T abs_rem_alu_event;
    T is_real;
    T remainder_check_multiplicity;
};

} // namespace sp1_gpu_sys

/// Opcode enum values for DivRem variants.
enum DivRemOpcode : uint8_t {
    DIV = 0,
    DIVU = 1,
    REM = 2,
    REMU = 3,
    DIVW = 4,
    DIVUW = 5,
    REMW = 6,
    REMUW = 7
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
    uint32_t prev_high = prev_timestamp >> 24;
    uint32_t prev_low_val = prev_timestamp & 0xFFFFFF;
    uint32_t current_high = current_timestamp >> 24;
    uint32_t current_low_val = current_timestamp & 0xFFFFFF;

    uint32_t old_timestamp = (prev_high == current_high) ? prev_low_val : 0;
    ts.prev_low = T::from_canonical_u32(old_timestamp);

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
    populate_register_access_timestamp(
        cols.access_timestamp,
        mem.prev_timestamp,
        mem.current_timestamp);
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

    state.pc[0] = T::from_canonical_u32(pc & 0x3FFFFF);
    state.pc[1] = T::from_canonical_u32((pc >> 22) & 0x3FFFFF);
    state.pc[2] = T::from_canonical_u32((pc >> 44) & 0x3FFFFF);
}

/// Populate RTypeReader from the GPU event data.
template <class T>
__device__ void populate_r_type_reader(
    sp1_gpu_sys::RTypeReader<T>& adapter,
    const sp1_gpu_sys::DivRemGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a == 0);

    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    adapter.op_c = T::from_canonical_u32(static_cast<uint32_t>(event.op_c));
    populate_register_access_cols(adapter.op_c_memory, event.mem_c);
}

/// Get MSB of a 64-bit value (bit 63).
__device__ uint8_t get_msb_64(uint64_t val) { return (val >> 63) & 1; }

/// Get MSB of a 32-bit value (bit 31).
__device__ uint8_t get_msb_32(uint64_t val) { return (val >> 31) & 1; }

/// Check if opcode is a signed word operation (DIVW, REMW).
__device__ bool is_signed_word_operation(uint8_t opcode) {
    return opcode == DIVW || opcode == REMW;
}

/// Check if opcode is an unsigned word operation (DIVUW, REMUW).
__device__ bool is_unsigned_word_operation(uint8_t opcode) {
    return opcode == DIVUW || opcode == REMUW;
}

/// Check if opcode is any word operation.
__device__ bool is_word_operation(uint8_t opcode) {
    return opcode == DIVW || opcode == REMW || opcode == DIVUW || opcode == REMUW;
}

/// Check if opcode is a signed 64-bit operation (DIV, REM).
__device__ bool is_signed_64bit_operation(uint8_t opcode) { return opcode == DIV || opcode == REM; }

/// Check if opcode is an unsigned 64-bit operation (DIVU, REMU).
__device__ bool is_unsigned_64bit_operation(uint8_t opcode) {
    return opcode == DIVU || opcode == REMU;
}

/// Compute quotient and remainder for division operations.
__device__ void get_quotient_and_remainder(
    uint64_t b,
    uint64_t c,
    uint8_t opcode,
    uint64_t& quotient,
    uint64_t& remainder) {

    if (is_signed_64bit_operation(opcode)) {
        // Signed 64-bit division
        int64_t b_signed = static_cast<int64_t>(b);
        int64_t c_signed = static_cast<int64_t>(c);

        if (c == 0) {
            // Division by zero: quotient = -1, remainder = b
            quotient = static_cast<uint64_t>(-1LL);
            remainder = b;
        } else if (b_signed == INT64_MIN && c_signed == -1) {
            // Overflow case
            quotient = b; // Return MIN itself
            remainder = 0;
        } else {
            quotient = static_cast<uint64_t>(b_signed / c_signed);
            remainder = static_cast<uint64_t>(b_signed % c_signed);
        }
    } else if (is_unsigned_64bit_operation(opcode)) {
        // Unsigned 64-bit division
        if (c == 0) {
            quotient = UINT64_MAX;
            remainder = b;
        } else {
            quotient = b / c;
            remainder = b % c;
        }
    } else if (is_signed_word_operation(opcode)) {
        // Signed 32-bit division
        int32_t b32 = static_cast<int32_t>(b);
        int32_t c32 = static_cast<int32_t>(c);

        if (c32 == 0) {
            quotient = static_cast<uint64_t>(-1LL);
            remainder = static_cast<uint64_t>(static_cast<int64_t>(b32));
        } else if (b32 == INT32_MIN && c32 == -1) {
            // Overflow case
            quotient = static_cast<uint64_t>(static_cast<int64_t>(b32));
            remainder = 0;
        } else {
            int32_t q = b32 / c32;
            int32_t r = b32 % c32;
            // Sign-extend to 64 bits
            quotient = static_cast<uint64_t>(static_cast<int64_t>(q));
            remainder = static_cast<uint64_t>(static_cast<int64_t>(r));
        }
    } else {
        // Unsigned 32-bit division (DIVUW, REMUW)
        uint32_t b32 = static_cast<uint32_t>(b);
        uint32_t c32 = static_cast<uint32_t>(c);

        if (c32 == 0) {
            quotient = UINT64_MAX;
            remainder = static_cast<uint64_t>(b32);
        } else {
            quotient = static_cast<uint64_t>(b32 / c32);
            remainder = static_cast<uint64_t>(b32 % c32);
        }
    }
}

/// Populate IsZeroOperation for a single field element value.
template <class T>
__device__ void populate_is_zero_operation(sp1_gpu_sys::IsZeroOperation<T>& op, uint64_t val) {
    if (val == 0) {
        op.inverse = T::zero();
        op.result = T::one();
    } else {
        // Compute inverse in the field
        T val_field = T::from_canonical_u32(static_cast<uint32_t>(val & 0xFFFFFFFF));
        op.inverse = val_field.inverse();
        op.result = T::zero();
    }
}

/// Populate IsZeroWordOperation.
template <class T>
__device__ void populate_is_zero_word(sp1_gpu_sys::IsZeroWordOperation<T>& op, uint64_t val) {
    uint16_t limbs[4] = {
        static_cast<uint16_t>(val & 0xFFFF),
        static_cast<uint16_t>((val >> 16) & 0xFFFF),
        static_cast<uint16_t>((val >> 32) & 0xFFFF),
        static_cast<uint16_t>((val >> 48) & 0xFFFF)};

    for (int i = 0; i < WORD_SIZE; i++) {
        populate_is_zero_operation(op.is_zero_limb[i], limbs[i]);
    }

    bool first_half_zero = (limbs[0] == 0) && (limbs[1] == 0);
    bool second_half_zero = (limbs[2] == 0) && (limbs[3] == 0);

    op.is_zero_first_half = first_half_zero ? T::one() : T::zero();
    op.is_zero_second_half = second_half_zero ? T::one() : T::zero();
    op.result = (first_half_zero && second_half_zero) ? T::one() : T::zero();
}

/// Populate U16toU8Operation - stores low bytes of each u16 limb.
template <class T>
__device__ void populate_u16_to_u8(sp1_gpu_sys::U16toU8Operation<T>& op, uint64_t val) {
    op.low_bytes[0] = T::from_canonical_u32(val & 0xFF);
    op.low_bytes[1] = T::from_canonical_u32((val >> 16) & 0xFF);
    op.low_bytes[2] = T::from_canonical_u32((val >> 32) & 0xFF);
    op.low_bytes[3] = T::from_canonical_u32((val >> 48) & 0xFF);
}

/// Populate MulOperation for computing c * quotient.
template <class T>
__device__ void populate_mul_operation(
    sp1_gpu_sys::MulOperation<T>& op,
    uint64_t quotient_comp,
    uint64_t c,
    bool is_signed,
    bool compute_upper) {

    uint8_t b_msb = get_msb_64(quotient_comp);
    uint8_t c_msb = get_msb_64(c);
    op.b_msb = T::from_canonical_u32(b_msb);
    op.c_msb = T::from_canonical_u32(c_msb);

    populate_u16_to_u8(op.b_lower_byte, quotient_comp);
    populate_u16_to_u8(op.c_lower_byte, c);

    // Prepare byte arrays
    uint8_t b_bytes[LONG_WORD_BYTE_SIZE];
    uint8_t c_bytes[LONG_WORD_BYTE_SIZE];

    for (int i = 0; i < WORD_BYTE_SIZE; i++) {
        b_bytes[i] = (quotient_comp >> (i * 8)) & 0xFF;
        c_bytes[i] = (c >> (i * 8)) & 0xFF;
    }

    bool b_sign_extend = is_signed && compute_upper && (b_msb == 1);
    bool c_sign_extend = is_signed && compute_upper && (c_msb == 1);

    op.b_sign_extend = b_sign_extend ? T::one() : T::zero();
    op.c_sign_extend = c_sign_extend ? T::one() : T::zero();

    for (int i = WORD_BYTE_SIZE; i < LONG_WORD_BYTE_SIZE; i++) {
        b_bytes[i] = b_sign_extend ? BYTE_MASK : 0;
        c_bytes[i] = c_sign_extend ? BYTE_MASK : 0;
    }

    // Compute uncarried product
    uint32_t product[LONG_WORD_BYTE_SIZE] = {0};
    int limit = (b_sign_extend || c_sign_extend) ? LONG_WORD_BYTE_SIZE : WORD_BYTE_SIZE;

    for (int i = 0; i < limit; i++) {
        for (int j = 0; j < limit; j++) {
            if (i + j < LONG_WORD_BYTE_SIZE) {
                product[i + j] +=
                    static_cast<uint32_t>(b_bytes[i]) * static_cast<uint32_t>(c_bytes[j]);
            }
        }
    }

    // Carry propagation
    uint32_t base = 1 << BYTE_SIZE;
    uint32_t carry[LONG_WORD_BYTE_SIZE] = {0};

    for (int i = 0; i < LONG_WORD_BYTE_SIZE; i++) {
        carry[i] = product[i] / base;
        product[i] = product[i] % base;
        if (i + 1 < LONG_WORD_BYTE_SIZE) {
            product[i + 1] += carry[i];
        }
        op.carry[i] = T::from_canonical_u32(carry[i]);
    }

    for (int i = 0; i < LONG_WORD_BYTE_SIZE; i++) {
        op.product[i] = T::from_canonical_u32(product[i]);
    }

    op.product_msb.msb = T::zero();
}

/// Populate LtOperationUnsigned for comparing abs(remainder) < max(abs(c), 1).
template <class T>
__device__ void populate_lt_unsigned(
    sp1_gpu_sys::LtOperationUnsigned<T>& op,
    uint64_t abs_remainder,
    uint64_t max_abs_c_or_1) {

    uint16_t a_limbs[4] = {
        static_cast<uint16_t>(abs_remainder & 0xFFFF),
        static_cast<uint16_t>((abs_remainder >> 16) & 0xFFFF),
        static_cast<uint16_t>((abs_remainder >> 32) & 0xFFFF),
        static_cast<uint16_t>((abs_remainder >> 48) & 0xFFFF)};

    uint16_t b_limbs[4] = {
        static_cast<uint16_t>(max_abs_c_or_1 & 0xFFFF),
        static_cast<uint16_t>((max_abs_c_or_1 >> 16) & 0xFFFF),
        static_cast<uint16_t>((max_abs_c_or_1 >> 32) & 0xFFFF),
        static_cast<uint16_t>((max_abs_c_or_1 >> 48) & 0xFFFF)};

    // Find the most significant differing limb
    int diff_idx = -1;
    for (int i = WORD_SIZE - 1; i >= 0; i--) {
        if (a_limbs[i] != b_limbs[i]) {
            diff_idx = i;
            break;
        }
    }

    // Set flags
    for (int i = 0; i < WORD_SIZE; i++) {
        op.u16_flags[i] = (i == diff_idx) ? T::one() : T::zero();
    }

    // Set comparison result
    bool is_less = (diff_idx >= 0) ? (a_limbs[diff_idx] < b_limbs[diff_idx]) : false;
    op.u16_compare_operation.bit = is_less ? T::one() : T::zero();

    // Set comparison limbs for the differing position
    if (diff_idx >= 0) {
        op.comparison_limbs[0] = T::from_canonical_u32(a_limbs[diff_idx]);
        op.comparison_limbs[1] = T::from_canonical_u32(b_limbs[diff_idx]);
        // Inverse of difference
        uint32_t diff = (a_limbs[diff_idx] > b_limbs[diff_idx])
                            ? (a_limbs[diff_idx] - b_limbs[diff_idx])
                            : (b_limbs[diff_idx] - a_limbs[diff_idx]);
        if (diff != 0) {
            T diff_field = T::from_canonical_u32(diff);
            op.not_eq_inv = diff_field.inverse();
        } else {
            op.not_eq_inv = T::zero();
        }
    } else {
        op.comparison_limbs[0] = T::zero();
        op.comparison_limbs[1] = T::zero();
        op.not_eq_inv = T::zero();
    }
}

/// Populate IsEqualWordOperation.
template <class T>
__device__ void
populate_is_equal_word(sp1_gpu_sys::IsEqualWordOperation<T>& op, uint64_t a, uint64_t b) {
    // Compute difference and check if zero
    uint64_t diff_val = 0;

    uint16_t a_limbs[4] = {
        static_cast<uint16_t>(a & 0xFFFF),
        static_cast<uint16_t>((a >> 16) & 0xFFFF),
        static_cast<uint16_t>((a >> 32) & 0xFFFF),
        static_cast<uint16_t>((a >> 48) & 0xFFFF)};
    uint16_t b_limbs[4] = {
        static_cast<uint16_t>(b & 0xFFFF),
        static_cast<uint16_t>((b >> 16) & 0xFFFF),
        static_cast<uint16_t>((b >> 32) & 0xFFFF),
        static_cast<uint16_t>((b >> 48) & 0xFFFF)};

    // Compute per-limb differences (treating as field subtraction, wrapping)
    for (int i = 0; i < WORD_SIZE; i++) {
        uint16_t diff_limb = a_limbs[i] - b_limbs[i]; // wrapping subtraction
        diff_val |= (static_cast<uint64_t>(diff_limb) << (i * 16));
    }

    populate_is_zero_word(op.is_diff_zero, diff_val);
}

/// Main kernel for DivRemChip trace generation.
template <class T>
__global__ void riscv_divrem_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::DivRemGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::DivRemCols<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::DivRemCols<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);

        // Zero initialize all columns
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];
            uint8_t opcode = event.opcode;

            // Set opcode flags
            cols.is_div = T::from_bool(opcode == DIV);
            cols.is_divu = T::from_bool(opcode == DIVU);
            cols.is_rem = T::from_bool(opcode == REM);
            cols.is_remu = T::from_bool(opcode == REMU);
            cols.is_divw = T::from_bool(opcode == DIVW);
            cols.is_divuw = T::from_bool(opcode == DIVUW);
            cols.is_remw = T::from_bool(opcode == REMW);
            cols.is_remuw = T::from_bool(opcode == REMUW);
            cols.is_real = T::one();

            bool word_op = is_word_operation(opcode);
            cols.is_real_not_word = word_op ? T::zero() : T::one();

            // Get computational values of b and c
            uint64_t b_comp, c_comp;
            if (is_signed_word_operation(opcode)) {
                b_comp = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(event.b)));
                c_comp = static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(event.c)));
            } else if (is_unsigned_word_operation(opcode)) {
                b_comp = static_cast<uint64_t>(static_cast<uint32_t>(event.b));
                c_comp = static_cast<uint64_t>(static_cast<uint32_t>(event.c));
            } else {
                b_comp = event.b;
                c_comp = event.c;
            }

            u64_to_word(event.a, cols.a);
            u64_to_word(b_comp, cols.b);
            u64_to_word(c_comp, cols.c);

            // Compute quotient and remainder
            uint64_t quotient, remainder;
            get_quotient_and_remainder(event.b, event.c, opcode, quotient, remainder);

            u64_to_word(quotient, cols.quotient);
            u64_to_word(remainder, cols.remainder);

            // Compute quotient_comp and remainder_comp
            uint64_t quotient_comp, remainder_comp;
            if (is_unsigned_word_operation(opcode)) {
                quotient_comp = static_cast<uint64_t>(static_cast<uint32_t>(quotient));
                remainder_comp = static_cast<uint64_t>(static_cast<uint32_t>(remainder));
            } else {
                quotient_comp = quotient;
                remainder_comp = remainder;
            }

            u64_to_word(quotient_comp, cols.quotient_comp);
            u64_to_word(remainder_comp, cols.remainder_comp);

            // Calculate sign flags
            uint8_t b_neg_bit = 0, c_neg_bit = 0, rem_neg_bit = 0;
            uint64_t abs_remainder_val = remainder_comp;
            uint64_t abs_c_val = c_comp;

            if (is_signed_64bit_operation(opcode)) {
                rem_neg_bit = get_msb_64(remainder);
                b_neg_bit = get_msb_64(event.b);
                c_neg_bit = get_msb_64(event.c);

                // Compute absolute values for signed 64-bit
                if (rem_neg_bit) {
                    abs_remainder_val = static_cast<uint64_t>(-static_cast<int64_t>(remainder));
                } else {
                    abs_remainder_val = remainder;
                }
                if (c_neg_bit) {
                    abs_c_val = static_cast<uint64_t>(-static_cast<int64_t>(event.c));
                } else {
                    abs_c_val = event.c;
                }
            } else if (is_signed_word_operation(opcode)) {
                int32_t rem32 = static_cast<int32_t>(remainder);
                int32_t b32 = static_cast<int32_t>(event.b);
                int32_t c32 = static_cast<int32_t>(event.c);

                rem_neg_bit = get_msb_64(static_cast<uint64_t>(static_cast<int64_t>(rem32)));
                b_neg_bit = get_msb_64(static_cast<uint64_t>(static_cast<int64_t>(b32)));
                c_neg_bit = get_msb_64(static_cast<uint64_t>(static_cast<int64_t>(c32)));

                abs_remainder_val = static_cast<uint64_t>(abs(static_cast<int64_t>(remainder)));
                abs_c_val = static_cast<uint64_t>(abs(static_cast<int64_t>(c_comp)));
            } else if (is_unsigned_word_operation(opcode)) {
                abs_remainder_val = remainder_comp;
                abs_c_val = static_cast<uint64_t>(static_cast<uint32_t>(event.c));
            } else {
                abs_remainder_val = remainder_comp;
                abs_c_val = event.c;
            }

            cols.b_neg = T::from_canonical_u32(b_neg_bit);
            cols.c_neg = T::from_canonical_u32(c_neg_bit);
            cols.rem_neg = T::from_canonical_u32(rem_neg_bit);

            u64_to_word(abs_remainder_val, cols.abs_remainder);
            u64_to_word(abs_c_val, cols.abs_c);

            uint64_t max_abs_c_or_1 = (abs_c_val > 0) ? abs_c_val : 1;
            u64_to_word(max_abs_c_or_1, cols.max_abs_c_or_1);

            // Check for overflow condition
            bool is_overflow = false;
            if (is_signed_64bit_operation(opcode)) {
                is_overflow =
                    (static_cast<int64_t>(event.b) == INT64_MIN &&
                     static_cast<int64_t>(event.c) == -1);
            } else if (is_signed_word_operation(opcode)) {
                is_overflow =
                    (static_cast<int32_t>(event.b) == INT32_MIN &&
                     static_cast<int32_t>(event.c) == -1);
            }
            cols.is_overflow = is_overflow ? T::one() : T::zero();

            cols.b_neg_not_overflow =
                T::from_canonical_u32(b_neg_bit) * (T::one() - cols.is_overflow);
            cols.b_not_neg_not_overflow =
                (T::one() - T::from_canonical_u32(b_neg_bit)) * (T::one() - cols.is_overflow);

            // Populate is_overflow_b and is_overflow_c
            if (word_op) {
                populate_is_equal_word(
                    cols.is_overflow_b,
                    static_cast<uint64_t>(static_cast<uint32_t>(event.b)),
                    static_cast<uint64_t>(static_cast<uint32_t>(INT32_MIN)));
                populate_is_equal_word(
                    cols.is_overflow_c,
                    static_cast<uint64_t>(static_cast<uint32_t>(event.c)),
                    static_cast<uint64_t>(static_cast<uint32_t>(-1)));
            } else {
                populate_is_equal_word(
                    cols.is_overflow_b,
                    event.b,
                    static_cast<uint64_t>(INT64_MIN));
                populate_is_equal_word(cols.is_overflow_c, event.c, static_cast<uint64_t>(-1LL));
            }

            // ALU event flags
            cols.abs_c_alu_event = cols.c_neg * cols.is_real;
            cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;

            // Populate c_neg_operation and rem_neg_operation when needed
            if (c_neg_bit) {
                u64_to_word(0, cols.c_neg_operation.value); // c + abs_c = 0 in 2's complement
            }
            if (rem_neg_bit) {
                u64_to_word(0, cols.rem_neg_operation.value); // rem + abs_rem = 0
            }

            // Populate MSB operations
            if (word_op) {
                cols.b_msb.msb = T::from_canonical_u32((event.b >> 31) & 1);
                cols.c_msb.msb = T::from_canonical_u32((event.c >> 31) & 1);
                cols.rem_msb.msb = T::from_canonical_u32((remainder >> 31) & 1);
                cols.quot_msb.msb = T::from_canonical_u32((quotient >> 31) & 1);
            } else {
                cols.b_msb.msb = T::from_canonical_u32((b_comp >> 63) & 1);
                cols.c_msb.msb = T::from_canonical_u32((c_comp >> 63) & 1);
                cols.rem_msb.msb = T::from_canonical_u32((remainder >> 63) & 1);
            }

            // Populate is_c_0
            populate_is_zero_word(cols.is_c_0, c_comp);

            // remainder_check_multiplicity
            bool is_c_zero = (cols.is_c_0.result == T::one());
            cols.remainder_check_multiplicity = is_c_zero ? T::zero() : cols.is_real;

            // Populate remainder_lt_operation if needed
            if (!is_c_zero) {
                populate_lt_unsigned(
                    cols.remainder_lt_operation,
                    abs_remainder_val,
                    max_abs_c_or_1);
            }

            // Compute c * quotient
            // Lower 8 bytes
            uint64_t c_times_quot_lower = quotient_comp * c_comp; // Lower 64 bits (wrapping)

            // Upper 8 bytes (for 64-bit operations)
            uint64_t c_times_quot_upper = 0;
            if (is_signed_64bit_operation(opcode)) {
                __int128 prod = static_cast<__int128>(static_cast<int64_t>(quotient_comp)) *
                                static_cast<__int128>(static_cast<int64_t>(c_comp));
                c_times_quot_upper = static_cast<uint64_t>(prod >> 64);
            } else if (is_unsigned_64bit_operation(opcode)) {
                unsigned __int128 prod = static_cast<unsigned __int128>(quotient_comp) *
                                         static_cast<unsigned __int128>(c_comp);
                c_times_quot_upper = static_cast<uint64_t>(prod >> 64);
            }

            // Store as u16 limbs
            for (int j = 0; j < 4; j++) {
                cols.c_times_quotient[j] =
                    T::from_canonical_u32((c_times_quot_lower >> (j * 16)) & 0xFFFF);
            }
            for (int j = 0; j < 4; j++) {
                cols.c_times_quotient[j + 4] =
                    T::from_canonical_u32((c_times_quot_upper >> (j * 16)) & 0xFFFF);
            }

            // Populate MulOperations
            populate_mul_operation(
                cols.c_times_quotient_lower,
                quotient_comp,
                c_comp,
                false,
                false);

            if (is_signed_64bit_operation(opcode) || is_unsigned_64bit_operation(opcode)) {
                populate_mul_operation(
                    cols.c_times_quotient_upper,
                    quotient_comp,
                    c_comp,
                    is_signed_64bit_operation(opcode),
                    true);
            }

            // Compute carry for c * quotient + remainder
            uint32_t remainder_u16[8];
            for (int j = 0; j < 4; j++) {
                remainder_u16[j] = (remainder_comp >> (j * 16)) & 0xFFFF;
                remainder_u16[j + 4] = rem_neg_bit ? 0xFFFF : 0;
            }

            uint16_t c_times_q_u16[8];
            for (int j = 0; j < 4; j++) {
                c_times_q_u16[j] = (c_times_quot_lower >> (j * 16)) & 0xFFFF;
                c_times_q_u16[j + 4] = (c_times_quot_upper >> (j * 16)) & 0xFFFF;
            }

            uint32_t carry[8] = {0};
            uint32_t base = 1 << 16;
            for (int j = 0; j < LONG_WORD_SIZE; j++) {
                uint32_t x = c_times_q_u16[j] + remainder_u16[j];
                if (j > 0) {
                    x += carry[j - 1];
                }
                carry[j] = x / base;
                cols.carry[j] = T::from_canonical_u32(carry[j]);
            }

            // Populate CPUState
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate RTypeReader
            populate_r_type_reader(cols.adapter, event);
        } else {
            // Padding row template: 0 divided by 1
            cols.is_divu = T::one();
            cols.b_not_neg_not_overflow = T::one();
            cols.abs_c._0[0] = T::one();
            cols.c._0[0] = T::one();
            cols.max_abs_c_or_1._0[0] = T::one();
            // adapter.op_c_memory.prev_value = 1
            cols.adapter.op_c_memory.prev_value._0[0] = T::one();
            populate_is_zero_word(cols.is_c_0, 1);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_divrem_generate_trace_kernel() {
    return (KernelPtr)::riscv_divrem_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
