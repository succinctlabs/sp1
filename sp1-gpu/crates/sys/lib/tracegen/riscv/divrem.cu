/// GPU trace generation for RISC-V DivRemChip.
///
/// Handles 8 division/remainder opcodes: DIV, DIVU, REM, REMU, DIVW, DIVUW, REMW, REMUW.
/// DivRemCols has many nested operations (MulOperation, AddOperation, IsZeroWordOperation,
/// IsEqualWordOperation, LtOperationUnsigned, U16MSBOperation) and complex sign/overflow logic.

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

// Constants matching Rust definitions
static constexpr size_t BYTE_SIZE = 8;
static constexpr size_t WORD_BYTE_SIZE = 8;
static constexpr size_t LONG_WORD_SIZE = 2 * WORD_SIZE; // 8 u16 limbs = 128 bits
static constexpr size_t LONG_WORD_BYTE_SIZE = 16;       // 16 bytes = 128 bits
static constexpr uint8_t BYTE_MASK = 0xFF;

// DivRem opcode enum values (mapped from Rust Opcode enum)
enum DivRemOpcode : uint8_t {
    OP_DIV = 0,
    OP_DIVU = 1,
    OP_REM = 2,
    OP_REMU = 3,
    OP_DIVW = 4,
    OP_DIVUW = 5,
    OP_REMW = 6,
    OP_REMUW = 7,
};

__device__ bool is_signed_64bit_op(uint8_t opcode) { return opcode == OP_DIV || opcode == OP_REM; }

__device__ bool is_unsigned_64bit_op(uint8_t opcode) {
    return opcode == OP_DIVU || opcode == OP_REMU;
}

__device__ bool is_signed_word_op(uint8_t opcode) { return opcode == OP_DIVW || opcode == OP_REMW; }

__device__ bool is_unsigned_word_op(uint8_t opcode) {
    return opcode == OP_DIVUW || opcode == OP_REMUW;
}

__device__ bool is_word_op(uint8_t opcode) {
    return opcode == OP_DIVW || opcode == OP_DIVUW || opcode == OP_REMW || opcode == OP_REMUW;
}

__device__ bool is_64bit_op(uint8_t opcode) {
    return opcode == OP_DIV || opcode == OP_DIVU || opcode == OP_REM || opcode == OP_REMU;
}

// Manually define nested operation structs that cbindgen can't resolve.
namespace sp1_gpu_sys {

// U16toU8Operation: stores low bytes of each u16 limb
template <typename T>
struct U16toU8OperationDivRem {
    T low_bytes[WORD_SIZE]; // 4
};

// MulOperation: multiplication operation columns
template <typename T>
struct MulOperationDivRem {
    T carry[LONG_WORD_BYTE_SIZE];   // 16
    T product[LONG_WORD_BYTE_SIZE]; // 16
    U16toU8OperationDivRem<T> b_lower_byte;
    U16toU8OperationDivRem<T> c_lower_byte;
    T b_msb;
    T c_msb;
    U16MSBOperation<T> product_msb;
    T b_sign_extend;
    T c_sign_extend;
};

// IsZeroOperation: check if a single u16 limb is zero
template <typename T>
struct IsZeroOperation {
    T inverse;
    T result;
};

// IsZeroWordOperation: check if a 64-bit Word is zero
template <typename T>
struct IsZeroWordOperation {
    IsZeroOperation<T> is_zero_limb[WORD_SIZE]; // 4 limbs
    T is_zero_first_half;
    T is_zero_second_half;
    T result;
};

// IsEqualWordOperation: check if two Words are equal
template <typename T>
struct IsEqualWordOperation {
    IsZeroWordOperation<T> is_diff_zero;
};

// LtOperationUnsigned: unsigned less-than comparison
template <typename T>
struct U16CompareOperation {
    T bit;
};

template <typename T>
struct LtOperationUnsigned {
    U16CompareOperation<T> u16_compare_operation;
    T u16_flags[WORD_SIZE]; // 4
    T not_eq_inv;
    T comparison_limbs[2];
};

// DivRemCols: full column layout
template <typename T>
struct DivRemCols {
    // CPU state
    CPUState<T> state;
    // Adapter
    RTypeReader<T> adapter;
    // Operands
    Word<T> a;
    Word<T> b;
    Word<T> c;
    // Quotient and remainder
    Word<T> quotient;
    Word<T> quotient_comp;
    Word<T> remainder_comp;
    Word<T> remainder;
    // Absolute values
    Word<T> abs_remainder;
    Word<T> abs_c;
    Word<T> max_abs_c_or_1;
    // Product c * quotient
    T c_times_quotient[LONG_WORD_SIZE]; // 8
    MulOperationDivRem<T> c_times_quotient_lower;
    MulOperationDivRem<T> c_times_quotient_upper;
    // Negation operations
    AddOperation<T> c_neg_operation;
    AddOperation<T> rem_neg_operation;
    // Remainder range check
    LtOperationUnsigned<T> remainder_lt_operation;
    // Carry propagation
    T carry[LONG_WORD_SIZE]; // 8
    // Division by zero check
    IsZeroWordOperation<T> is_c_0;
    // Opcode flags
    T is_div;
    T is_divu;
    T is_rem;
    T is_remu;
    T is_divw;
    T is_remw;
    T is_divuw;
    T is_remuw;
    // Overflow
    T is_overflow;
    IsEqualWordOperation<T> is_overflow_b;
    IsEqualWordOperation<T> is_overflow_c;
    // MSB operations
    U16MSBOperation<T> b_msb;
    U16MSBOperation<T> rem_msb;
    U16MSBOperation<T> c_msb;
    U16MSBOperation<T> quot_msb;
    // Sign flags
    T b_neg;
    T b_neg_not_overflow;
    T b_not_neg_not_overflow;
    T is_real_not_word;
    T rem_neg;
    T c_neg;
    // ALU event selectors
    T abs_c_alu_event;
    T abs_rem_alu_event;
    // Row validity
    T is_real;
    T remainder_check_multiplicity;
};

} // namespace sp1_gpu_sys

/// Extract u16 limbs from a u64 value.
__device__ void divrem_u64_to_u16_limbs(uint64_t value, uint16_t limbs[WORD_SIZE]) {
    limbs[0] = value & 0xFFFF;
    limbs[1] = (value >> 16) & 0xFFFF;
    limbs[2] = (value >> 32) & 0xFFFF;
    limbs[3] = (value >> 48) & 0xFFFF;
}

/// Get MSB (sign bit) of a 64-bit value.
__device__ uint8_t divrem_get_msb(uint64_t val) { return (val >> 63) & 1; }

/// Compute quotient and remainder per RISC-V division spec.
__device__ void get_quotient_and_remainder(
    uint64_t b,
    uint64_t c,
    uint8_t opcode,
    uint64_t& quotient,
    uint64_t& remainder) {
    if (c == 0 && is_64bit_op(opcode)) {
        quotient = UINT64_MAX;
        remainder = b;
    } else if (((int32_t)c == 0) && is_word_op(opcode)) {
        quotient = UINT64_MAX;
        remainder = (uint64_t)(int64_t)(int32_t)b;
    } else if (is_signed_64bit_op(opcode)) {
        int64_t sb = (int64_t)b;
        int64_t sc = (int64_t)c;
        // Use manual overflow check for i64::MIN / -1
        if (sb == INT64_MIN && sc == -1) {
            quotient = (uint64_t)INT64_MIN; // wrapping
            remainder = 0;
        } else {
            quotient = (uint64_t)(sb / sc);
            remainder = (uint64_t)(sb % sc);
        }
    } else if (is_signed_word_op(opcode)) {
        int32_t sb = (int32_t)b;
        int32_t sc = (int32_t)c;
        if (sb == INT32_MIN && sc == -1) {
            quotient = (uint64_t)(int64_t)(int32_t)INT32_MIN; // wrapping
            remainder = 0;
        } else {
            quotient = (uint64_t)(int64_t)(sb / sc);
            remainder = (uint64_t)(int64_t)(sb % sc);
        }
    } else if (is_unsigned_word_op(opcode)) {
        uint32_t ub = (uint32_t)b;
        uint32_t uc = (uint32_t)c;
        // Sign-extend the u32 result to i64 then to u64, matching Rust: as i32 as i64 as u64
        quotient = (uint64_t)(int64_t)(int32_t)(ub / uc);
        remainder = (uint64_t)(int64_t)(int32_t)(ub % uc);
    } else {
        // Unsigned 64-bit
        quotient = b / c;
        remainder = b % c;
    }
}

/// Populate U16toU8Operation - stores low bytes of each u16 limb.
template <class T>
__device__ void
populate_u16_to_u8_divrem(sp1_gpu_sys::U16toU8OperationDivRem<T>& op, uint64_t val) {
    op.low_bytes[0] = T::from_canonical_u32(val & 0xFF);
    op.low_bytes[1] = T::from_canonical_u32((val >> 16) & 0xFF);
    op.low_bytes[2] = T::from_canonical_u32((val >> 32) & 0xFF);
    op.low_bytes[3] = T::from_canonical_u32((val >> 48) & 0xFF);
}

/// Populate MulOperation for DivRem c*quotient computation.
/// Parameters is_mulh, is_mulhsu, is_mulw control sign extension behavior.
template <class T>
__device__ void populate_mul_operation_divrem(
    sp1_gpu_sys::MulOperationDivRem<T>& op,
    uint64_t b_u64,
    uint64_t c_u64,
    bool is_mulh,
    bool is_mulhsu,
    bool is_mulw) {
    // Handle MULW product MSB
    if (is_mulw) {
        int32_t b32 = static_cast<int32_t>(b_u64);
        int32_t c32 = static_cast<int32_t>(c_u64);
        int64_t mulw_result = static_cast<int64_t>(b32) * static_cast<int64_t>(c32);
        uint64_t mulw_value = static_cast<uint64_t>(mulw_result);
        uint16_t limb1 = (mulw_value >> 16) & 0xFFFF;
        op.product_msb.msb = T::from_canonical_u32((limb1 >> 15) & 1);
    } else {
        op.product_msb.msb = T::zero();
    }

    populate_u16_to_u8_divrem(op.b_lower_byte, b_u64);
    populate_u16_to_u8_divrem(op.c_lower_byte, c_u64);

    uint8_t b_msb_val = divrem_get_msb(b_u64);
    uint8_t c_msb_val = divrem_get_msb(c_u64);
    op.b_msb = T::from_canonical_u32(b_msb_val);
    op.c_msb = T::from_canonical_u32(c_msb_val);

    // Prepare byte arrays for b and c
    uint8_t b_bytes[LONG_WORD_BYTE_SIZE];
    uint8_t c_bytes[LONG_WORD_BYTE_SIZE];

    for (int i = 0; i < WORD_BYTE_SIZE; i++) {
        b_bytes[i] = (b_u64 >> (i * 8)) & 0xFF;
        c_bytes[i] = (c_u64 >> (i * 8)) & 0xFF;
    }

    // Sign extension
    bool b_sign_extend = (is_mulh || is_mulhsu) && (b_msb_val == 1);
    bool c_sign_extend = is_mulh && (c_msb_val == 1);

    op.b_sign_extend = b_sign_extend ? T::one() : T::zero();
    op.c_sign_extend = c_sign_extend ? T::one() : T::zero();

    for (int i = WORD_BYTE_SIZE; i < LONG_WORD_BYTE_SIZE; i++) {
        b_bytes[i] = b_sign_extend ? BYTE_MASK : 0;
        c_bytes[i] = c_sign_extend ? BYTE_MASK : 0;
    }

    // Compute the uncarried product
    uint32_t product[LONG_WORD_BYTE_SIZE] = {0};
    int loop_len = (b_sign_extend || c_sign_extend) ? LONG_WORD_BYTE_SIZE : WORD_BYTE_SIZE;
    for (int i = 0; i < loop_len; i++) {
        for (int j = 0; j < loop_len; j++) {
            if (i + j < LONG_WORD_BYTE_SIZE) {
                product[i + j] +=
                    static_cast<uint32_t>(b_bytes[i]) * static_cast<uint32_t>(c_bytes[j]);
            }
        }
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

    for (int i = 0; i < LONG_WORD_BYTE_SIZE; i++) {
        op.product[i] = T::from_canonical_u32(product[i]);
    }
}

/// Populate IsZeroOperation for a single u16 limb (canonical value).
template <class T>
__device__ void populate_is_zero(sp1_gpu_sys::IsZeroOperation<T>& op, uint16_t value) {
    if (value == 0) {
        op.inverse = T::zero();
        op.result = T::one();
    } else {
        // Compute field inverse of value
        kb31_t field_val = kb31_t::from_canonical_u32(value);
        op.inverse = field_val.reciprocal();
        op.result = T::zero();
    }
}

/// Populate IsZeroOperation from a field element (for IsEqualWord per-limb differences).
template <class T>
__device__ void populate_is_zero_from_field(sp1_gpu_sys::IsZeroOperation<T>& op, T field_val) {
    if (field_val == T::zero()) {
        op.inverse = T::zero();
        op.result = T::one();
    } else {
        op.inverse = field_val.reciprocal();
        op.result = T::zero();
    }
}

/// Populate IsZeroWordOperation for a u64 value (canonical u16 limbs).
template <class T>
__device__ void populate_is_zero_word(sp1_gpu_sys::IsZeroWordOperation<T>& op, uint64_t value) {
    uint16_t limbs[WORD_SIZE];
    divrem_u64_to_u16_limbs(value, limbs);

    for (int i = 0; i < WORD_SIZE; i++) {
        populate_is_zero(op.is_zero_limb[i], limbs[i]);
    }

    op.is_zero_first_half = T::from_bool(limbs[0] == 0 && limbs[1] == 0);
    op.is_zero_second_half = T::from_bool(limbs[2] == 0 && limbs[3] == 0);
    op.result = T::from_bool(value == 0);
}

/// Populate IsZeroWordOperation from field element limbs (for IsEqualWord).
/// Each limb is already a field element (result of field subtraction), not a canonical u16.
template <class T>
__device__ void populate_is_zero_word_from_field(
    sp1_gpu_sys::IsZeroWordOperation<T>& op,
    T field_limbs[WORD_SIZE]) {
    bool all_zero = true;
    for (int i = 0; i < WORD_SIZE; i++) {
        populate_is_zero_from_field(op.is_zero_limb[i], field_limbs[i]);
        all_zero &= (field_limbs[i] == T::zero());
    }

    op.is_zero_first_half = op.is_zero_limb[0].result * op.is_zero_limb[1].result;
    op.is_zero_second_half = op.is_zero_limb[2].result * op.is_zero_limb[3].result;
    op.result = T::from_bool(all_zero);
}

/// Populate IsEqualWordOperation for two u64 values.
/// Computes per-limb field differences (matching CPU behavior), NOT whole u64 subtraction.
template <class T>
__device__ void
populate_is_equal_word(sp1_gpu_sys::IsEqualWordOperation<T>& op, uint64_t a, uint64_t b) {
    uint16_t a_limbs[WORD_SIZE], b_limbs[WORD_SIZE];
    divrem_u64_to_u16_limbs(a, a_limbs);
    divrem_u64_to_u16_limbs(b, b_limbs);

    // Per-limb field subtraction: F::from_canonical_u16(a[i]) - F::from_canonical_u16(b[i])
    T diff_limbs[WORD_SIZE];
    for (int i = 0; i < WORD_SIZE; i++) {
        diff_limbs[i] = T::from_canonical_u32(a_limbs[i]) - T::from_canonical_u32(b_limbs[i]);
    }

    populate_is_zero_word_from_field(op.is_diff_zero, diff_limbs);
}

/// Populate LtOperationUnsigned.
/// Checks if a_flag * (b < c) holds, where a_flag is expected to be 1 when b < c.
template <class T>
__device__ void populate_lt_unsigned(
    sp1_gpu_sys::LtOperationUnsigned<T>& op,
    uint64_t a_flag,
    uint64_t b_val,
    uint64_t c_val) {
    uint16_t b_limbs[WORD_SIZE], c_limbs[WORD_SIZE];
    divrem_u64_to_u16_limbs(b_val, b_limbs);
    divrem_u64_to_u16_limbs(c_val, c_limbs);

    // Initialize
    for (int i = 0; i < WORD_SIZE; i++) {
        op.u16_flags[i] = T::zero();
    }
    op.not_eq_inv = T::zero();
    op.comparison_limbs[0] = T::zero();
    op.comparison_limbs[1] = T::zero();

    // Find most significant differing limb
    for (int i = WORD_SIZE - 1; i >= 0; i--) {
        if (b_limbs[i] != c_limbs[i]) {
            op.u16_flags[i] = T::one();
            op.comparison_limbs[0] = T::from_canonical_u32(b_limbs[i]);
            op.comparison_limbs[1] = T::from_canonical_u32(c_limbs[i]);
            // Compute field inverse of (b_limb - c_limb)
            kb31_t b_field = kb31_t::from_canonical_u32(b_limbs[i]);
            kb31_t c_field = kb31_t::from_canonical_u32(c_limbs[i]);
            kb31_t diff = b_field - c_field;
            op.not_eq_inv = diff.reciprocal();
            break;
        }
    }

    // Result bit
    op.u16_compare_operation.bit = T::from_canonical_u32((uint32_t)(a_flag & 1));
}

/// Main kernel for DivRemChip trace generation.
template <class T>
__global__ void riscv_divrem_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::MulGpuEvent* events,
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

            // Populate opcode flags
            cols.is_div = T::from_bool(opcode == OP_DIV);
            cols.is_divu = T::from_bool(opcode == OP_DIVU);
            cols.is_rem = T::from_bool(opcode == OP_REM);
            cols.is_remu = T::from_bool(opcode == OP_REMU);
            cols.is_divw = T::from_bool(opcode == OP_DIVW);
            cols.is_divuw = T::from_bool(opcode == OP_DIVUW);
            cols.is_remw = T::from_bool(opcode == OP_REMW);
            cols.is_remuw = T::from_bool(opcode == OP_REMUW);

            cols.is_real = T::one();

            T not_word_op = T::one() - cols.is_divw - cols.is_remw - cols.is_divuw - cols.is_remuw;
            cols.is_real_not_word = cols.is_real * not_word_op;

            // Get the correct computational values of b and c
            uint64_t b_val, c_val;
            if (is_signed_word_op(opcode)) {
                b_val = (uint64_t)(int64_t)(int32_t)event.b;
                c_val = (uint64_t)(int64_t)(int32_t)event.c;
            } else if (is_unsigned_word_op(opcode)) {
                b_val = (uint64_t)(uint32_t)event.b;
                c_val = (uint64_t)(uint32_t)event.c;
            } else {
                b_val = event.b;
                c_val = event.c;
            }

            // Populate a, b, c words
            u64_to_word(event.a, cols.a);
            u64_to_word(b_val, cols.b);
            u64_to_word(c_val, cols.c);

            // Is c == 0?
            populate_is_zero_word(cols.is_c_0, c_val);

            // Compute quotient and remainder
            uint64_t quotient, remainder;
            get_quotient_and_remainder(event.b, event.c, opcode, quotient, remainder);

            u64_to_word(quotient, cols.quotient);
            u64_to_word(remainder, cols.remainder);

            // Computational forms
            uint64_t quotient_comp =
                is_unsigned_word_op(opcode) ? (uint64_t)(uint32_t)quotient : quotient;
            uint64_t remainder_comp =
                is_unsigned_word_op(opcode) ? (uint64_t)(uint32_t)remainder : remainder;
            u64_to_word(quotient_comp, cols.quotient_comp);
            u64_to_word(remainder_comp, cols.remainder_comp);

            // Sign detection and overflow
            bool overflow = false;
            if (is_signed_64bit_op(opcode)) {
                cols.rem_neg = T::from_canonical_u32(divrem_get_msb(remainder));
                cols.b_neg = T::from_canonical_u32(divrem_get_msb(event.b));
                cols.c_neg = T::from_canonical_u32(divrem_get_msb(event.c));
                overflow = ((int64_t)event.b == INT64_MIN) && ((int64_t)event.c == -1);
                cols.is_overflow = T::from_bool(overflow);
                uint64_t abs_rem =
                    (uint64_t)(((int64_t)remainder < 0) ? -(int64_t)remainder : (int64_t)remainder);
                uint64_t abs_c_val =
                    (uint64_t)(((int64_t)event.c < 0) ? -(int64_t)event.c : (int64_t)event.c);
                u64_to_word(abs_rem, cols.abs_remainder);
                u64_to_word(abs_c_val, cols.abs_c);
                uint64_t max_abs_c = (abs_c_val > 1) ? abs_c_val : 1;
                u64_to_word(max_abs_c, cols.max_abs_c_or_1);
            } else if (is_signed_word_op(opcode)) {
                // For signed word, use sign-extended values
                uint64_t rem_sign_ext = (uint64_t)(int64_t)(int32_t)remainder;
                uint64_t b_sign_ext = (uint64_t)(int64_t)(int32_t)event.b;
                uint64_t c_sign_ext = (uint64_t)(int64_t)(int32_t)event.c;
                cols.rem_neg = T::from_canonical_u32(divrem_get_msb(rem_sign_ext));
                cols.b_neg = T::from_canonical_u32(divrem_get_msb(b_sign_ext));
                cols.c_neg = T::from_canonical_u32(divrem_get_msb(c_sign_ext));
                overflow = ((int32_t)event.b == INT32_MIN) && ((int32_t)event.c == -1);
                cols.is_overflow = T::from_bool(overflow);
                // abs_remainder and abs_c use the sign-extended (b_val, c_val) values
                uint64_t abs_rem =
                    (uint64_t)(((int64_t)remainder < 0) ? -(int64_t)remainder : (int64_t)remainder);
                uint64_t abs_c_val =
                    (uint64_t)(((int64_t)c_val < 0) ? -(int64_t)c_val : (int64_t)c_val);
                u64_to_word(abs_rem, cols.abs_remainder);
                u64_to_word(abs_c_val, cols.abs_c);
                uint64_t max_abs_c = (abs_c_val > 1) ? abs_c_val : 1;
                u64_to_word(max_abs_c, cols.max_abs_c_or_1);
            } else if (is_unsigned_word_op(opcode)) {
                // No sign for unsigned word ops
                cols.abs_remainder = cols.remainder_comp;
                uint64_t abs_c_val = (uint64_t)(uint32_t)event.c;
                u64_to_word(abs_c_val, cols.abs_c);
                uint64_t max_abs_c = (abs_c_val > 1) ? abs_c_val : 1;
                u64_to_word(max_abs_c, cols.max_abs_c_or_1);
            } else {
                // Unsigned 64-bit
                cols.abs_remainder = cols.remainder_comp;
                u64_to_word(event.c, cols.abs_c);
                uint64_t max_abs_c = (event.c > 1) ? event.c : 1;
                u64_to_word(max_abs_c, cols.max_abs_c_or_1);
            }

            // Overflow detection: compare b and c against overflow constants
            if (is_word_op(opcode)) {
                populate_is_equal_word(
                    cols.is_overflow_b,
                    (uint64_t)(uint32_t)event.b,
                    (uint64_t)(uint32_t)(int32_t)INT32_MIN);
                populate_is_equal_word(
                    cols.is_overflow_c,
                    (uint64_t)(uint32_t)event.c,
                    (uint64_t)(uint32_t)(int32_t)-1);
            } else {
                populate_is_equal_word(cols.is_overflow_b, event.b, (uint64_t)INT64_MIN);
                populate_is_equal_word(cols.is_overflow_c, event.c, (uint64_t)(int64_t)-1);
            }

            // Derived sign flags
            T one_val = T::one();
            T is_overflow_val = cols.is_overflow;
            cols.b_neg_not_overflow = cols.b_neg * (one_val - is_overflow_val);
            cols.b_not_neg_not_overflow = (one_val - cols.b_neg) * (one_val - is_overflow_val);

            // ALU event flags
            cols.abs_c_alu_event = cols.c_neg * cols.is_real;
            cols.abs_rem_alu_event = cols.rem_neg * cols.is_real;

            // Populate c_neg_operation (negation of c)
            // c_neg_operation.value = c + abs_c (which wraps to 0 for negation)
            if (cols.abs_c_alu_event == one_val) {
                uint64_t c_word_val = c_val;
                uint64_t abs_c_word_val;
                // Read back abs_c from cols
                uint16_t abs_c_limbs[WORD_SIZE];
                abs_c_limbs[0] = cols.abs_c._0[0].as_canonical_u32();
                abs_c_limbs[1] = cols.abs_c._0[1].as_canonical_u32();
                abs_c_limbs[2] = cols.abs_c._0[2].as_canonical_u32();
                abs_c_limbs[3] = cols.abs_c._0[3].as_canonical_u32();
                abs_c_word_val = (uint64_t)abs_c_limbs[0] | ((uint64_t)abs_c_limbs[1] << 16) |
                                 ((uint64_t)abs_c_limbs[2] << 32) |
                                 ((uint64_t)abs_c_limbs[3] << 48);
                // AddOperation.value = wrapping add of c + abs_c
                uint64_t add_result = c_word_val + abs_c_word_val;
                u64_to_word(add_result, cols.c_neg_operation.value);
            }

            // Populate rem_neg_operation (negation of remainder)
            if (cols.abs_rem_alu_event == one_val) {
                uint64_t rem_word_val;
                if (is_signed_word_op(opcode)) {
                    rem_word_val = (uint64_t)(int64_t)(int32_t)remainder;
                } else {
                    rem_word_val = remainder;
                }
                uint16_t abs_rem_limbs[WORD_SIZE];
                abs_rem_limbs[0] = cols.abs_remainder._0[0].as_canonical_u32();
                abs_rem_limbs[1] = cols.abs_remainder._0[1].as_canonical_u32();
                abs_rem_limbs[2] = cols.abs_remainder._0[2].as_canonical_u32();
                abs_rem_limbs[3] = cols.abs_remainder._0[3].as_canonical_u32();
                uint64_t abs_rem_word_val =
                    (uint64_t)abs_rem_limbs[0] | ((uint64_t)abs_rem_limbs[1] << 16) |
                    ((uint64_t)abs_rem_limbs[2] << 32) | ((uint64_t)abs_rem_limbs[3] << 48);
                uint64_t add_result = rem_word_val + abs_rem_word_val;
                u64_to_word(add_result, cols.rem_neg_operation.value);
            }

            // MSB operations
            if (is_word_op(opcode)) {
                cols.b_msb.msb = T::from_canonical_u32(((event.b >> 16) >> 15) & 1);
                cols.c_msb.msb = T::from_canonical_u32(((event.c >> 16) >> 15) & 1);
                cols.rem_msb.msb = T::from_canonical_u32(((remainder >> 16) >> 15) & 1);
                cols.quot_msb.msb = T::from_canonical_u32(((quotient >> 16) >> 15) & 1);
            } else {
                cols.b_msb.msb = T::from_canonical_u32((b_val >> 48 >> 15) & 1);
                cols.c_msb.msb = T::from_canonical_u32((c_val >> 48 >> 15) & 1);
                cols.rem_msb.msb = T::from_canonical_u32((remainder >> 48 >> 15) & 1);
                // quot_msb is not set for 64-bit ops (stays zero)
            }

            // Remainder range check
            bool is_c_zero = (cols.is_c_0.result == one_val);
            cols.remainder_check_multiplicity = cols.is_real * (one_val - cols.is_c_0.result);
            if (!is_c_zero) {
                // Determine abs_remainder and max_abs_c_or_1 for LT check
                uint16_t abs_rem_limbs2[WORD_SIZE];
                abs_rem_limbs2[0] = cols.abs_remainder._0[0].as_canonical_u32();
                abs_rem_limbs2[1] = cols.abs_remainder._0[1].as_canonical_u32();
                abs_rem_limbs2[2] = cols.abs_remainder._0[2].as_canonical_u32();
                abs_rem_limbs2[3] = cols.abs_remainder._0[3].as_canonical_u32();
                uint64_t abs_rem_u64 =
                    (uint64_t)abs_rem_limbs2[0] | ((uint64_t)abs_rem_limbs2[1] << 16) |
                    ((uint64_t)abs_rem_limbs2[2] << 32) | ((uint64_t)abs_rem_limbs2[3] << 48);

                uint16_t max_c_limbs[WORD_SIZE];
                max_c_limbs[0] = cols.max_abs_c_or_1._0[0].as_canonical_u32();
                max_c_limbs[1] = cols.max_abs_c_or_1._0[1].as_canonical_u32();
                max_c_limbs[2] = cols.max_abs_c_or_1._0[2].as_canonical_u32();
                max_c_limbs[3] = cols.max_abs_c_or_1._0[3].as_canonical_u32();
                uint64_t max_c_u64 = (uint64_t)max_c_limbs[0] | ((uint64_t)max_c_limbs[1] << 16) |
                                     ((uint64_t)max_c_limbs[2] << 32) |
                                     ((uint64_t)max_c_limbs[3] << 48);

                populate_lt_unsigned(cols.remainder_lt_operation, 1, abs_rem_u64, max_c_u64);
            }

            // c * quotient computation
            {
                // Compute c * quotient_comp as 128-bit product
                uint8_t c_times_quotient_byte[16] = {0};

                // Lower 64 bits
                uint64_t lower_product = quotient_comp * c_val; // wrapping mul
                for (int j = 0; j < 8; j++) {
                    c_times_quotient_byte[j] = (lower_product >> (j * 8)) & 0xFF;
                }

                // Upper 64 bits
                uint64_t upper_product;
                if (is_signed_64bit_op(opcode) || is_signed_word_op(opcode)) {
                    __int128 sq = (__int128)(int64_t)quotient_comp;
                    __int128 sc = (__int128)(int64_t)c_val;
                    upper_product = (uint64_t)((sq * sc) >> 64);
                } else {
                    unsigned __int128 uq = (unsigned __int128)quotient_comp;
                    unsigned __int128 uc = (unsigned __int128)c_val;
                    upper_product = (uint64_t)((uq * uc) >> 64);
                }
                for (int j = 0; j < 8; j++) {
                    c_times_quotient_byte[8 + j] = (upper_product >> (j * 8)) & 0xFF;
                }

                // Convert to u16 limbs for c_times_quotient
                uint16_t c_times_quotient_u16[LONG_WORD_SIZE];
                for (int j = 0; j < LONG_WORD_SIZE; j++) {
                    c_times_quotient_u16[j] = (uint16_t)c_times_quotient_byte[2 * j] |
                                              ((uint16_t)c_times_quotient_byte[2 * j + 1] << 8);
                    cols.c_times_quotient[j] = T::from_canonical_u32(c_times_quotient_u16[j]);
                }

                // Populate lower MulOperation (always enabled)
                populate_mul_operation_divrem(
                    cols.c_times_quotient_lower,
                    quotient_comp,
                    c_val,
                    false,
                    false,
                    false);

                // Populate upper MulOperation (for 64-bit ops)
                if (is_signed_64bit_op(opcode)) {
                    populate_mul_operation_divrem(
                        cols.c_times_quotient_upper,
                        quotient_comp,
                        c_val,
                        true,
                        false,
                        false);
                } else if (is_unsigned_64bit_op(opcode)) {
                    populate_mul_operation_divrem(
                        cols.c_times_quotient_upper,
                        quotient_comp,
                        c_val,
                        false,
                        false,
                        false);
                }

                // Add remainder with carry propagation
                uint32_t remainder_u16[LONG_WORD_SIZE] = {0};
                for (int j = 0; j < 4; j++) {
                    remainder_u16[j] = cols.remainder_comp._0[j].as_canonical_u32();
                }
                // Sign-extend upper half if remainder is negative
                uint32_t rem_neg_u32 = cols.rem_neg.as_canonical_u32();
                for (int j = 4; j < LONG_WORD_SIZE; j++) {
                    remainder_u16[j] = rem_neg_u32 * ((1 << 16) - 1);
                }

                uint32_t carry_val[LONG_WORD_SIZE] = {0};
                uint32_t base = 1 << 16;
                for (int j = 0; j < LONG_WORD_SIZE; j++) {
                    uint32_t x = (uint32_t)c_times_quotient_u16[j] + remainder_u16[j];
                    if (j > 0) {
                        x += carry_val[j - 1];
                    }
                    carry_val[j] = x / base;
                    cols.carry[j] = T::from_canonical_u32(carry_val[j]);
                }
            }

            // Populate CPUState from clk and pc
            populate_cpu_state(cols.state, event.clk, event.pc);

            // Populate RTypeReader from event
            populate_r_type_reader(cols.adapter, event);
        } else {
            // Padding row template: 0 / 1 = 0 remainder 0 (DIVU)
            cols.is_divu = T::one();
            cols.adapter.op_c_memory.prev_value._0[0] = T::one();
            cols.abs_c._0[0] = T::one();
            cols.c._0[0] = T::one();
            cols.max_abs_c_or_1._0[0] = T::one();
            cols.b_not_neg_not_overflow = T::one();
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
