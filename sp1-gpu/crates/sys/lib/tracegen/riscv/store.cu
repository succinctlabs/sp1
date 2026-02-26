/// GPU trace generation for RISC-V memory store instructions.
///
/// Handles StoreByte (SB), StoreHalf (SH), StoreWord (SW), StoreDouble (SD).

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

/// GPU-compatible event for memory store instructions.
/// Must match the Rust StoreGpuEvent struct layout in riscv_events.rs.
struct StoreGpuEvent {
    uint64_t clk;
    uint64_t pc;
    uint64_t b;
    uint64_t c;
    uint64_t a;
    uint64_t mem_access_prev_value;
    uint64_t mem_access_new_value;
    uint64_t mem_access_prev_timestamp;
    uint64_t mem_access_current_timestamp;
    uint8_t op_a;
    uint64_t op_b;
    uint64_t op_c;
    bool op_a_0;
    sp1_gpu_sys::GpuMemoryAccess mem_a;
    sp1_gpu_sys::GpuMemoryAccess mem_b;
};

/// Populate ITypeReader from a StoreGpuEvent.
template <class T>
__device__ void populate_i_type_reader_from_store(
    sp1_gpu_sys::ITypeReader<T>& adapter,
    const StoreGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a_0);

    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    u64_to_word(event.op_c, adapter.op_c_imm);
}

// Reuse column structures from load.cu that are shared.
// These are manually defined since cbindgen can't handle them.
namespace sp1_gpu_sys {

/// Memory access timestamp columns (5 fields).
template <typename T>
struct MemoryAccessTimestamp {
    T prev_high;
    T prev_low;
    T compare_low;
    T diff_low_limb;
    T diff_high_limb;
};

/// Memory access columns: prev_value (4 u16 limbs) + timestamp.
template <typename T>
struct MemoryAccessCols {
    Word<T> prev_value;
    MemoryAccessTimestamp<T> access_timestamp;
};

/// Address addition operation: result as 3 u16 limbs (48 bits).
template <typename T>
struct AddrAddOperation {
    T value[3];
};

/// Address operation: addr_operation + top_two_limb_inv for validation.
template <typename T>
struct AddressOperation {
    AddrAddOperation<T> addr_operation;
    T top_two_limb_inv;
};

/// StoreByteColumns
template <typename T>
struct StoreByteColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit[3];
    T mem_limb;
    T mem_limb_low_byte;
    T register_low_byte;
    T increment;
    Word<T> store_value;
    T is_real;
};

/// StoreHalfColumns
template <typename T>
struct StoreHalfColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit[2];
    Word<T> store_value;
    T is_real;
};

/// StoreWordColumns
template <typename T>
struct StoreWordColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit;
    Word<T> store_value;
    T is_real;
};

/// StoreDoubleColumns
template <typename T>
struct StoreDoubleColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T is_real;
};

} // namespace sp1_gpu_sys

/// Populate MemoryAccessTimestamp from timestamps.
template <class T>
__device__ void populate_memory_access_timestamp(
    sp1_gpu_sys::MemoryAccessTimestamp<T>& ts,
    uint64_t prev_timestamp,
    uint64_t current_timestamp) {
    uint32_t prev_high = prev_timestamp >> 24;
    uint32_t prev_low_val = prev_timestamp & 0xFFFFFF;
    uint32_t current_high = current_timestamp >> 24;
    uint32_t current_low_val = current_timestamp & 0xFFFFFF;

    ts.prev_high = T::from_canonical_u32(prev_high);
    ts.prev_low = T::from_canonical_u32(prev_low_val);

    bool use_low_comparison = (prev_high == current_high);
    ts.compare_low = T::from_bool(use_low_comparison);

    uint32_t prev_time_value = use_low_comparison ? prev_low_val : prev_high;
    uint32_t current_time_value = use_low_comparison ? current_low_val : current_high;

    uint32_t diff_minus_one = current_time_value - prev_time_value - 1;
    ts.diff_low_limb = T::from_canonical_u32(diff_minus_one & 0xFFFF);
    ts.diff_high_limb = T::from_canonical_u32((diff_minus_one >> 16) & 0xFF);
}

/// Populate MemoryAccessCols from memory access fields.
template <class T>
__device__ void populate_memory_access_cols(
    sp1_gpu_sys::MemoryAccessCols<T>& cols,
    uint64_t prev_value,
    uint64_t prev_timestamp,
    uint64_t current_timestamp) {
    u64_to_word(prev_value, cols.prev_value);
    populate_memory_access_timestamp(cols.access_timestamp, prev_timestamp, current_timestamp);
}

/// Populate AddressOperation from base address b and offset c.
template <class T>
__device__ uint64_t
populate_address_operation(sp1_gpu_sys::AddressOperation<T>& op, uint64_t b, uint64_t c) {
    uint64_t memory_addr = b + c; // wrapping add
    op.addr_operation.value[0] = T::from_canonical_u32(memory_addr & 0xFFFF);
    op.addr_operation.value[1] = T::from_canonical_u32((memory_addr >> 16) & 0xFFFF);
    op.addr_operation.value[2] = T::from_canonical_u32((memory_addr >> 32) & 0xFFFF);

    uint32_t limb1 = (memory_addr >> 16) & 0xFFFF;
    uint32_t limb2 = (memory_addr >> 32) & 0xFFFF;
    T sum = T::from_canonical_u32(limb1) + T::from_canonical_u32(limb2);
    op.top_two_limb_inv = sum.reciprocal();

    return memory_addr;
}

// =============================================================================
// StoreByte kernel
// =============================================================================
template <class T>
__global__ void riscv_store_byte_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const StoreGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::StoreByteColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::StoreByteColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_prev_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            uint64_t memory_addr =
                populate_address_operation(cols.address_operation, event.b, event.c);

            uint16_t bit0 = memory_addr & 1;
            uint16_t bit1 = (memory_addr >> 1) & 1;
            uint16_t bit2 = (memory_addr >> 2) & 1;
            cols.offset_bit[0] = T::from_canonical_u32(bit0);
            cols.offset_bit[1] = T::from_canonical_u32(bit1);
            cols.offset_bit[2] = T::from_canonical_u32(bit2);

            // Select the u16 limb from prev_value based on offset bits
            uint16_t limb_number = 2 * bit2 + bit1;
            uint64_t prev_value = event.mem_access_prev_value;
            uint16_t limbs[4] = {
                static_cast<uint16_t>(prev_value & 0xFFFF),
                static_cast<uint16_t>((prev_value >> 16) & 0xFFFF),
                static_cast<uint16_t>((prev_value >> 32) & 0xFFFF),
                static_cast<uint16_t>((prev_value >> 48) & 0xFFFF),
            };
            uint16_t limb = limbs[limb_number];
            cols.mem_limb = T::from_canonical_u32(limb);
            cols.mem_limb_low_byte = T::from_canonical_u32(limb & 0xFF);

            // Register low byte (the byte to store)
            uint8_t register_low_byte = event.a & 0xFF;
            cols.register_low_byte = T::from_canonical_u32(register_low_byte);

            // Compute increment
            // If bit0=0: increment = register_low_byte - mem_limb_low_byte
            // If bit0=1: increment = 256 * register_low_byte - mem_limb + mem_limb_low_byte
            T bit0_f = cols.offset_bit[0];
            T one_minus_bit0 = T::one() - bit0_f;
            T inc_low = cols.register_low_byte - cols.mem_limb_low_byte;
            // Use *= to force full Montgomery reduction and avoid accel_t intermediates
            T inc_high = T::from_canonical_u32(256);
            inc_high *= cols.register_low_byte;
            inc_high -= cols.mem_limb;
            inc_high += cols.mem_limb_low_byte;
            // Also force full reduction for the final sum
            T term_low = inc_low;
            term_low *= one_minus_bit0;
            T term_high = inc_high;
            term_high *= bit0_f;
            cols.increment = term_low + term_high;

            // Store value is the new value after write
            u64_to_word(event.mem_access_new_value, cols.store_value);

            cols.is_real = T::one();

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_store(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// StoreHalf kernel
// =============================================================================
template <class T>
__global__ void riscv_store_half_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const StoreGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::StoreHalfColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::StoreHalfColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_prev_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            uint64_t memory_addr =
                populate_address_operation(cols.address_operation, event.b, event.c);

            uint16_t bit1 = (memory_addr >> 1) & 1;
            uint16_t bit2 = (memory_addr >> 2) & 1;
            cols.offset_bit[0] = T::from_canonical_u32(bit1);
            cols.offset_bit[1] = T::from_canonical_u32(bit2);

            // Store value is the new value after write
            u64_to_word(event.mem_access_new_value, cols.store_value);

            cols.is_real = T::one();

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_store(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// StoreWord kernel
// =============================================================================
template <class T>
__global__ void riscv_store_word_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const StoreGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::StoreWordColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::StoreWordColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_prev_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            uint64_t memory_addr =
                populate_address_operation(cols.address_operation, event.b, event.c);

            uint16_t bit2 = (memory_addr >> 2) & 1;
            cols.offset_bit = T::from_canonical_u32(bit2);

            u64_to_word(event.mem_access_new_value, cols.store_value);

            cols.is_real = T::one();

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_store(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// StoreDouble kernel
// =============================================================================
template <class T>
__global__ void riscv_store_double_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const StoreGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::StoreDoubleColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::StoreDoubleColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_prev_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            populate_address_operation(cols.address_operation, event.b, event.c);

            cols.is_real = T::one();

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_store(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// Kernel exports
// =============================================================================
namespace sp1_gpu_sys {
extern KernelPtr riscv_store_byte_generate_trace_kernel() {
    return (KernelPtr)::riscv_store_byte_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_store_half_generate_trace_kernel() {
    return (KernelPtr)::riscv_store_half_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_store_word_generate_trace_kernel() {
    return (KernelPtr)::riscv_store_word_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_store_double_generate_trace_kernel() {
    return (KernelPtr)::riscv_store_double_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
