/// GPU trace generation for RISC-V memory load instructions.
///
/// Handles LoadByte (LB, LBU), LoadHalf (LH, LHU), LoadWord (LW, LWU),
/// LoadDouble (LD), and LoadX0 (all load opcodes with op_a = x0).

#include "tracegen/riscv/common.cuh"

using namespace riscv_tracegen;

/// GPU-compatible event for memory load instructions.
/// Must match the Rust LoadGpuEvent struct layout in riscv_events.rs.
struct LoadGpuEvent {
    uint64_t clk;
    uint64_t pc;
    uint64_t b;
    uint64_t c;
    uint64_t a;
    uint8_t opcode;
    uint64_t mem_access_value;
    uint64_t mem_access_prev_timestamp;
    uint64_t mem_access_current_timestamp;
    uint8_t op_a;
    uint64_t op_b;
    uint64_t op_c;
    bool op_a_0;
    sp1_gpu_sys::GpuMemoryAccess mem_a;
    sp1_gpu_sys::GpuMemoryAccess mem_b;
};

/// Populate ITypeReader from a LoadGpuEvent.
template <class T>
__device__ void
populate_i_type_reader_from_load(sp1_gpu_sys::ITypeReader<T>& adapter, const LoadGpuEvent& event) {
    adapter.op_a = T::from_canonical_u32(event.op_a);
    populate_register_access_cols(adapter.op_a_memory, event.mem_a);
    adapter.op_a_0 = T::from_bool(event.op_a_0);

    adapter.op_b = T::from_canonical_u32(static_cast<uint32_t>(event.op_b));
    populate_register_access_cols(adapter.op_b_memory, event.mem_b);

    u64_to_word(event.op_c, adapter.op_c_imm);
}

// Manually define column structures since cbindgen can't handle
// MemoryAccessCols and AddressOperation from the core crate.
namespace sp1_gpu_sys {

/// Memory access timestamp columns (5 fields).
/// Different from RegisterAccessTimestamp which only has 2 fields.
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

/// LoadByteColumns
template <typename T>
struct LoadByteColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit[3];
    T selected_limb;
    T selected_limb_low_byte;
    T selected_byte;
    T msb;
    T is_lb;
    T is_lbu;
};

/// LoadHalfColumns
template <typename T>
struct LoadHalfColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit[2];
    T selected_half;
    U16MSBOperation<T> msb;
    T is_lh;
    T is_lhu;
};

/// LoadWordColumns
template <typename T>
struct LoadWordColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit;
    T selected_word[2];
    U16MSBOperation<T> msb;
    T is_lw;
    T is_lwu;
};

/// LoadDoubleColumns
template <typename T>
struct LoadDoubleColumns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T is_real;
};

/// LoadX0Columns
template <typename T>
struct LoadX0Columns {
    CPUState<T> state;
    ITypeReader<T> adapter;
    AddressOperation<T> address_operation;
    MemoryAccessCols<T> memory_access;
    T offset_bit[3];
    T is_lb;
    T is_lbu;
    T is_lh;
    T is_lhu;
    T is_lw;
    T is_lwu;
    T is_ld;
};

} // namespace sp1_gpu_sys

// Load opcode values matching sp1_core_executor::Opcode
enum LoadOpcode : uint8_t {
    LB_OP = 0,
    LBU_OP = 1,
    LH_OP = 2,
    LHU_OP = 3,
    LW_OP = 4,
    LWU_OP = 5,
    LD_OP = 6,
};

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

/// Populate MemoryAccessCols from a LoadGpuEvent's memory access fields.
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
    // Populate AddrAddOperation: 3 u16 limbs of the 48-bit address
    op.addr_operation.value[0] = T::from_canonical_u32(memory_addr & 0xFFFF);
    op.addr_operation.value[1] = T::from_canonical_u32((memory_addr >> 16) & 0xFFFF);
    op.addr_operation.value[2] = T::from_canonical_u32((memory_addr >> 32) & 0xFFFF);

    // top_two_limb_inv = inverse of (addr_limb[1] + addr_limb[2])
    uint32_t limb1 = (memory_addr >> 16) & 0xFFFF;
    uint32_t limb2 = (memory_addr >> 32) & 0xFFFF;
    T sum = T::from_canonical_u32(limb1) + T::from_canonical_u32(limb2);
    op.top_two_limb_inv = sum.reciprocal();

    return memory_addr;
}

// =============================================================================
// LoadByte kernel
// =============================================================================
template <class T>
__global__ void riscv_load_byte_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const LoadGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::LoadByteColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::LoadByteColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            // Populate memory access columns
            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            // Compute address and offset bits
            uint64_t memory_addr =
                populate_address_operation(cols.address_operation, event.b, event.c);
            uint16_t bit0 = memory_addr & 1;
            uint16_t bit1 = (memory_addr >> 1) & 1;
            uint16_t bit2 = (memory_addr >> 2) & 1;
            cols.offset_bit[0] = T::from_canonical_u32(bit0);
            cols.offset_bit[1] = T::from_canonical_u32(bit1);
            cols.offset_bit[2] = T::from_canonical_u32(bit2);

            // Select the u16 limb
            uint16_t limb_number = 2 * bit2 + bit1;
            uint64_t mem_value = event.mem_access_value;
            uint16_t limbs[4] = {
                static_cast<uint16_t>(mem_value & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 16) & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 32) & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 48) & 0xFFFF),
            };
            uint16_t limb = limbs[limb_number];
            cols.selected_limb = T::from_canonical_u32(limb);
            cols.selected_limb_low_byte = T::from_canonical_u32(limb & 0xFF);

            // Extract the byte
            uint8_t low_byte = limb & 0xFF;
            uint8_t high_byte = (limb >> 8) & 0xFF;
            uint8_t byte = bit0 ? high_byte : low_byte;
            cols.selected_byte = T::from_canonical_u32(byte);

            // Opcode flags
            bool is_lb = (event.opcode == LB_OP);
            cols.is_lb = T::from_bool(is_lb);
            cols.is_lbu = T::from_bool(!is_lb);

            // MSB for signed load
            if (is_lb) {
                cols.msb = T::from_canonical_u32((byte >> 7) & 1);
            }

            // Populate CPU state and adapter
            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_load(cols.adapter, event);
        }

        // Write to trace in column-major format
        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// LoadHalf kernel
// =============================================================================
template <class T>
__global__ void riscv_load_half_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const LoadGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::LoadHalfColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::LoadHalfColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            uint64_t memory_addr =
                populate_address_operation(cols.address_operation, event.b, event.c);
            uint16_t bit1 = (memory_addr >> 1) & 1;
            uint16_t bit2 = (memory_addr >> 2) & 1;
            uint16_t limb_number = 2 * bit2 + bit1;
            cols.offset_bit[0] = T::from_canonical_u32(bit1);
            cols.offset_bit[1] = T::from_canonical_u32(bit2);

            uint64_t mem_value = event.mem_access_value;
            uint16_t limbs[4] = {
                static_cast<uint16_t>(mem_value & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 16) & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 32) & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 48) & 0xFFFF),
            };
            uint16_t limb = limbs[limb_number];
            cols.selected_half = T::from_canonical_u32(limb);

            bool is_lh = (event.opcode == LH_OP);
            cols.is_lh = T::from_bool(is_lh);
            cols.is_lhu = T::from_bool(!is_lh);

            if (is_lh) {
                cols.msb.msb = T::from_canonical_u32((limb >> 15) & 1);
            }

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_load(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// LoadWord kernel
// =============================================================================
template <class T>
__global__ void riscv_load_word_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const LoadGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::LoadWordColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::LoadWordColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            uint64_t memory_addr =
                populate_address_operation(cols.address_operation, event.b, event.c);
            uint16_t bit2 = (memory_addr >> 2) & 1;
            cols.offset_bit = T::from_canonical_u32(bit2);

            uint16_t limb_number = 2 * bit2;
            uint64_t mem_value = event.mem_access_value;
            uint16_t limbs[4] = {
                static_cast<uint16_t>(mem_value & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 16) & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 32) & 0xFFFF),
                static_cast<uint16_t>((mem_value >> 48) & 0xFFFF),
            };
            uint16_t limb_0 = limbs[limb_number];
            uint16_t limb_1 = limbs[limb_number + 1];
            cols.selected_word[0] = T::from_canonical_u32(limb_0);
            cols.selected_word[1] = T::from_canonical_u32(limb_1);

            bool is_lw = (event.opcode == LW_OP);
            cols.is_lw = T::from_bool(is_lw);
            cols.is_lwu = T::from_bool(!is_lw);

            if (is_lw) {
                cols.msb.msb = T::from_canonical_u32((limb_1 >> 15) & 1);
            }

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_load(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// LoadDouble kernel
// =============================================================================
template <class T>
__global__ void riscv_load_double_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const LoadGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::LoadDoubleColumns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::LoadDoubleColumns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_value,
                event.mem_access_prev_timestamp,
                event.mem_access_current_timestamp);

            populate_address_operation(cols.address_operation, event.b, event.c);
            cols.is_real = T::one();

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_load(cols.adapter, event);
        }

        const T* arr = reinterpret_cast<const T*>(&cols);
        for (size_t k = 0; k < COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

// =============================================================================
// LoadX0 kernel
// =============================================================================
template <class T>
__global__ void riscv_load_x0_generate_trace_kernel(
    T* trace,
    uintptr_t trace_height,
    const LoadGpuEvent* events,
    uintptr_t nb_events) {
    static const size_t COLUMNS = sizeof(sp1_gpu_sys::LoadX0Columns<T>) / sizeof(T);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::LoadX0Columns<T> cols;
        T* cols_arr = reinterpret_cast<T*>(&cols);
        for (size_t k = 0; k < COLUMNS; k++) {
            cols_arr[k] = T::zero();
        }

        if (i < nb_events) {
            const auto& event = events[i];

            populate_memory_access_cols(
                cols.memory_access,
                event.mem_access_value,
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

            cols.is_lb = T::from_bool(event.opcode == LB_OP);
            cols.is_lbu = T::from_bool(event.opcode == LBU_OP);
            cols.is_lh = T::from_bool(event.opcode == LH_OP);
            cols.is_lhu = T::from_bool(event.opcode == LHU_OP);
            cols.is_lw = T::from_bool(event.opcode == LW_OP);
            cols.is_lwu = T::from_bool(event.opcode == LWU_OP);
            cols.is_ld = T::from_bool(event.opcode == LD_OP);

            populate_cpu_state(cols.state, event.clk, event.pc);
            populate_i_type_reader_from_load(cols.adapter, event);
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
extern KernelPtr riscv_load_byte_generate_trace_kernel() {
    return (KernelPtr)::riscv_load_byte_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_load_half_generate_trace_kernel() {
    return (KernelPtr)::riscv_load_half_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_load_word_generate_trace_kernel() {
    return (KernelPtr)::riscv_load_word_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_load_double_generate_trace_kernel() {
    return (KernelPtr)::riscv_load_double_generate_trace_kernel<kb31_t>;
}
extern KernelPtr riscv_load_x0_generate_trace_kernel() {
    return (KernelPtr)::riscv_load_x0_generate_trace_kernel<kb31_t>;
}
} // namespace sp1_gpu_sys
