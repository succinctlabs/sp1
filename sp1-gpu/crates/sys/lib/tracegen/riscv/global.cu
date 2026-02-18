#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"
#include "fields/kb31_septic_extension_t.cuh"

#include "poseidon2/poseidon2.cuh"
#include "poseidon2/poseidon2_kb31_16.cuh"

#include "tracegen/poseidon2_wide.cuh"

constexpr static const uintptr_t POSEIDON2_WIDTH = poseidon2_kb31_16::constants::WIDTH;

// (kb::MOD-1) / 2
constexpr static const uint32_t HALF_MOD_LOW = (kb31_t::MOD - 1) / 2;
// (kb::MOD+1)/2
constexpr static const uint32_t HALF_MOD_HIGH = (kb31_t::MOD + 1) / 2;
__device__ void populate_global_interaction(
    sp1_gpu_sys::GlobalInteractionOperation<kb31_t>* cols,
    const sp1_gpu_sys::GlobalInteractionEvent* event) {
    // Initialize `m_trial` to the first 7 elements of the message.

#pragma unroll(1)
    for (uint32_t offset = 0; offset < 256; ++offset) {
        kb31_t m_trial[POSEIDON2_WIDTH];
        {
            m_trial[0] = kb31_t::from_canonical_u32(event->message[0]) +
                         kb31_t::from_canonical_u32(uint32_t(event->kind) << 24);
            m_trial[1] = kb31_t::from_canonical_u32(event->message[1]);
            m_trial[2] = kb31_t::from_canonical_u32(event->message[2]);
            m_trial[3] = kb31_t::from_canonical_u32(event->message[3]);
            m_trial[4] = kb31_t::from_canonical_u32(event->message[4]);
            m_trial[5] = kb31_t::from_canonical_u32(event->message[5]);
            m_trial[6] = kb31_t::from_canonical_u32(event->message[6]);
            m_trial[7] = kb31_t::from_canonical_u32(event->message[7]) +
                         kb31_t::from_canonical_u32(offset << 16);
            m_trial[8] = kb31_t::zero();
            m_trial[9] = kb31_t::zero();
            m_trial[10] = kb31_t::zero();
            m_trial[11] = kb31_t::zero();
            m_trial[12] = kb31_t::zero();
            m_trial[13] = kb31_t::zero();
            m_trial[14] = kb31_t::zero();
            m_trial[15] = kb31_t::zero();
        }
        // Set the 8th element of `x_trial` to the offset.

        // Compute the poseidon2 hash of `m_trial` to compute `m_hash`.
        kb31_t m_hash[POSEIDON2_WIDTH];
        poseidon2::KoalaBearHasher::permute(m_trial, m_hash);

        // Convert the hash to a septic extension element.
        kb31_septic_extension_t x_trial = kb31_septic_extension_t::zero();
        for (uint32_t i = 0; i < 7; i++) {
            x_trial.value[i] = m_hash[i];
        }

        kb31_septic_extension_t y_sq = x_trial.curve_formula();
        kb31_t y_sq_pow_r = y_sq.pow_r();
        kb31_t is_square = y_sq_pow_r ^ HALF_MOD_LOW;
        if (is_square == kb31_t::one()) {
            kb31_septic_extension_t y = y_sq.sqrt(y_sq_pow_r);
            if (y.is_exception()) {
                continue;
            }
            if (y.is_receive() != event->is_receive) {
                y = kb31_septic_extension_t::zero() - y;
            }
            cols->offset = kb31_t::from_canonical_u32(offset);
            for (uintptr_t i = 0; i < 7; i++) {
                cols->x_coordinate._0[i] = x_trial.value[i];
                cols->y_coordinate._0[i] = y.value[i];
            }
            uint32_t range_check_value;
            if (event->is_receive) {
                range_check_value = y.value[6].as_canonical_u32() - 1;
            } else {
                range_check_value = kb31_t::MOD - y.value[6].as_canonical_u32() - 1;
            }
            for (uint32_t idx = 0; idx < 4; idx++) {
                cols->y6_byte_decomp[idx] =
                    kb31_t::from_canonical_u32((range_check_value >> (idx * 8)) & 0xFF);
            }
            kb31_t* input_row = reinterpret_cast<kb31_t*>(&cols->permutation);
            poseidon2_wide::event_to_row(m_trial, input_row, 0, 1);

            return;
        }
    }
}

__device__ void
populate_global_interaction_dummy(sp1_gpu_sys::GlobalInteractionOperation<kb31_t>* cols) {
    kb31_t m_trial[POSEIDON2_WIDTH];
    {
        m_trial[0] = kb31_t::zero();
        m_trial[1] = kb31_t::zero();
        m_trial[2] = kb31_t::zero();
        m_trial[3] = kb31_t::zero();
        m_trial[4] = kb31_t::zero();
        m_trial[5] = kb31_t::zero();
        m_trial[6] = kb31_t::zero();
        m_trial[7] = kb31_t::zero();
        m_trial[8] = kb31_t::zero();
        m_trial[9] = kb31_t::zero();
        m_trial[10] = kb31_t::zero();
        m_trial[11] = kb31_t::zero();
        m_trial[12] = kb31_t::zero();
        m_trial[13] = kb31_t::zero();
        m_trial[14] = kb31_t::zero();
        m_trial[15] = kb31_t::zero();
    }

    kb31_t* input_row = reinterpret_cast<kb31_t*>(&cols->permutation);
    poseidon2_wide::event_to_row(m_trial, input_row, 0, 1);
}

__global__ void riscv_global_generate_trace_decompress_kernel(
    kb31_t* trace,
    uintptr_t trace_height,
    const sp1_gpu_sys::GlobalInteractionEvent* events,
    uintptr_t nb_events) {
    static const size_t GLOBAL_COLUMNS = sizeof(sp1_gpu_sys::GlobalCols<kb31_t>) / sizeof(kb31_t);

    int i = blockIdx.x * blockDim.x + threadIdx.x;
#pragma unroll(1)
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        // ok so we're on the ith row
        bb31_septic_curve_t sum = bb31_septic_curve_t();
        if (i == 0) {
            sum = bb31_septic_curve_t::start_point();
        }
        sp1_gpu_sys::GlobalCols<kb31_t> cols;
        kb31_t* cols_arr = reinterpret_cast<kb31_t*>(&cols);
        for (int k = 0; k < GLOBAL_COLUMNS; k++) {
            cols_arr[k] = kb31_t::zero();
        }

        if (i < nb_events) {
            for (int k = 0; k < 8; k++) {
                cols.message[k] = kb31_t::from_canonical_u32(events[i].message[k]);
            }
            cols.is_receive = kb31_t::from_bool(events[i].is_receive);
            cols.kind = kb31_t::from_canonical_u8(events[i].kind);
            cols.is_send = kb31_t::one() - kb31_t::from_bool(events[i].is_receive);
            cols.is_real = kb31_t::one();
            cols.message_0_16bit_limb = kb31_t::from_canonical_u32(events[i].message[0] & 0xFFFF);
            cols.message_0_8bit_limb =
                kb31_t::from_canonical_u32((events[i].message[0] >> 16) & 0xFF);
            cols.index = kb31_t::from_canonical_u32(i);

            // Populate the interaction.
            populate_global_interaction(&cols.interaction, &events[i]);

            // Compute the running accumulator.
            cols.accumulation.cumulative_sum[0] = cols.interaction.x_coordinate;
            cols.accumulation.cumulative_sum[1] = cols.interaction.y_coordinate;
            bb31_septic_curve_t point = bb31_septic_curve_t(
                cols.interaction.x_coordinate._0,
                cols.interaction.y_coordinate._0);
            sum += point;
        } else {
            populate_global_interaction_dummy(&cols.interaction);
        }

        // Populate the initial digest.
        for (int k = 0; k < 7; k++) {
            cols.accumulation.initial_digest[0]._0[k] = sum.x.value[k];
            cols.accumulation.initial_digest[1]._0[k] = sum.y.value[k];
        }

        // Populate the trace.
        const kb31_t* arr = reinterpret_cast<kb31_t*>(&cols);
        for (size_t k = 0; k < GLOBAL_COLUMNS; ++k) {
            trace[i + k * trace_height] = arr[k];
        }
    }
}

__global__ void riscv_global_generate_trace_finalize_kernel(
    kb31_t* trace,
    uintptr_t trace_height,
    const bb31_septic_curve_t* cumulative_sums,
    uintptr_t nb_events) {
    static const size_t GLOBAL_COLUMNS = sizeof(sp1_gpu_sys::GlobalCols<kb31_t>) / sizeof(kb31_t);

    int i = blockIdx.x * blockDim.x + threadIdx.x;

#pragma unroll(1)
    for (; i < trace_height; i += blockDim.x * gridDim.x) {
        sp1_gpu_sys::GlobalCols<kb31_t> cols;
        kb31_t* temp_arr = reinterpret_cast<kb31_t*>(&cols);
        for (int j = 0; j < GLOBAL_COLUMNS; j++) {
            temp_arr[j] = trace[i + j * trace_height];
        }

        bb31_septic_curve_t sum = cumulative_sums[i];

        int event_idx = i;

        kb31_septic_extension_t point_x = kb31_septic_extension_t(cols.interaction.x_coordinate._0);
        kb31_septic_extension_t point_y =
            kb31_septic_extension_t(cols.interaction.y_coordinate._0) *
            (kb31_t::zero() - kb31_t::one());
        bb31_septic_curve_t point = bb31_septic_curve_t(point_x, point_y);

        for (int k = 0; k < 7; k++) {
            cols.accumulation.cumulative_sum[0]._0[k] = sum.x.value[k];
            cols.accumulation.cumulative_sum[1]._0[k] = sum.y.value[k];
        }

        sum += point;

        for (int k = 0; k < 7; k++) {
            cols.accumulation.initial_digest[0]._0[k] = sum.x.value[k];
            cols.accumulation.initial_digest[1]._0[k] = sum.y.value[k];
        }

        if (event_idx >= nb_events) {
            bb31_septic_curve_t dummy = bb31_septic_curve_t::dummy_point();
            bb31_septic_curve_t start = bb31_septic_curve_t::start_point();
            
            for (int k = 0; k < 7; k++) {
                cols.accumulation.initial_digest[0]._0[k] = start.x.value[k];
                cols.accumulation.initial_digest[1]._0[k] = start.y.value[k];
                cols.interaction.x_coordinate._0[k] = dummy.x.value[k];
                cols.interaction.y_coordinate._0[k] = dummy.y.value[k];
            }

            start += dummy;

            for (int k = 0; k < 7; k++) {
                cols.accumulation.cumulative_sum[0]._0[k] = start.x.value[k];
                cols.accumulation.cumulative_sum[1]._0[k] = start.y.value[k];
            }
        }

        kb31_t* final_temp = reinterpret_cast<kb31_t*>(&cols);
        for (int j = 0; j < GLOBAL_COLUMNS; j++) {
            trace[i + j * trace_height] = final_temp[j];
        }
    }
}

namespace sp1_gpu_sys {
extern KernelPtr riscv_global_generate_trace_decompress_kernel() {
    return (KernelPtr)::riscv_global_generate_trace_decompress_kernel;
}
extern KernelPtr riscv_global_generate_trace_finalize_kernel() {
    return (KernelPtr)::riscv_global_generate_trace_finalize_kernel;
}
} // namespace sp1_gpu_sys
