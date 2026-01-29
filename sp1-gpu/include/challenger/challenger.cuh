#pragma once
#include "fields/kb31_t.cuh"
#include "poseidon2/poseidon2_kb31_16.cuh"
#include "poseidon2/poseidon2_bn254_3.cuh"
#include "poseidon2/poseidon2.cuh"
#include "fields/kb31_extension_t.cuh"
#include "fields/bn254_t.cuh"

extern "C" void* grind_koala_bear();


class DuplexChallenger {
    static constexpr const int WIDTH = poseidon2_kb31_16::KoalaBear::WIDTH;
    static constexpr const int RATE = poseidon2_kb31_16::constants::RATE;

    kb31_t* sponge_state;
    kb31_t* input_buffer;
    size_t* buffer_sizes;
    kb31_t* output_buffer;

    __device__ void duplexing() {
        // Assert input size doesn't exceed RATE
        assert(buffer_sizes[0] <= RATE);

        // Copy input buffer elements to sponge state
        for (size_t i = 0; i < buffer_sizes[0]; i++) {
            sponge_state[i] = input_buffer[i];
        }

        // Clear input buffer.
        buffer_sizes[0] = 0;

        // Apply the permutation to the sponge state and store the output in the output buffer.
        poseidon2::KoalaBearHasher hasher;
        hasher.permute(sponge_state, output_buffer);

        // Copy the output buffer to the sponge state.
        buffer_sizes[1] = RATE;
        for (size_t i = 0; i < WIDTH; i++) {
            sponge_state[i] = output_buffer[i];
            if (i >= RATE) {
                output_buffer[i] = kb31_t::zero();
            }
        }
    }

  public:
    static constexpr const size_t NUM_ELEMENTS = WIDTH + 2 * RATE;

    __device__ __forceinline__ kb31_t getVal(size_t idx) { return sponge_state[idx % 16]; }

    __device__ __forceinline__ DuplexChallenger load(kb31_t* shared, size_t* buffer_sizes) {
        DuplexChallenger challenger;
        challenger.sponge_state = shared;
        challenger.input_buffer = shared + WIDTH;
        challenger.output_buffer = shared + WIDTH + RATE;
        challenger.buffer_sizes = buffer_sizes;
        return challenger;
    }

    __device__ __forceinline__ void observe(kb31_t* value) {
        // Clear the output buffer.
        buffer_sizes[1] = 0;

        // Push value to the input buffer.
        buffer_sizes[0] += 1;
        input_buffer[buffer_sizes[0] - 1] = *value;

        if (buffer_sizes[0] == RATE) {
            duplexing();
        }
    }

    __device__ __forceinline__ void observe_ext(kb31_extension_t* value) {
#pragma unroll
        for (size_t i = 0; i < kb31_extension_t::D; i++) {
            observe(&value->value[i]);
        }
    }

    __device__ __forceinline__ kb31_t sample() {
        kb31_t result;
        if (buffer_sizes[0] != 0 || buffer_sizes[1] == 0) {
            duplexing();
        }
        // Pop the last element of the buffer.
        result = output_buffer[buffer_sizes[1] - 1];
        buffer_sizes[1] -= 1;
        return result;
    }

    __device__ __forceinline__ kb31_extension_t sample_ext() {
        kb31_extension_t result;
        for (size_t i = 0; i < kb31_extension_t::D; i++) {
            result.value[i] = sample();
        }
        return result;
    }

    __device__ __forceinline__ size_t sample_bits(size_t bits) {
        kb31_t rand_f = sample();

        // Equivalent to "as_canonical_u32" in the Rust implementation.
        size_t rand_usize = rand_f.as_canonical_u32();
        return rand_usize & ((1 << bits) - 1);
    }

    __device__ __forceinline__ bool check_witness(size_t bits, kb31_t* witness) {
        observe(witness);
        return sample_bits(bits) == 0;
    }

    __device__ __forceinline__ void
    grind(size_t bits, kb31_t* result, volatile bool* found_flag, size_t n) {
        size_t idx = threadIdx.x + blockIdx.x * blockDim.x;

        size_t original_buffer_size = buffer_sizes[0];
        size_t original_output_buffer_size = buffer_sizes[1];
        __shared__ kb31_t challenger_state[NUM_ELEMENTS];

        if (threadIdx.x == 0) {
            for (size_t j = 0; j < WIDTH; j++) {
                challenger_state[j] = sponge_state[j];
            }
            for (size_t j = WIDTH; j < WIDTH + RATE; j++) {
                challenger_state[j] = input_buffer[j - WIDTH];
            }
            for (size_t j = WIDTH + RATE; j < NUM_ELEMENTS; j++) {
                challenger_state[j] = output_buffer[j - WIDTH - RATE];
            }
        }

        // Ensure all threads see the shared memory initialized
        __syncthreads();

        // Local copy of challenger state for each thread in each iteration.
        kb31_t local_state[NUM_ELEMENTS];
        size_t buffer_sizes[2];
        for (size_t i = idx; i < n && !*found_flag; i += blockDim.x * gridDim.x) {
            buffer_sizes[0] = original_buffer_size;
            buffer_sizes[1] = original_output_buffer_size;
            // Reset the local state to the shared state.
            for (size_t j = 0; j < NUM_ELEMENTS; j++) {
                local_state[j] = challenger_state[j];
            }
            DuplexChallenger temp_challenger = load(local_state, buffer_sizes);


            kb31_t witness = kb31_t((int)i);
            if (temp_challenger.check_witness(bits, &witness)) {
                result[0] = witness;
                atomicExch((int*)found_flag, 1);
                __threadfence();
                return;
            }
        }
    }
};

class MultiField32Challenger {
    static constexpr const int WIDTH = poseidon2_bn254_3::Bn254::WIDTH;
    static constexpr const int RATE = poseidon2_bn254_3::constants::RATE;

    bn254_t* sponge_state;
    kb31_t* input_buffer;
    size_t* buffer_sizes;
    kb31_t* output_buffer;

    __device__ void duplexing() {
        // Assert input size doesn't exceed RATE
        assert(buffer_sizes[3] == 4);
        assert(buffer_sizes[0] <= buffer_sizes[2] * RATE);

        // Copy input buffer elements to sponge state
        for (size_t i = 0; i < buffer_sizes[0]; i += buffer_sizes[2]) {
            size_t end = min(buffer_sizes[0], i + buffer_sizes[2]);
            bn254_t reduced =
                poseidon2_bn254_3::reduceKoalaBear(input_buffer + i, nullptr, end - i, 0);
            sponge_state[i / buffer_sizes[2]] = reduced;
        }

        // Clear input buffer.
        buffer_sizes[0] = 0;

        // Apply the permutation to the sponge state and store the output in the output buffer.
        poseidon2::Bn254Hasher hasher;

        bn254_t next_state[WIDTH];
        for (size_t i = 0; i < WIDTH; i++) {
            next_state[i].set_to_zero();
        }
        hasher.permute(sponge_state, next_state);

        // Copy the output buffer to the sponge state.
        buffer_sizes[1] = RATE * buffer_sizes[3];
        for (size_t i = 0; i < WIDTH; i++) {
            sponge_state[i] = next_state[i];
            bn254_t x = next_state[i];
            x.from();
            if (i < RATE) {
                uint32_t v0 =
                    (uint32_t)(((uint64_t)(x[0]) + (uint64_t(1) << 32) * (uint64_t)(x[1])) %
                               0x7f000001);
                uint32_t v1 =
                    (uint32_t)(((uint64_t)(x[2]) + (uint64_t(1) << 32) * (uint64_t)(x[3])) %
                               0x7f000001);
                uint32_t v2 =
                    (uint32_t)(((uint64_t)(x[4]) + (uint64_t(1) << 32) * (uint64_t)(x[5])) %
                               0x7f000001);
                uint32_t v3 =
                    (uint32_t)(((uint64_t)(x[6]) + (uint64_t(1) << 32) * (uint64_t)(x[7])) %
                               0x7f000001);
                output_buffer[i * 4] = kb31_t::from_canonical_u32(v0);
                output_buffer[i * 4 + 1] = kb31_t::from_canonical_u32(v1);
                output_buffer[i * 4 + 2] = kb31_t::from_canonical_u32(v2);
                output_buffer[i * 4 + 3] = kb31_t::from_canonical_u32(v3);
            }
        }
    }

  public:
    __device__ __forceinline__ void observe(kb31_t* value) {
        // Clear the output buffer.
        buffer_sizes[1] = 0;

        // Push value to the input buffer.
        buffer_sizes[0] += 1;
        input_buffer[buffer_sizes[0] - 1] = *value;

        if (buffer_sizes[0] == buffer_sizes[2] * RATE) {
            duplexing();
        }
    }

    __device__ __forceinline__ void observe_ext(kb31_extension_t* value) {
#pragma unroll
        for (size_t i = 0; i < kb31_extension_t::D; i++) {
            observe(&value->value[i]);
        }
    }

    __device__ __forceinline__ kb31_t sample() {
        kb31_t result;
        if (buffer_sizes[0] != 0 || buffer_sizes[1] == 0) {
            duplexing();
        }
        // Pop the last element of the buffer.
        result = output_buffer[buffer_sizes[1] - 1];
        buffer_sizes[1] -= 1;
        return result;
    }

    __device__ __forceinline__ kb31_extension_t sample_ext() {
        kb31_extension_t result;
        for (size_t i = 0; i < kb31_extension_t::D; i++) {
            result.value[i] = sample();
        }
        return result;
    }
};