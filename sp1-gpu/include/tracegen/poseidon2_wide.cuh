#pragma once

#include "sp1-gpu-cbindgen.hpp"

#include "fields/kb31_t.cuh"

#include "poseidon2/poseidon2_kb31_16.cuh"

namespace poseidon2_wide
{
    using namespace poseidon2_kb31_16::constants;

    constexpr static const uintptr_t NUM_EXTERNAL_ROUNDS = poseidon2_kb31_16::constants::ROUNDS_F;
    constexpr static const uintptr_t NUM_INTERNAL_ROUNDS = poseidon2_kb31_16::constants::ROUNDS_P;

    __constant__ constexpr const uint32_t RC_16_30_U32[28][16] = {
        {
            0x7ee56a48U,
            0x11367045U,
            0x12e41941U,
            0x7ebbc12bU,
            0x1970b7d5U,
            0x662b60e8U,
            0x3e4990c6U,
            0x679f91f5U,
            0x350813bbU,
            0x00874ad4U,
            0x28a0081aU,
            0x18fa5872U,
            0x5f25b071U,
            0x5e5d5998U,
            0x5e6fd3e7U,
            0x5b2e2660U,
        },
        {
            0x6f1837bfU,
            0x3fe6182bU,
            0x1edd7ac5U,
            0x57470d00U,
            0x43d486d5U,
            0x1982c70fU,
            0x0ea53af9U,
            0x61d6165bU,
            0x51639c00U,
            0x2dec352cU,
            0x2950e531U,
            0x2d2cb947U,
            0x08256cefU,
            0x1a0109f6U,
            0x1f51faf3U,
            0x5cef1c62U,
        },
        {
            0x3d65e50eU,
            0x33d91626U,
            0x133d5a1eU,
            0x0ff49b0dU,
            0x38900cd1U,
            0x2c22cc3fU,
            0x28852bb2U,
            0x06c65a02U,
            0x7b2cf7bcU,
            0x68016e1aU,
            0x15e16bc0U,
            0x5248149aU,
            0x6dd212a0U,
            0x18d6830aU,
            0x5001be82U,
            0x64dac34eU,
        },
        {
            0x5902b287U,
            0x426583a0U,
            0x0c921632U,
            0x3fe028a5U,
            0x245f8e49U,
            0x43bb297eU,
            0x7873dbd9U,
            0x3cc987dfU,
            0x286bb4ceU,
            0x640a8dcdU,
            0x512a8e36U,
            0x03a4cf55U,
            0x481837a2U,
            0x03d6da84U,
            0x73726ac7U,
            0x760e7fdfU,
        },
        {
            0x54dfeb5dU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x7d40afd6U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x722cb316U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x106a4573U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x45a7ccdbU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x44061375U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x154077a5U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x45744faaU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x4eb5e5eeU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x3794e83fU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x47c7093cU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x5694903cU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x69cb6299U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x373df84cU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x46a0df58U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x46b8758aU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x3241ebcbU,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x0b09d233U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x1af42357U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x1e66cec2U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
            0x00000000U,
        },
        {
            0x43e7dc24U,
            0x259a5d61U,
            0x27e85a3bU,
            0x1b9133faU,
            0x343e5628U,
            0x485cd4c2U,
            0x16e269f5U,
            0x165b60c6U,
            0x25f683d9U,
            0x124f81f9U,
            0x174331f9U,
            0x77344dc5U,
            0x5a821dbaU,
            0x5fc4177fU,
            0x54153bf5U,
            0x5e3f1194U,
        },
        {
            0x3bdbf191U,
            0x088c84a3U,
            0x68256c9bU,
            0x3c90bbc6U,
            0x6846166aU,
            0x03f4238dU,
            0x463335fbU,
            0x5e3d3551U,
            0x6e59ae6fU,
            0x32d06cc0U,
            0x596293f3U,
            0x6c87edb2U,
            0x08fc60b5U,
            0x34bcca80U,
            0x24f007f3U,
            0x62731c6fU,
        },
        {
            0x1e1db6c6U,
            0x0ca409bbU,
            0x585c1e78U,
            0x56e94edcU,
            0x16d22734U,
            0x18e11467U,
            0x7b2c3730U,
            0x770075e4U,
            0x35d1b18cU,
            0x22be3db5U,
            0x4fb1fbb7U,
            0x477cb3edU,
            0x7d5311c6U,
            0x5b62ae7dU,
            0x559c5fa8U,
            0x77f15048U,
        },
        {
            0x3211570bU,
            0x490fef6aU,
            0x77ec311fU,
            0x2247171bU,
            0x4e0ac711U,
            0x2edf69c9U,
            0x3b5a8850U,
            0x65809421U,
            0x5619b4aaU,
            0x362019a7U,
            0x6bf9d4edU,
            0x5b413dffU,
            0x617e181eU,
            0x5e7ab57bU,
            0x33ad7833U,
            0x3466c7caU,
        },
    };

    __constant__ constexpr const kb31_t
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY[16] = {
            kb31_t(kb31_t::to_monty(0x7f000001u - 2)), // KoalaBear::ORDER_U32 - 2
            kb31_t(kb31_t::to_monty(1)),               // 1
            kb31_t(kb31_t::to_monty(1 << 1)),          // 1 << 1
            kb31_t(kb31_t::to_monty(1 << 2)),          // 1 << 2
            kb31_t(kb31_t::to_monty(1 << 3)),          // 1 << 3
            kb31_t(kb31_t::to_monty(1 << 4)),          // 1 << 4
            kb31_t(kb31_t::to_monty(1 << 5)),          // 1 << 5
            kb31_t(kb31_t::to_monty(1 << 6)),          // 1 << 6
            kb31_t(kb31_t::to_monty(1 << 7)),          // 1 << 7
            kb31_t(kb31_t::to_monty(1 << 8)),          // 1 << 8
            kb31_t(kb31_t::to_monty(1 << 9)),          // 1 << 9
            kb31_t(kb31_t::to_monty(1 << 10)),         // 1 << 10
            kb31_t(kb31_t::to_monty(1 << 11)),         // 1 << 11
            kb31_t(kb31_t::to_monty(1 << 12)),         // 1 << 12
            kb31_t(kb31_t::to_monty(1 << 13)),         // 1 << 13
            kb31_t(kb31_t::to_monty(1 << 15)),         // 1 << 15
    };

    __device__ __forceinline__ void populate_external_round(
        const kb31_t external_rounds_state[WIDTH * NUM_EXTERNAL_ROUNDS],
        size_t r, kb31_t next_state[WIDTH])
    {
        kb31_t round_state[WIDTH];
        if (r == 0)
        {
            // external_linear_layer_immut
            kb31_t temp_round_state[WIDTH];
            for (size_t i = 0; i < WIDTH; i++)
            {
                temp_round_state[i] = external_rounds_state[r * WIDTH + i];
            }
            poseidon2_kb31_16::KoalaBear::externalLinearLayer(temp_round_state);
            for (size_t i = 0; i < WIDTH; i++)
            {
                round_state[i] = temp_round_state[i];
            }
        }
        else
        {
            for (size_t i = 0; i < WIDTH; i++)
            {
                round_state[i] = external_rounds_state[r * WIDTH + i];
            }
        }

        size_t round = r < NUM_EXTERNAL_ROUNDS / 2 ? r : r + NUM_INTERNAL_ROUNDS;
        kb31_t add_rc[WIDTH];
        for (size_t i = 0; i < WIDTH; i++)
        {
            add_rc[i] = round_state[i] + kb31_t(kb31_t::to_monty(RC_16_30_U32[round][i]));
        }

        kb31_t sbox_deg_3[WIDTH];
        for (size_t i = 0; i < WIDTH; i++)
        {
            sbox_deg_3[i] = add_rc[i] * add_rc[i] * add_rc[i];
            // sbox_deg_7[i] = sbox_deg_3[i] * sbox_deg_3[i] * add_rc[i];
        }

        for (size_t i = 0; i < WIDTH; i++)
        {
            next_state[i] = sbox_deg_3[i];
        }
        poseidon2_kb31_16::KoalaBear::externalLinearLayer(next_state);
    }

    __device__ __forceinline__ void populate_internal_rounds(
        const kb31_t internal_rounds_state[WIDTH],
        kb31_t internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1], 
        kb31_t ret_state[WIDTH])
    {
        kb31_t state[WIDTH];
        for (size_t i = 0; i < WIDTH; i++)
        {
            state[i] = internal_rounds_state[i];
        }

        kb31_t sbox_deg_3[NUM_INTERNAL_ROUNDS];
        for (size_t r = 0; r < NUM_INTERNAL_ROUNDS; r++)
        {
            size_t round = r + NUM_EXTERNAL_ROUNDS / 2;
            kb31_t add_rc = state[0] + kb31_t(kb31_t::to_monty(RC_16_30_U32[round][0]));

            sbox_deg_3[r] = add_rc * add_rc * add_rc;
            // kb31_t sbox_deg_7 = sbox_deg_3[r] * sbox_deg_3[r] * add_rc;

            state[0] = sbox_deg_3[r];
            poseidon2_kb31_16::KoalaBear::internalLinearLayer(state, MAT_INTERNAL_DIAG_M1, MONTY_INVERSE);

            if (r < NUM_INTERNAL_ROUNDS - 1)
            {
                internal_rounds_s0[r] = state[0];
            }
        }

        for (size_t i = 0; i < WIDTH; i++)
        {
            ret_state[i] = state[i];
        }
    }

    __device__ __forceinline__ void populate_perm(
        const kb31_t input[WIDTH], kb31_t external_rounds_state[WIDTH * NUM_EXTERNAL_ROUNDS],
        kb31_t internal_rounds_state[WIDTH],
        kb31_t internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1],
        // kb31_t external_sbox[WIDTH * NUM_EXTERNAL_ROUNDS],
        kb31_t output_state[WIDTH])
    {
        for (size_t i = 0; i < WIDTH; i++)
        {
            external_rounds_state[i] = input[i];
        }

        for (size_t r = 0; r < NUM_EXTERNAL_ROUNDS / 2; r++)
        {
            kb31_t next_state[WIDTH];
            populate_external_round(external_rounds_state, r,
                                    next_state);
            if (r == NUM_EXTERNAL_ROUNDS / 2 - 1)
            {
                for (size_t i = 0; i < WIDTH; i++)
                {
                    internal_rounds_state[i] = next_state[i];
                }
            }
            else
            {
                for (size_t i = 0; i < WIDTH; i++)
                {
                    external_rounds_state[(r + 1) * WIDTH + i] = next_state[i];
                }
            }
        }

        kb31_t ret_state[WIDTH];
        populate_internal_rounds(internal_rounds_state, internal_rounds_s0,
                                  ret_state);
        size_t row = NUM_EXTERNAL_ROUNDS / 2;
        for (size_t i = 0; i < WIDTH; i++)
        {
            external_rounds_state[row * WIDTH + i] = ret_state[i];
        }

        for (size_t r = NUM_EXTERNAL_ROUNDS / 2; r < NUM_EXTERNAL_ROUNDS; r++)
        {
            kb31_t next_state[WIDTH];
            populate_external_round(external_rounds_state,  r,
                                    next_state);
            if (r == NUM_EXTERNAL_ROUNDS - 1)
            {
                for (size_t i = 0; i < WIDTH; i++)
                {
                    output_state[i] = next_state[i];
                }
            }
            else
            {
                for (size_t i = 0; i < WIDTH; i++)
                {
                    external_rounds_state[(r + 1) * WIDTH + i] = next_state[i];
                }
            }
        }
    }

    __device__ __forceinline__ void event_to_row(const kb31_t input[WIDTH], kb31_t *input_row,
                                 size_t start, size_t stride
                                 )
    {
        kb31_t external_rounds_state[WIDTH * NUM_EXTERNAL_ROUNDS];
        kb31_t internal_rounds_state[WIDTH];
        kb31_t internal_rounds_s0[NUM_INTERNAL_ROUNDS - 1];
        kb31_t output_state[WIDTH];
        // kb31_t external_sbox[WIDTH * NUM_EXTERNAL_ROUNDS];
        // kb31_t internal_sbox[NUM_INTERNAL_ROUNDS];

        populate_perm(input, external_rounds_state, internal_rounds_state,
                      internal_rounds_s0, 
                      output_state);

        size_t cursor = 0;
        for (size_t i = 0; i < (WIDTH * NUM_EXTERNAL_ROUNDS); i++)
        {
            input_row[start + (cursor + i) * stride] = external_rounds_state[i];
        }

        cursor += WIDTH * NUM_EXTERNAL_ROUNDS;
        for (size_t i = 0; i < WIDTH; i++)
        {
            input_row[start + (cursor + i) * stride] = internal_rounds_state[i];
        }

        cursor += WIDTH;
        for (size_t i = 0; i < (NUM_INTERNAL_ROUNDS - 1); i++)
        {
            input_row[start + (cursor + i) * stride] = internal_rounds_s0[i];
        }

        cursor += NUM_INTERNAL_ROUNDS - 1;
        for (size_t i = 0; i < WIDTH; i++)
        {
            input_row[start + (cursor + i) * stride] = output_state[i];
        }
    }

} // namespace poseidon2_wide