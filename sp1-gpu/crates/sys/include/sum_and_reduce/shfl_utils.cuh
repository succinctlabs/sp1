#pragma once

// Shuffle-down helper: reinterprets any type as an array of uint32_t and
// shuffles each 32-bit word independently. This works for kb31_t (1 word)
// and kb31_extension_t (4 words) without requiring type-specific overloads.
template <typename F>
__device__ __forceinline__ F shfl_down_field(F val, unsigned int offset) {
    static_assert(sizeof(F) % sizeof(uint32_t) == 0,
                  "Field type size must be a multiple of 4 bytes");
    constexpr int N = sizeof(F) / sizeof(uint32_t);
    uint32_t* words = reinterpret_cast<uint32_t*>(&val);
#pragma unroll
    for (int i = 0; i < N; i++) {
#ifdef __HIPCC__
        words[i] = __shfl_down(words[i], offset);
#else
        words[i] = __shfl_down_sync(0xFFFFFFFF, words[i], offset);
#endif
    }
    return val;
}

// Shuffle (broadcast) helper: shuffles any type word-by-word.
template <typename F>
__device__ __forceinline__ F shfl_field(F val, int srcLane, int width = 0) {
    static_assert(sizeof(F) % sizeof(uint32_t) == 0,
                  "Field type size must be a multiple of 4 bytes");
    constexpr int N = sizeof(F) / sizeof(uint32_t);
    uint32_t* words = reinterpret_cast<uint32_t*>(&val);
#pragma unroll
    for (int i = 0; i < N; i++) {
#ifdef __HIPCC__
        if (width > 0)
            words[i] = __shfl(words[i], srcLane, width);
        else
            words[i] = __shfl(words[i], srcLane);
#else
        words[i] = __shfl_sync(0xFFFFFFFF, words[i], srcLane);
#endif
    }
    return val;
}
