#pragma once

#include <cstdint>

// Trace section a `PairCol` reads from; matches `PairColSource` in
// `crates/logup_gkr/src/interactions.rs`.
#define PAIR_COL_SOURCE_PREPROCESSED 0
#define PAIR_COL_SOURCE_GLOBAL 1
#define PAIR_COL_SOURCE_MAIN 2

template <typename F>
struct PairCol {
    size_t column_idx;
    uint8_t source;
    F weight;

  public:
    __device__ F get(F* preprocessed, F* global, F* main, size_t rowIdx, size_t height) {
        F* base;
        if (source == PAIR_COL_SOURCE_PREPROCESSED) {
            base = preprocessed;
        } else if (source == PAIR_COL_SOURCE_GLOBAL) {
            base = global;
        } else {
            base = main;
        }
        return base[column_idx * height + rowIdx] * weight;
    }
};

template <typename F>
struct Interactions {
    size_t* values_ptr;
    size_t* multiplicities_ptr;
    size_t* values_col_weights_ptr;

    PairCol<F>* values_col_weights;
    F* values_constants;

    PairCol<F>* mult_col_weights;
    F* mult_constants;

    F* arg_indices;
    bool* is_send;
    bool* is_global;

    size_t num_interactions;
};
