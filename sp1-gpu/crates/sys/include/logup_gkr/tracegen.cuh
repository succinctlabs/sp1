#pragma once

template <typename F>
struct PairCol {
    size_t column_idx;
    bool is_preprocessed;
    F weight;

  public:
    __device__ F get(F* preprocessed, F* main, size_t rowIdx, size_t height) {
        if (is_preprocessed) {
            return preprocessed[column_idx * height + rowIdx] * weight;
        } else {
            return main[column_idx * height + rowIdx] * weight;
        }
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

    size_t num_interactions;
};