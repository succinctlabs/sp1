#pragma once
#include "config.cuh"

#include "config.cuh"

template <typename F>
struct DenseBuffer {
    using OutputDenseData = DenseBuffer<ext_t>;

  public:
    /// data
    F* data;

    __forceinline__ __device__ void fixLastVariable(
        DenseBuffer<ext_t>& other,
        size_t restrictedIdx,
        size_t zeroIdx,
        size_t oneIdx,
        ext_t alpha) const {

        F valuesZero = F::load(data, zeroIdx);
        F valuesOne = F::load(data, oneIdx);

        ext_t result = alpha * (valuesOne - valuesZero) + valuesZero;
        ext_t::store(other.data, restrictedIdx, result);
    }

    __forceinline__ __device__ void pad(DenseBuffer<ext_t>& other, size_t restrictedIdx) const {
        ext_t::store(other.data, restrictedIdx, ext_t::zero());
    }

    /// The composition of two `fixLastVariable` folds on one quadruple:
    ///   out1[k] = in[2k]  + alpha_1 · (in[2k+1] − in[2k])
    ///   out2[j] = out1[2j] + alpha_2 · (out1[2j+1] − out1[2j])
    /// evaluated on elements `baseIdx .. baseIdx+3`, without materializing
    /// the intermediate.
    __forceinline__ __device__ void fixLastTwoVariables(
        DenseBuffer<ext_t>& other,
        size_t restrictedIdx,
        size_t baseIdx,
        ext_t alpha_1,
        ext_t alpha_2) const {

        F v0 = F::load(data, baseIdx);
        F v1 = F::load(data, baseIdx + 1);
        F v2 = F::load(data, baseIdx + 2);
        F v3 = F::load(data, baseIdx + 3);

        ext_t lo = alpha_1 * (v1 - v0) + v0;
        ext_t hi = alpha_1 * (v3 - v2) + v2;
        ext_t result = alpha_2 * (hi - lo) + lo;
        ext_t::store(other.data, restrictedIdx, result);
    }

    __forceinline__ __device__ ext_t evaluate(uint32_t index, ext_t coef) const {
        return coef * data[index];
    }
};

struct InfoBuffer {
    using OutputDenseData = InfoBuffer;

  public:
    /// data
    uint64_t* data;

    __forceinline__ __device__ uint64_t fixLastVariable(
        InfoBuffer& other,
        size_t restrictedIdx,
        size_t zeroIdx
    ) const {
        uint64_t info = data[zeroIdx];
        other.data[restrictedIdx] = info;
        return info;
    }

    __forceinline__ __device__ void pad_const(InfoBuffer& other, size_t restrictedIdx, uint64_t value) const {
        other.data[restrictedIdx] = value;
    }
};

extern "C" void* initialize_jagged_info();
extern "C" void* fix_last_variable_jagged_felt();
extern "C" void* fix_last_variable_jagged_ext();
extern "C" void* fix_last_two_variables_jagged_felt();
extern "C" void* fix_last_variable_jagged_info();
extern "C" void* jagged_eval_kernel_chunked_felt();
extern "C" void* jagged_eval_kernel_chunked_ext();
