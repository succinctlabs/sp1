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

    __forceinline__ __device__ ext_t evaluate(uint32_t index, ext_t coef) const {
        return coef * data[index];
    }
};

struct InfoBuffer {
    using OutputDenseData = InfoBuffer;

  public:
    /// data
    uint32_t* data;
    
    __forceinline__ __device__ uint32_t fixLastVariable(
        InfoBuffer& other,
        size_t restrictedIdx,
        size_t zeroIdx
    ) const {
        uint32_t info = data[zeroIdx];
        other.data[restrictedIdx] = info;
        return info;
    }

    __forceinline__ __device__ void pad_const(InfoBuffer& other, size_t restrictedIdx, uint32_t value) const {
        other.data[restrictedIdx] = value;
    }
};

extern "C" void* initialize_jagged_info();
extern "C" void* fix_last_variable_jagged_felt();
extern "C" void* fix_last_variable_jagged_ext();
extern "C" void* fix_last_variable_jagged_info();
extern "C" void* jagged_eval_kernel_chunked_felt();
extern "C" void* jagged_eval_kernel_chunked_ext();
