// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef __SPPARK_UTIL_VEC2D_T_HPP__
#define __SPPARK_UTIL_VEC2D_T_HPP__

#include <cstdint>

#ifndef __CUDACC__
# define __host__
# define __device__
#endif

template<typename T, typename dim_t = uint32_t> class vec2d_t {
    dim_t dim_x;
    bool owned;
    T* ptr;

public:
    __host__ __device__
    vec2d_t(T* data, dim_t x)  : dim_x(x), owned(false), ptr(data) {}
    vec2d_t(void* data, dim_t x)  : dim_x(x), owned(false), ptr((T*)data) {}
    vec2d_t(dim_t x, size_t y) : dim_x(x), owned(true),  ptr(new T[x*y]) {}
    vec2d_t() : dim_x(0), owned(false), ptr(nullptr) {}
#ifndef __CUDA_ARCH__
    vec2d_t(const vec2d_t& other) { *this = other; owned = false; }
    ~vec2d_t() { if (owned) delete[] ptr; }

    inline vec2d_t& operator=(const vec2d_t& other)
    {
        if (this == &other)
            return *this;

        dim_x = other.dim_x;
        owned = false;
        ptr   = other.ptr;

        return *this;
    }
#endif
    inline operator void*() { return ptr; }
    __host__ __device__
    inline T* operator[](size_t y) const { return ptr + dim_x*y; }

#ifndef NDEBUG
    inline dim_t x() { return dim_x; }
#endif
};

#ifndef __CUDACC__
# undef __device__
# undef __host__
#endif

#endif
