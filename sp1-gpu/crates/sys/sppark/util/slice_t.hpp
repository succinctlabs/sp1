// Copyright Supranational LLC
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef __SPPARK_UTIL_SLICE_T_HPP__
#define __SPPARK_UTIL_SLICE_T_HPP__

#include <vector>

#ifdef __CUDACC__
# ifdef inline
#  define slice_t_saved_inline inline
#  undef inline
# endif
# define inline inline __host__ __device__
#endif

// A simple way to pack a constant pointer and array's size length,
// and to "borrow" std::vector<T>&...
template<typename T> class slice_t {
    const T* ptr;
    size_t nelems;
public:
    slice_t() : ptr(nullptr), nelems(0)                                 {}
    slice_t(void* p, size_t n) : ptr(reinterpret_cast<T*>(p)), nelems(n){}
    slice_t(const T* p, size_t n) : ptr(p), nelems(n)                   {}
    slice_t(const std::vector<T>& v) : ptr(v.data()), nelems(v.size())  {}

    inline operator void*() const               { return (void*)ptr; }
    inline operator decltype(ptr)() const       { return ptr; }
    inline const T* data() const                { return ptr; }
    inline size_t size() const                  { return nelems; }
    inline const T& operator[](size_t i) const  { return ptr[i]; }
};

#ifdef __CUDACC__
# undef inline
# ifdef slice_t_saved_inline
#  define inline slice_t_saved_inline
# endif
#endif

#endif
