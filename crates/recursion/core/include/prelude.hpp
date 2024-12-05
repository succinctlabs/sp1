#pragma once

#include "sp1-recursion-core-sys-cbindgen.hpp"

#ifndef __CUDACC__
#define __SP1_HOSTDEV__
#define __SP1_INLINE__ inline
#include <array>

namespace sp1_recursion_core_sys {
template <class T, std::size_t N>
using array_t = std::array<T, N>;
}  // namespace sp1_recursion_core_sys
#else
#define __SP1_HOSTDEV__ __host__ __device__
#define __SP1_INLINE__ __forceinline__
#include <cuda/std/array>

namespace sp1_recursion_core_sys {
template <class T, std::size_t N>
using array_t = cuda::std::array<T, N>;
}  // namespace sp1_recursion_core_sys
#endif
