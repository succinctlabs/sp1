#include <cuda_runtime.h>
#include <util/gpu_t.cuh>

extern "C" void drop_gpu_ptr_t(gpu_ptr_t<void>& ref)
{   ref.~gpu_ptr_t();   }

#ifdef __clang__
# pragma clang diagnostic push
# pragma clang diagnostic ignored "-Wreturn-type-c-linkage"
#endif

extern "C" gpu_ptr_t<void>::by_value clone_gpu_ptr_t(const gpu_ptr_t<void>& rhs)
{   return rhs;   }

#ifdef __clang__
# pragma clang diagnostic pop
#endif
