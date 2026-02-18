#include "gpu_t.cuh"

class gpus_t {
    std::vector<const gpu_t*> gpus;
public:
    gpus_t()
    {
        int n;
        if (cudaGetDeviceCount(&n) != cudaSuccess)
            return;
        for (int id = 0; id < n; id++) {
            cudaDeviceProp prop;
            if (cudaGetDeviceProperties(&prop, id) == cudaSuccess &&
                prop.major >= 7) {
                cudaSetDevice(id);
                gpus.push_back(new gpu_t(gpus.size(), id, prop));
            }
        }
        cudaSetDevice(0);
    }
    ~gpus_t()
    {   for (auto* ptr: gpus) delete ptr;   }

    static const auto& all()
    {
        static gpus_t all_gpus;
        return all_gpus.gpus;
    }
};

const gpu_t& select_gpu(int id)
{
    auto& gpus = gpus_t::all();
    if (id == -1) {
        int cuda_id;
        CUDA_UNWRAP_SPPARK(cudaGetDevice(&cuda_id));
        for (auto* gpu: gpus)
           if (gpu->cid() == cuda_id) return *gpu;
        id = 0;
    }
    auto* gpu = gpus[id];
    gpu->select();
    return *gpu;
}

const cudaDeviceProp& gpu_props(int id)
{   return gpus_t::all()[id]->props();   }

size_t ngpus()
{   return gpus_t::all().size();   }

const std::vector<const gpu_t*>& all_gpus()
{   return gpus_t::all();   }

extern "C" bool cuda_available()
{   return gpus_t::all().size() != 0;   }
