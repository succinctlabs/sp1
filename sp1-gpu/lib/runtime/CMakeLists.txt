add_library(runtime_objs OBJECT
    exception.cu
    mem_pool.cu
    memory.cu
    stream.cu
)
target_link_libraries(runtime_objs PRIVATE sp1_gpu_common)
