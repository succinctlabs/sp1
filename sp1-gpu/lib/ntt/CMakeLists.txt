add_library(ntt_objs OBJECT
    sppark.cu
)
target_link_libraries(ntt_objs PRIVATE sp1_gpu_common)
