add_library(basefold_objs OBJECT
    basefold.cu
)
target_link_libraries(basefold_objs PRIVATE sp1_gpu_common)
