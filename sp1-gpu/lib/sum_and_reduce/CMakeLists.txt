add_library(sum_and_reduce_objs OBJECT
    dot.cu
    reduce.cu
    reduction.cu
    sum.cu
)
target_link_libraries(sum_and_reduce_objs PRIVATE sp1_gpu_common)
