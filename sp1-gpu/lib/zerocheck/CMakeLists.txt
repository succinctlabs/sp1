add_library(zerocheck_objs OBJECT
    jagged_mle.cu
    zerocheck.cu
    zerocheck_eval.cu
)
target_link_libraries(zerocheck_objs PRIVATE sp1_gpu_common)
