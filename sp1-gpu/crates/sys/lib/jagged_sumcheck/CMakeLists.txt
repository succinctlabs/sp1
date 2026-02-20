add_library(jagged_sumcheck_objs OBJECT
    hadamard.cu
    jagged_sumcheck.cu
)
target_link_libraries(jagged_sumcheck_objs PRIVATE sp1_gpu_common)
