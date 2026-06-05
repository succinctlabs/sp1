add_library(jagged_assist_objs OBJECT
    branching_program.cu
    bit_decompose_prefix_sums.cu
)
target_link_libraries(jagged_assist_objs PRIVATE sp1_gpu_common)
