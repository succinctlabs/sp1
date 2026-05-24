add_library(zerocheck_objs OBJECT
    jagged_mle.cu
    sequential.cu
    column_tile.cu
    geq_corrections.cu
    aggregate.cu
    gkr_sweep.cu
)
target_link_libraries(zerocheck_objs PRIVATE sp1_gpu_common)
