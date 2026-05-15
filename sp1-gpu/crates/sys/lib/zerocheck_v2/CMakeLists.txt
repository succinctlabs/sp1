add_library(zerocheck_v2_objs OBJECT
    sequential.cu
    column_tile.cu
)
target_link_libraries(zerocheck_v2_objs PRIVATE sp1_gpu_common)
