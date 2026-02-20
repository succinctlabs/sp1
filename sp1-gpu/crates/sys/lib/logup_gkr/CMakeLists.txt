add_library(logup_gkr_objs OBJECT
    execution.cu
    first_layer.cu
    round.cu
    tracegen.cu
)
target_link_libraries(logup_gkr_objs PRIVATE sp1_gpu_common)
