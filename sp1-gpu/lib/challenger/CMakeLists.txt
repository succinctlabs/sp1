add_library(challenger_objs OBJECT
    challenger.cu
)
target_link_libraries(challenger_objs PRIVATE sp1_gpu_common)
