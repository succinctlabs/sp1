add_library(mle_objs OBJECT
    fixlastvariable.cu
    mle.cu
)
target_link_libraries(mle_objs PRIVATE sp1_gpu_common)
