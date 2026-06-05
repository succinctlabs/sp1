add_library(product_sumcheck_objs OBJECT
    product_sumcheck.cu
)
target_link_libraries(product_sumcheck_objs PRIVATE sp1_gpu_common)
