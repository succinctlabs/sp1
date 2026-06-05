add_library(eq_product_sumcheck_objs OBJECT
    eq_product_sumcheck.cu
)
target_link_libraries(eq_product_sumcheck_objs PRIVATE sp1_gpu_common)
