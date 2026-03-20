add_library(jagged_sumcheck_objs OBJECT
    hadamard.cu
    jagged_sumcheck.cu
)
target_link_libraries(jagged_sumcheck_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(hadamard.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(jagged_sumcheck.cu PROPERTIES LANGUAGE HIP)
endif()
