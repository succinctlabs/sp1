add_library(zerocheck_objs OBJECT
    jagged_mle.cu
    zerocheck.cu
    zerocheck_eval.cu
)
target_link_libraries(zerocheck_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(jagged_mle.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(zerocheck.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(zerocheck_eval.cu PROPERTIES LANGUAGE HIP)
endif()
