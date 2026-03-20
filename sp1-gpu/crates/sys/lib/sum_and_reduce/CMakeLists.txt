add_library(sum_and_reduce_objs OBJECT
    dot.cu
    reduce.cu
    reduction.cu
    sum.cu
)
target_link_libraries(sum_and_reduce_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(dot.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(reduce.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(reduction.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(sum.cu PROPERTIES LANGUAGE HIP)
endif()
