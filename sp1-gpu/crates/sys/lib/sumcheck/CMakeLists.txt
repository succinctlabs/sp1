add_library(sumcheck_objs OBJECT
    observe_and_sample.cu
)
target_link_libraries(sumcheck_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(observe_and_sample.cu PROPERTIES LANGUAGE HIP)
endif()
