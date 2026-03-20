add_library(mle_objs OBJECT
    fixlastvariable.cu
    mle.cu
)
target_link_libraries(mle_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(fixlastvariable.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(mle.cu PROPERTIES LANGUAGE HIP)
endif()
