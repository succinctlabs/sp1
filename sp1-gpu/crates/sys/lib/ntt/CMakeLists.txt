add_library(ntt_objs OBJECT
    sppark.cu
)
target_link_libraries(ntt_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(sppark.cu PROPERTIES LANGUAGE HIP)
endif()
