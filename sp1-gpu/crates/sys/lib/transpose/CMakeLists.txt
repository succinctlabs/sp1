add_library(transpose_objs OBJECT
    transpose.cu
)
target_link_libraries(transpose_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(transpose.cu PROPERTIES LANGUAGE HIP)
endif()
