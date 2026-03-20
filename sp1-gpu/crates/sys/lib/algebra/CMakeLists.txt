add_library(algebra_objs OBJECT
    algebra.cu
)
target_link_libraries(algebra_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(algebra.cu PROPERTIES LANGUAGE HIP)
endif()
