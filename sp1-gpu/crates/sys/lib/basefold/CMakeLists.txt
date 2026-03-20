add_library(basefold_objs OBJECT
    basefold.cu
)
target_link_libraries(basefold_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(basefold.cu PROPERTIES LANGUAGE HIP)
endif()
