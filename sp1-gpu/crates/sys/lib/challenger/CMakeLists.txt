add_library(challenger_objs OBJECT
    challenger.cu
)
target_link_libraries(challenger_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(challenger.cu PROPERTIES LANGUAGE HIP)
endif()
