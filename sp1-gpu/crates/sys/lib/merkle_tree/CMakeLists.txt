add_library(merkle_tree_objs OBJECT
    merkle_tree.cu
)
target_link_libraries(merkle_tree_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(merkle_tree.cu PROPERTIES LANGUAGE HIP)
endif()
