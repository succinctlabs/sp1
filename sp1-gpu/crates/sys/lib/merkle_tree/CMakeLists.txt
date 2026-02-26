add_library(merkle_tree_objs OBJECT
    merkle_tree.cu
)
target_link_libraries(merkle_tree_objs PRIVATE sp1_gpu_common)
