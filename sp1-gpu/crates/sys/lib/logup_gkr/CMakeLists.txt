add_library(logup_gkr_objs OBJECT
    execution.cu
    first_layer.cu
    round.cu
    tracegen.cu
)
target_link_libraries(logup_gkr_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(execution.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(first_layer.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(round.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(tracegen.cu PROPERTIES LANGUAGE HIP)
endif()
