add_library(jagged_assist_objs OBJECT
    branching_program.cu
)
target_link_libraries(jagged_assist_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(branching_program.cu PROPERTIES LANGUAGE HIP)
endif()
