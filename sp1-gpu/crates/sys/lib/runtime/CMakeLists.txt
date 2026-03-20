add_library(runtime_objs OBJECT
    exception.cu
    mem_pool.cu
    memory.cu
    stream.cu
)
target_link_libraries(runtime_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(exception.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(mem_pool.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(memory.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(stream.cu PROPERTIES LANGUAGE HIP)
endif()
