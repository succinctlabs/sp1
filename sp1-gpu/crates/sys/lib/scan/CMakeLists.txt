add_library(scan_objs OBJECT
    scan.cu
)
target_link_libraries(scan_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(scan.cu PROPERTIES LANGUAGE HIP)
endif()
