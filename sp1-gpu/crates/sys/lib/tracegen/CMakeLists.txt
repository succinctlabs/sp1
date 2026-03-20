add_library(tracegen_objs OBJECT
    jagged_tracegen/tracegen.cu
    recursion/alu_base.cu
    recursion/alu_ext.cu
    recursion/convert.cu
    recursion/linear_layer.cu
    recursion/poseidon2_wide.cu
    recursion/prefix_sum_checks.cu
    recursion/sbox.cu
    recursion/select.cu
    riscv/global.cu
)
target_link_libraries(tracegen_objs PRIVATE sp1_gpu_common)

if(USE_HIP)
    set_source_files_properties(jagged_tracegen/tracegen.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/alu_base.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/alu_ext.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/convert.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/linear_layer.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/poseidon2_wide.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/prefix_sum_checks.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/sbox.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(recursion/select.cu PROPERTIES LANGUAGE HIP)
    set_source_files_properties(riscv/global.cu PROPERTIES LANGUAGE HIP)
endif()
