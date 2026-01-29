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
