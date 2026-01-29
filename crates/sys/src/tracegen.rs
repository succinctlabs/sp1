use crate::runtime::KernelPtr;

extern "C" {
    // RISC-V Global chip
    pub fn riscv_global_generate_trace_decompress_kernel() -> KernelPtr;
    pub fn riscv_global_generate_trace_finalize_kernel() -> KernelPtr;
    // RISC-V Add chip
    pub fn riscv_add_generate_trace_kernel() -> KernelPtr;
    // RISC-V Addi chip
    pub fn riscv_addi_generate_trace_kernel() -> KernelPtr;
    // RISC-V Addw chip
    pub fn riscv_addw_generate_trace_kernel() -> KernelPtr;
    // RISC-V Sub chip
    pub fn riscv_sub_generate_trace_kernel() -> KernelPtr;
    // RISC-V Subw chip
    pub fn riscv_subw_generate_trace_kernel() -> KernelPtr;
    // RISC-V Mul chip
    pub fn riscv_mul_generate_trace_kernel() -> KernelPtr;
    // RISC-V Lt chip
    pub fn riscv_lt_generate_trace_kernel() -> KernelPtr;
    // RISC-V Bitwise chip
    pub fn riscv_bitwise_generate_trace_kernel() -> KernelPtr;
    // RISC-V ShiftLeft chip
    pub fn riscv_shift_left_generate_trace_kernel() -> KernelPtr;
    // RISC-V ShiftRight chip
    pub fn riscv_shift_right_generate_trace_kernel() -> KernelPtr;
    // RISC-V LoadByte chip
    pub fn riscv_load_byte_generate_trace_kernel() -> KernelPtr;
    // RISC-V LoadHalf chip
    pub fn riscv_load_half_generate_trace_kernel() -> KernelPtr;
    // RISC-V LoadWord chip
    pub fn riscv_load_word_generate_trace_kernel() -> KernelPtr;
    // RISC-V LoadDouble chip
    pub fn riscv_load_double_generate_trace_kernel() -> KernelPtr;
    // RISC-V LoadX0 chip
    pub fn riscv_load_x0_generate_trace_kernel() -> KernelPtr;
    // RISC-V StoreByte chip
    pub fn riscv_store_byte_generate_trace_kernel() -> KernelPtr;
    // RISC-V StoreHalf chip
    pub fn riscv_store_half_generate_trace_kernel() -> KernelPtr;
    // RISC-V StoreWord chip
    pub fn riscv_store_word_generate_trace_kernel() -> KernelPtr;
    // RISC-V StoreDouble chip
    pub fn riscv_store_double_generate_trace_kernel() -> KernelPtr;
    // RISC-V UType chip
    pub fn riscv_utype_generate_trace_kernel() -> KernelPtr;
    // RISC-V Jal chip
    pub fn riscv_jal_generate_trace_kernel() -> KernelPtr;
    // RISC-V Jalr chip
    pub fn riscv_jalr_generate_trace_kernel() -> KernelPtr;
    // RISC-V Branch chip
    pub fn riscv_branch_generate_trace_kernel() -> KernelPtr;
    // RISC-V SyscallInstrs chip
    pub fn riscv_syscall_instrs_generate_trace_kernel() -> KernelPtr;
    // RISC-V Syscall chip (Core and Precompile)
    pub fn riscv_syscall_generate_trace_kernel() -> KernelPtr;
    // RISC-V ByteChip (lookup table)
    pub fn riscv_byte_lookup_generate_trace_kernel() -> KernelPtr;
    // RISC-V RangeChip (lookup table)
    pub fn riscv_range_lookup_generate_trace_kernel() -> KernelPtr;
    // RISC-V MemoryGlobalChip (Init and Finalize)
    pub fn riscv_memory_global_generate_trace_kernel() -> KernelPtr;
    // RISC-V MemoryLocalChip
    pub fn riscv_memory_local_generate_trace_kernel() -> KernelPtr;
    // RISC-V MemoryBumpChip
    pub fn riscv_memory_bump_generate_trace_kernel() -> KernelPtr;
    pub fn recursion_base_alu_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_base_alu_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_ext_alu_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_ext_alu_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_poseidon2_wide_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_poseidon2_wide_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_select_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_select_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_prefix_sum_checks_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_convert_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_convert_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_linear_layer_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_linear_layer_generate_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_sbox_generate_preprocessed_trace_koala_bear_kernel() -> KernelPtr;
    pub fn recursion_sbox_generate_trace_koala_bear_kernel() -> KernelPtr;
}
