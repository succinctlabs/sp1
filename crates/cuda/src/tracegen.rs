use slop_koala_bear::KoalaBear;
use sp1_gpu_sys::runtime::KernelPtr;

use crate::TaskScope;

/// # Safety
pub unsafe trait TracegenRiscvAddKernel<F> {
    fn tracegen_riscv_add_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvAddKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_add_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_add_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvAddiKernel<F> {
    fn tracegen_riscv_addi_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvAddiKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_addi_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_addi_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvAddwKernel<F> {
    fn tracegen_riscv_addw_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvAddwKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_addw_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_addw_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvSubKernel<F> {
    fn tracegen_riscv_sub_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvSubKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_sub_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_sub_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvSubwKernel<F> {
    fn tracegen_riscv_subw_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvSubwKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_subw_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_subw_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvMulKernel<F> {
    fn tracegen_riscv_mul_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvMulKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_mul_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_mul_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvLtKernel<F> {
    fn tracegen_riscv_lt_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvLtKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_lt_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_lt_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvBitwiseKernel<F> {
    fn tracegen_riscv_bitwise_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvBitwiseKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_bitwise_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_bitwise_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvShiftLeftKernel<F> {
    fn tracegen_riscv_shift_left_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvShiftLeftKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_shift_left_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_shift_left_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvShiftRightKernel<F> {
    fn tracegen_riscv_shift_right_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvShiftRightKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_shift_right_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_shift_right_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvLoadByteKernel<F> {
    fn tracegen_riscv_load_byte_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvLoadByteKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_load_byte_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_load_byte_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvLoadHalfKernel<F> {
    fn tracegen_riscv_load_half_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvLoadHalfKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_load_half_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_load_half_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvLoadWordKernel<F> {
    fn tracegen_riscv_load_word_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvLoadWordKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_load_word_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_load_word_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvLoadDoubleKernel<F> {
    fn tracegen_riscv_load_double_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvLoadDoubleKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_load_double_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_load_double_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvLoadX0Kernel<F> {
    fn tracegen_riscv_load_x0_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvLoadX0Kernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_load_x0_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_load_x0_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvStoreByteKernel<F> {
    fn tracegen_riscv_store_byte_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvStoreByteKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_store_byte_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_store_byte_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvStoreHalfKernel<F> {
    fn tracegen_riscv_store_half_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvStoreHalfKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_store_half_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_store_half_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvStoreWordKernel<F> {
    fn tracegen_riscv_store_word_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvStoreWordKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_store_word_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_store_word_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvStoreDoubleKernel<F> {
    fn tracegen_riscv_store_double_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvStoreDoubleKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_store_double_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_store_double_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvJalKernel<F> {
    fn tracegen_riscv_jal_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvJalKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_jal_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_jal_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvJalrKernel<F> {
    fn tracegen_riscv_jalr_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvJalrKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_jalr_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_jalr_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvUTypeKernel<F> {
    fn tracegen_riscv_utype_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvUTypeKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_utype_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_utype_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvBranchKernel<F> {
    fn tracegen_riscv_branch_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvBranchKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_branch_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_branch_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvSyscallInstrsKernel<F> {
    fn tracegen_riscv_syscall_instrs_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvSyscallInstrsKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_syscall_instrs_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_syscall_instrs_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvSyscallKernel<F> {
    fn tracegen_riscv_syscall_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvSyscallKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_syscall_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_syscall_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvByteLookupKernel<F> {
    fn tracegen_riscv_byte_lookup_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvByteLookupKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_byte_lookup_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_byte_lookup_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvRangeLookupKernel<F> {
    fn tracegen_riscv_range_lookup_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvRangeLookupKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_range_lookup_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_range_lookup_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvMemoryGlobalKernel<F> {
    fn tracegen_riscv_memory_global_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvMemoryGlobalKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_memory_global_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_memory_global_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvMemoryLocalKernel<F> {
    fn tracegen_riscv_memory_local_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvMemoryLocalKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_memory_local_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_memory_local_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvMemoryBumpKernel<F> {
    fn tracegen_riscv_memory_bump_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvMemoryBumpKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_memory_bump_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_memory_bump_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvStateBumpKernel<F> {
    fn tracegen_riscv_state_bump_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvStateBumpKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_state_bump_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_state_bump_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvProgramPreprocessedKernel<F> {
    fn tracegen_riscv_program_preprocessed_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvProgramPreprocessedKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_program_preprocessed_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_program_generate_preprocessed_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvProgramKernel<F> {
    fn tracegen_riscv_program_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvProgramKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_program_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_program_generate_trace_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRiscvGlobalKernel<F> {
    fn tracegen_riscv_global_decompress_kernel() -> KernelPtr;
    fn tracegen_riscv_global_finalize_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvGlobalKernel<KoalaBear> for TaskScope {
    fn tracegen_riscv_global_decompress_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_global_generate_trace_decompress_kernel() }
    }
    fn tracegen_riscv_global_finalize_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::riscv_global_generate_trace_finalize_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionBaseAluKernel<F> {
    fn tracegen_preprocessed_recursion_base_alu_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionBaseAluKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_base_alu_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_base_alu_generate_preprocessed_trace_koala_bear_kernel(
            )
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionBaseAluKernel<F> {
    fn tracegen_recursion_base_alu_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionBaseAluKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_base_alu_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_base_alu_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionExtAluKernel<F> {
    fn tracegen_preprocessed_recursion_ext_alu_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionExtAluKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_ext_alu_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_ext_alu_generate_preprocessed_trace_koala_bear_kernel()
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionExtAluKernel<F> {
    fn tracegen_recursion_ext_alu_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionExtAluKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_ext_alu_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_ext_alu_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionPoseidon2WideKernel<F> {
    fn tracegen_preprocessed_recursion_poseidon2_wide_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionPoseidon2WideKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_poseidon2_wide_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_poseidon2_wide_generate_preprocessed_trace_koala_bear_kernel(
            )
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionPoseidon2WideKernel<F> {
    fn tracegen_recursion_poseidon2_wide_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionPoseidon2WideKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_poseidon2_wide_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_poseidon2_wide_generate_trace_koala_bear_kernel()
        }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionSelectKernel<F> {
    fn tracegen_preprocessed_recursion_select_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionSelectKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_select_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_select_generate_preprocessed_trace_koala_bear_kernel()
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionSelectKernel<F> {
    fn tracegen_recursion_select_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionSelectKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_select_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_select_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionPrefixSumChecksKernel<F> {
    fn tracegen_recursion_prefix_sum_checks_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionPrefixSumChecksKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_prefix_sum_checks_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_prefix_sum_checks_generate_trace_koala_bear_kernel()
        }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionConvertKernel<F> {
    fn tracegen_preprocessed_recursion_convert_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionConvertKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_convert_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_convert_generate_preprocessed_trace_koala_bear_kernel()
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionConvertKernel<F> {
    fn tracegen_recursion_convert_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionConvertKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_convert_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_convert_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionLinearLayerKernel<F> {
    fn tracegen_preprocessed_recursion_linear_layer_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionLinearLayerKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_linear_layer_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_linear_layer_generate_preprocessed_trace_koala_bear_kernel(
            )
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionLinearLayerKernel<F> {
    fn tracegen_recursion_linear_layer_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionLinearLayerKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_linear_layer_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_linear_layer_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionSBoxKernel<F> {
    fn tracegen_preprocessed_recursion_sbox_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionSBoxKernel<KoalaBear> for TaskScope {
    fn tracegen_preprocessed_recursion_sbox_kernel() -> KernelPtr {
        unsafe {
            sp1_gpu_sys::tracegen::recursion_sbox_generate_preprocessed_trace_koala_bear_kernel()
        }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionSBoxKernel<F> {
    fn tracegen_recursion_sbox_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionSBoxKernel<KoalaBear> for TaskScope {
    fn tracegen_recursion_sbox_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_sbox_generate_trace_koala_bear_kernel() }
    }
}
