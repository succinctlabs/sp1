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
