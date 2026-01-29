use sp1_gpu_sys::runtime::KernelPtr;
use sp1_primitives::SP1Field;

use crate::TaskScope;

/// # Safety
pub unsafe trait TracegenRiscvGlobalKernel<F> {
    fn tracegen_riscv_global_decompress_kernel() -> KernelPtr;
    fn tracegen_riscv_global_finalize_kernel() -> KernelPtr;
}

unsafe impl TracegenRiscvGlobalKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenPreprocessedRecursionBaseAluKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionBaseAluKernel<SP1Field> for TaskScope {
    fn tracegen_recursion_base_alu_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_base_alu_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionExtAluKernel<F> {
    fn tracegen_preprocessed_recursion_ext_alu_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionExtAluKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionExtAluKernel<SP1Field> for TaskScope {
    fn tracegen_recursion_ext_alu_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_ext_alu_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionPoseidon2WideKernel<F> {
    fn tracegen_preprocessed_recursion_poseidon2_wide_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionPoseidon2WideKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionPoseidon2WideKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenPreprocessedRecursionSelectKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionSelectKernel<SP1Field> for TaskScope {
    fn tracegen_recursion_select_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_select_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenRecursionPrefixSumChecksKernel<F> {
    fn tracegen_recursion_prefix_sum_checks_kernel() -> KernelPtr;
}

unsafe impl TracegenRecursionPrefixSumChecksKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenPreprocessedRecursionConvertKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionConvertKernel<SP1Field> for TaskScope {
    fn tracegen_recursion_convert_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_convert_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionLinearLayerKernel<F> {
    fn tracegen_preprocessed_recursion_linear_layer_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionLinearLayerKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionLinearLayerKernel<SP1Field> for TaskScope {
    fn tracegen_recursion_linear_layer_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_linear_layer_generate_trace_koala_bear_kernel() }
    }
}

/// # Safety
pub unsafe trait TracegenPreprocessedRecursionSBoxKernel<F> {
    fn tracegen_preprocessed_recursion_sbox_kernel() -> KernelPtr;
}

unsafe impl TracegenPreprocessedRecursionSBoxKernel<SP1Field> for TaskScope {
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

unsafe impl TracegenRecursionSBoxKernel<SP1Field> for TaskScope {
    fn tracegen_recursion_sbox_kernel() -> KernelPtr {
        unsafe { sp1_gpu_sys::tracegen::recursion_sbox_generate_trace_koala_bear_kernel() }
    }
}
