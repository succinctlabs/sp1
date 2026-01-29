use crate::runtime::KernelPtr;

extern "C" {
    pub fn interpolate_row_koala_bear_kernel() -> KernelPtr;
    pub fn interpolate_row_koala_bear_extension_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_32_koala_bear_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_64_koala_bear_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_128_koala_bear_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_256_koala_bear_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_512_koala_bear_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_1024_koala_bear_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_32_koala_bear_extension_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_64_koala_bear_extension_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_128_koala_bear_extension_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_256_koala_bear_extension_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_512_koala_bear_extension_kernel() -> KernelPtr;
    pub fn constraint_poly_eval_1024_koala_bear_extension_kernel() -> KernelPtr;
}
