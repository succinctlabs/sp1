use crate::runtime::KernelPtr;

extern "C" {
    pub fn hadamard_univariate_poly_eval_koala_bear_base_ext_kernel() -> KernelPtr;
    pub fn hadamard_univariate_poly_eval_koala_bear_base_kernel() -> KernelPtr;
    pub fn hadamard_univariate_poly_eval_koala_bear_ext_kernel() -> KernelPtr;
}
