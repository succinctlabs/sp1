use crate::runtime::KernelPtr;

extern "C" {
    pub fn partial_lagrange_koala_bear() -> KernelPtr;
    pub fn partial_lagrange_koala_bear_extension() -> KernelPtr;

    pub fn mle_fold_koala_bear_base_base() -> KernelPtr;
    pub fn mle_fold_koala_bear_base_extension() -> KernelPtr;
    pub fn mle_fold_koala_bear_ext_ext() -> KernelPtr;

    pub fn mle_fix_last_variable_in_place_koala_bear_base() -> KernelPtr;
    pub fn mle_fix_last_variable_in_place_koala_bear_extension() -> KernelPtr;

    pub fn partial_geq_koala_bear() -> KernelPtr;
}
