use crate::runtime::KernelPtr;

// #[link_name = "logup_gkr"]
// #[allow(unused_attributes)]
// extern "C" {
//     pub fn gkr_circuit_transition_koala_bear_kernel() -> KernelPtr;
//     pub fn gkr_circuit_transition_koala_bear_extension_kernel() -> KernelPtr;
// }

// #[link_name = "logup_gkr_sum"]
// #[allow(unused_attributes)]
// extern "C" {
//     pub fn logup_gkr_poly_koala_bear_kernel() -> KernelPtr;
//     pub fn logup_gkr_poly_koala_bear_extension_kernel() -> KernelPtr;
// }

// #[link_name = "logup_tracegen"]
// #[allow(unused_attributes)]
// extern "C" {
//     pub fn gkr_tracegen_kernel() -> KernelPtr;
// }

extern "C" {
    pub fn logup_gkr_sum_as_poly_layer_kernel_circuit_layer_koala_bear_extension() -> KernelPtr;
    pub fn logup_gkr_fix_last_variable_circuit_layer_kernel_koala_bear_extension() -> KernelPtr;
    pub fn logup_gkr_fix_last_row_last_circuit_layer_kernel_circuit_layer_koala_bear_extension(
    ) -> KernelPtr;
    pub fn logup_gkr_sum_as_poly_layer_kernel_interactions_layer_koala_bear_extension() -> KernelPtr;
    pub fn logup_gkr_fix_last_variable_interactions_layer_kernel_koala_bear_extension() -> KernelPtr;
    pub fn logup_gkr_circuit_transition_koala_bear_extension() -> KernelPtr;

    pub fn logup_gkr_sum_as_poly_first_layer_kernel_koala_bear() -> KernelPtr;
    pub fn logup_gkr_fix_last_variable_first_layer_kernel_koala_bear() -> KernelPtr;
    pub fn logup_gkr_first_layer_transition_koala_bear() -> KernelPtr;

    pub fn logup_gkr_populate_last_circuit_layer_koala_bear() -> KernelPtr;
    pub fn logup_gkr_extract_output_koala_bear() -> KernelPtr;
}
