use crate::runtime::KernelPtr;

extern "C" {
    pub fn leaf_hash_merkle_tree_koala_bear_16_kernel() -> KernelPtr;
    pub fn compress_merkle_tree_koala_bear_16_kernel() -> KernelPtr;
    pub fn compute_paths_merkle_tree_koala_bear_16_kernel() -> KernelPtr;
    pub fn compute_openings_merkle_tree_koala_bear_16_kernel() -> KernelPtr;

    pub fn leaf_hash_merkle_tree_bn254_kernel() -> KernelPtr;
    pub fn compress_merkle_tree_bn254_kernel() -> KernelPtr;
    pub fn compute_paths_merkle_tree_bn254_kernel() -> KernelPtr;
    pub fn compute_openings_merkle_tree_bn254_kernel() -> KernelPtr;
}
