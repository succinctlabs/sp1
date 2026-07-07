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

    pub fn hash_pages_koala_bear_16_kernel() -> KernelPtr;

    pub fn count_histogram_merkle_tree_kernel() -> KernelPtr;
    pub fn prev_leader_flags_merkle_tree_kernel() -> KernelPtr;
    pub fn scan_reset_merkle_tree_kernel() -> KernelPtr;
    pub fn scan_u32_merkle_tree_kernel() -> KernelPtr;
    pub fn prev_scatter_leaders_merkle_tree_kernel() -> KernelPtr;
    pub fn prev_compress_dense_merkle_tree_kernel() -> KernelPtr;
    pub fn cur_compress_merkle_tree_kernel() -> KernelPtr;
    pub fn emit_rows_merkle_tree_kernel() -> KernelPtr;
}
