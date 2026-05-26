#pragma once

extern "C" void *leaf_hash_merkle_tree_koala_bear_16_kernel();
extern "C" void *compress_merkle_tree_koala_bear_16_kernel();
extern "C" void *compute_paths_merkle_tree_koala_bear_16_kernel();
extern "C" void *compute_openings_merkle_tree_koala_bear_16_kernel();

extern "C" void *leaf_hash_merkle_tree_bn254_kernel();
extern "C" void *compress_merkle_tree_bn254_kernel();
extern "C" void *compute_paths_merkle_tree_bn254_kernel();
extern "C" void *compute_openings_merkle_tree_bn254_kernel();

extern "C" void *count_histogram_merkle_tree_kernel();
extern "C" void *copy_digest8_merkle_tree_kernel();
extern "C" void *prev_leader_flags_merkle_tree_kernel();
extern "C" void *scan_reset_merkle_tree_kernel();
extern "C" void *scan_u32_merkle_tree_kernel();
extern "C" void *prev_compress_merkle_tree_kernel();
extern "C" void *cur_compress_merkle_tree_kernel();
extern "C" void *emit_rows_merkle_tree_kernel();