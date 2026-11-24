#pragma once

extern "C" void *gather_merkle_openings_kernel();

extern "C" void *leaf_hash_merkle_tree_koala_bear_16_kernel();
extern "C" void *compress_merkle_tree_koala_bear_16_kernel();
extern "C" void *compress_layers_merkle_tree_koala_bear_16_kernel();
extern "C" void *compute_paths_merkle_tree_koala_bear_16_kernel();
extern "C" void *compute_openings_merkle_tree_koala_bear_16_kernel();

extern "C" void *leaf_hash_merkle_tree_bn254_kernel();
extern "C" void *compress_merkle_tree_bn254_kernel();
extern "C" void *compress_layers_merkle_tree_bn254_kernel();
extern "C" void *compute_paths_merkle_tree_bn254_kernel();
extern "C" void *compute_openings_merkle_tree_bn254_kernel();
