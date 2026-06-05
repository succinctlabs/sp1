#pragma once

// Two-stage-GKR Option 2 GPU kernels.  K = K_1 · K_2 = 64.  All five splits supported:
// (2, 32), (4, 16), (8, 8), (16, 4), (32, 2).  See the .cu for the algorithmic overview.

// B_j build kernels (per split).
extern "C" void* build_b_mles_2_32_kernel();
extern "C" void* build_b_mles_4_16_kernel();
extern "C" void* build_b_mles_8_8_kernel();
extern "C" void* build_b_mles_16_4_kernel();
extern "C" void* build_b_mles_32_2_kernel();

// Stage-1 round kernels (per K_2).  Ext-input, with (a, b) = (0, 1) set on the host so
// the factor `a + b·B_j` is the MLE value itself.
extern "C" void* two_stage_stage1_sum_as_poly_ext_2_kernel();
extern "C" void* two_stage_stage1_fix_and_sum_ext_2_kernel();
extern "C" void* two_stage_stage1_sum_as_poly_ext_4_kernel();
extern "C" void* two_stage_stage1_fix_and_sum_ext_4_kernel();
extern "C" void* two_stage_stage1_sum_as_poly_ext_8_kernel();
extern "C" void* two_stage_stage1_fix_and_sum_ext_8_kernel();
extern "C" void* two_stage_stage1_sum_as_poly_ext_16_kernel();
extern "C" void* two_stage_stage1_fix_and_sum_ext_16_kernel();
extern "C" void* two_stage_stage1_sum_as_poly_ext_32_kernel();
extern "C" void* two_stage_stage1_fix_and_sum_ext_32_kernel();

// Stage-2 round kernels (per (K_1, K_2)).  Base-input flavour for round 0, ext-input
// for rounds 1..c-1.
extern "C" void* two_stage_stage2_sum_as_poly_base_2_32_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_base_2_32_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_ext_2_32_kernel();
extern "C" void* two_stage_stage2_sum_as_poly_base_4_16_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_base_4_16_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_ext_4_16_kernel();
extern "C" void* two_stage_stage2_sum_as_poly_base_8_8_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_base_8_8_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_ext_8_8_kernel();
extern "C" void* two_stage_stage2_sum_as_poly_base_16_4_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_base_16_4_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_ext_16_4_kernel();
extern "C" void* two_stage_stage2_sum_as_poly_base_32_2_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_base_32_2_kernel();
extern "C" void* two_stage_stage2_fix_and_sum_ext_32_2_kernel();
