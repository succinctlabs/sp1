#pragma once

#include "sum_and_reduce/reduction.cuh"
#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"

extern "C" void* partial_inner_product_koala_bear_kernel();

extern "C" void* partial_inner_product_koala_bear_extension_kernel();

extern "C" void* partial_inner_product_koala_bear_base_extension_kernel();

extern "C" void* partial_dot_koala_bear_kernel();

extern "C" void* partial_dot_koala_bear_extension_kernel();

extern "C" void* partial_dot_koala_bear_base_extension_kernel();

extern "C" void* dot_along_short_dimension_kernel_koala_bear_base_base();

extern "C" void* dot_along_short_dimension_kernel_koala_bear_base_extension();

extern "C" void* dot_along_short_dimension_kernel_koala_bear_extension_extension();
