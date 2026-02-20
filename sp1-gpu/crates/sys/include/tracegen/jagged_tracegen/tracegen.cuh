#pragma once

extern "C" void* generate_col_index();
extern "C" void* generate_start_indices();
extern "C" void* fill_buffer();
extern "C" void* count_and_add_kernel();
extern "C" void* sum_to_trace_kernel();