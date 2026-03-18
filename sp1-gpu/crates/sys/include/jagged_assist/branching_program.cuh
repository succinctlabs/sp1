#pragma once

#include <cstdint>

extern "C" void* branching_program_kernel();
extern "C" void* transition_kernel();
extern "C" void* transition_w8_kernel();
extern "C" void* interpolateAndObserve_kernel();
extern "C" void* precomputePrefixStates_kernel();
extern "C" void* evalWithCachedAtZeroAndHalf_kernel();
extern "C" void* updateSuffixVector_kernel();

// A range of values where the start is inclusive and the end is exclusive.
struct Range {
    int start;
    int end;

    __device__ bool in_range(int val) { return val >= start && val < end; }
};

// All the values of the BitState struct:
// https://github.com/succinctlabs/slop/blob/783136d30dc2b5e9ce558385b333dad93a89fd29/crates/jagged/src/poly.rs#L73
enum BitState {
    ROW_0__INDEX_0__CURR_PS_0__NEXT_PS_0,
    ROW_0__INDEX_0__CURR_PS_0__NEXT_PS_1,
    ROW_0__INDEX_0__CURR_PS_1__NEXT_PS_0,
    ROW_0__INDEX_0__CURR_PS_1__NEXT_PS_1,
    ROW_0__INDEX_1__CURR_PS_0__NEXT_PS_0,
    ROW_0__INDEX_1__CURR_PS_0__NEXT_PS_1,
    ROW_0__INDEX_1__CURR_PS_1__NEXT_PS_0,
    ROW_0__INDEX_1__CURR_PS_1__NEXT_PS_1,
    ROW_1__INDEX_0__CURR_PS_0__NEXT_PS_0,
    ROW_1__INDEX_0__CURR_PS_0__NEXT_PS_1,
    ROW_1__INDEX_0__CURR_PS_1__NEXT_PS_0,
    ROW_1__INDEX_0__CURR_PS_1__NEXT_PS_1,
    ROW_1__INDEX_1__CURR_PS_0__NEXT_PS_0,
    ROW_1__INDEX_1__CURR_PS_0__NEXT_PS_1,
    ROW_1__INDEX_1__CURR_PS_1__NEXT_PS_0,
    ROW_1__INDEX_1__CURR_PS_1__NEXT_PS_1,
    BIT_STATE_COUNT,
};

// All the values of the MemoryState struct:
// https://github.com/succinctlabs/slop/blob/783136d30dc2b5e9ce558385b333dad93a89fd29/crates/jagged/src/poly.rs#L39
// and the StateOrFail enum:
// https://github.com/succinctlabs/slop/blob/783136d30dc2b5e9ce558385b333dad93a89fd29/crates/jagged/src/poly.rs#L64
enum MemoryState {
    COMP_SO_FAR_0__CARRY_0,
    COMP_SO_FAR_0__CARRY_1,
    COMP_SO_FAR_1__CARRY_0,
    COMP_SO_FAR_1__CARRY_1,
    FAIL,
    MEMORY_STATE_COUNT,
};

// The success memory state:
// https://github.com/succinctlabs/slop/blob/783136d30dc2b5e9ce558385b333dad93a89fd29/crates/jagged/src/poly.rs#L53
__device__ constexpr int SUCCESS_STATE = COMP_SO_FAR_1__CARRY_0;

__device__ constexpr int INITIAL_MEMORY_STATE = COMP_SO_FAR_0__CARRY_0;

// Width-8 transition tables for the interleaved branching program.
// Memory state index: carry + (comparison_so_far << 1) + (saved_index_bit << 2), range 0..7.
// WIDE_FAIL = 8.
__device__ constexpr int WIDE_BP_WIDTH = 8;
__device__ constexpr int WIDE_FAIL = 8;
__device__ constexpr int WIDE_INITIAL_STATE = 0;
// Success states: carry=0, comp=1, saved=0 => 2; carry=0, comp=1, saved=1 => 6.
__device__ constexpr int WIDE_SUCCESS_STATE_0 = 2;
__device__ constexpr int WIDE_SUCCESS_STATE_1 = 6;

// Even layer (Curr): 8 bit states × 8 memory states.
// Bit state index: (curr_ps_bit << 2) | (index_bit << 1) | row_bit
__constant__ constexpr const uint8_t CURR_TRANSITIONS_W8[8][8] = {
    {0, 8, 2, 8, 0, 8, 2, 8}, // bit_state 0: row=0 idx=0 cps=0
    {8, 1, 8, 3, 8, 1, 8, 3}, // bit_state 1: row=1 idx=0 cps=0
    {8, 4, 8, 6, 8, 4, 8, 6}, // bit_state 2: row=0 idx=1 cps=0
    {4, 8, 6, 8, 4, 8, 6, 8}, // bit_state 3: row=1 idx=1 cps=0
    {8, 1, 8, 3, 8, 1, 8, 3}, // bit_state 4: row=0 idx=0 cps=1
    {1, 8, 3, 8, 1, 8, 3, 8}, // bit_state 5: row=1 idx=0 cps=1
    {4, 8, 6, 8, 4, 8, 6, 8}, // bit_state 6: row=0 idx=1 cps=1
    {8, 5, 8, 7, 8, 5, 8, 7}, // bit_state 7: row=1 idx=1 cps=1
};

// Odd layer (Next): 2 bit states × 8 memory states.
// Bit state index: next_ps_bit
__constant__ constexpr const uint8_t NEXT_TRANSITIONS_W8[2][8] = {
    {0, 1, 2, 3, 0, 1, 0, 1}, // next_ps=0
    {2, 3, 2, 3, 0, 1, 2, 3}, // next_ps=1
};

__constant__ constexpr const MemoryState TRANSITIONS[BIT_STATE_COUNT][MEMORY_STATE_COUNT] = {
    {COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_1__CARRY_0, FAIL, FAIL},
    {COMP_SO_FAR_1__CARRY_0, FAIL, COMP_SO_FAR_1__CARRY_0, FAIL, FAIL},
    {FAIL, COMP_SO_FAR_0__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL},
    {FAIL, COMP_SO_FAR_1__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL},
    {FAIL, COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_0__CARRY_0, FAIL},
    {FAIL, COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_1__CARRY_0, FAIL},
    {COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_0__CARRY_0, FAIL, FAIL},
    {COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_1__CARRY_0, FAIL, FAIL},
    {FAIL, COMP_SO_FAR_0__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL},
    {FAIL, COMP_SO_FAR_1__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL},
    {COMP_SO_FAR_0__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL, FAIL},
    {COMP_SO_FAR_1__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL, FAIL},
    {COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_0__CARRY_0, FAIL, FAIL},
    {COMP_SO_FAR_0__CARRY_0, FAIL, COMP_SO_FAR_1__CARRY_0, FAIL, FAIL},
    {FAIL, COMP_SO_FAR_0__CARRY_1, FAIL, COMP_SO_FAR_0__CARRY_1, FAIL},
    {FAIL, COMP_SO_FAR_0__CARRY_1, FAIL, COMP_SO_FAR_1__CARRY_1, FAIL},
};