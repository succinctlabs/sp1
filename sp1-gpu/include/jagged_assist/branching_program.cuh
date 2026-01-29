#pragma once

extern "C" void* branching_program_kernel();
extern "C" void* transition_kernel();
extern "C" void* interpolateAndObserve_kernel();

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