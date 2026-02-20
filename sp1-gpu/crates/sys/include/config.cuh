#pragma once

#include "fields/kb31_t.cuh"
#include "fields/kb31_extension_t.cuh"

using felt_t = kb31_t;
using ext_t = kb31_extension_t;

struct Pair {
    ext_t p;
    ext_t q;
};