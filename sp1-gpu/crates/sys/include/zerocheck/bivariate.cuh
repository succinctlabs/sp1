// Shared helpers for the fused first-two-rounds ("bivariate") zerocheck.
//
// The first two sumcheck rounds are proven from a single pass over the
// base-field trace: the round polynomial is evaluated as a *bivariate* in the
// last two variables `(X, Y)` on the grid `{0, 1, 2, 4}^2`. Rows are consumed
// in quadruples (element index `4·quad + 2·X + Y`); the four boolean nodes
// `X, Y ∈ {0, 1}` need no constraint evaluation (constraints vanish on real
// rows and the padded-row values cancel exactly against the geq correction),
// leaving the 12 non-boolean nodes below.
//
// The node order MUST match `sp1_hypercube::prover::ZEROCHECK_CONSTRAINT_NODES`
// (with `ZEROCHECK_NODE_XS = [0, 1, 2, 4]`), which the host uses to assemble
// the grid and interpolate the two round messages.

#pragma once

#include "config.cuh"
#include <cstdint>

// Number of non-boolean grid nodes evaluated by the constraint kernels; also
// the output stride of every bivariate partials buffer.
constexpr int BIVARIATE_NUM_NODES = 12;

// Number of boolean corner nodes swept by the GKR corner kernel.
constexpr int BIVARIATE_NUM_CORNERS = 4;

// The `(x, y, x·y)` coordinates of node `e`. All coordinates are powers of
// two (or zero/one), so interpolation multiplies reduce to doublings.
struct BivariateNode {
    uint32_t cx;
    uint32_t cy;
    uint32_t cxy;
};

// Node table — must match ZEROCHECK_CONSTRAINT_NODES:
//   [(0,2),(0,4),(1,2),(1,4),(2,0),(2,1),(2,2),(2,4),(4,0),(4,1),(4,2),(4,4)]
// `e` is uniform per block (blockIdx.z), so the switch never diverges.
__device__ __forceinline__ BivariateNode bivariate_node(int e) {
    switch (e) {
    case 0:  return {0u, 2u, 0u};
    case 1:  return {0u, 4u, 0u};
    case 2:  return {1u, 2u, 2u};
    case 3:  return {1u, 4u, 4u};
    case 4:  return {2u, 0u, 0u};
    case 5:  return {2u, 1u, 2u};
    case 6:  return {2u, 2u, 4u};
    case 7:  return {2u, 4u, 8u};
    case 8:  return {4u, 0u, 0u};
    case 9:  return {4u, 1u, 4u};
    case 10: return {4u, 2u, 8u};
    default: return {4u, 4u, 16u};
    }
}

// `v * c` for `c ∈ {0, 1, 2, 4, 8, 16}` via doublings. `c` is uniform per
// block (derived from blockIdx.z), so the switch costs nothing.
template <typename K>
__device__ __forceinline__ K mul_small_pow2(K v, uint32_t c) {
    switch (c) {
    case 0: return K::zero();
    case 1: return v;
    case 2: return v + v;
    case 4: {
        K d = v + v;
        return d + d;
    }
    case 8: {
        K d = v + v;
        d = d + d;
        return d + d;
    }
    default: {  // 16
        K d = v + v;
        d = d + d;
        d = d + d;
        return d + d;
    }
    }
}

// Bilinear interpolation of a quadruple's corner values at node `nd`:
//   value = r00 + x·(r10 − r00) + y·(r01 − r00) + x·y·(r11 − r10 − r01 + r00)
// where `r[2x + y]` is the value at boolean point `(x, y)`.
template <typename K>
__device__ __forceinline__ K bivariate_interp(K r00, K r01, K r10, K r11, BivariateNode nd) {
    K dy = r01 - r00;
    K dx = r10 - r00;
    K dxy = (r11 - r10) - dy;
    return r00 + mul_small_pow2(dx, nd.cx) + mul_small_pow2(dy, nd.cy)
        + mul_small_pow2(dxy, nd.cxy);
}
