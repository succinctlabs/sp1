// Per-chunk `padded_row_adjustment` kernel — see pad_adj.cuh.

#include "zerocheck/pad_adj.cuh"
#include "zerocheck/sequential.cuh"  // ChunkStatic, DagInstr, LeafRef, BcOp
#include "config.cuh"

#include <cstdint>

namespace {

template <int MAX_REGS>
__global__ void zerocheck_pad_adj(
    const ChunkStatic* __restrict__ chunk_static,
    uint32_t n_chunks,
    const felt_t* __restrict__ public_values,
    const ext_t* __restrict__ powers_of_alpha,
    ext_t* __restrict__ output  // one ext_t per chunk
) {
    uint32_t chunk_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (chunk_idx >= n_chunks) {
        return;
    }
    ChunkStatic stc = chunk_static[chunk_idx];
    const felt_t* consts = reinterpret_cast<const felt_t*>(stc.consts);

    // Run the bytecode at the all-zero trace: LOAD_LEAF returns 0, every
    // other op behaves normally. The bytecode is deterministic given its
    // inputs, so each thread's `regs[]` evolves independently.
    felt_t regs[MAX_REGS];
    for (uint32_t i = 0; i < stc.n_instrs; i++) {
        DagInstr instr = stc.instrs[i];
        switch (instr.opcode) {
        case BC_LOAD_LEAF: {
            regs[instr.out] = felt_t::zero();
            break;
        }
        case BC_LOAD_CONST: {
            regs[instr.out] = consts[instr.a];
            break;
        }
        case BC_LOAD_PUBLIC: {
            uint32_t pv_idx = stc.publics[instr.a];
            regs[instr.out] = felt_t::load(public_values, pv_idx);
            break;
        }
        case BC_ADD_F: {
            regs[instr.out] = regs[instr.a] + regs[instr.b];
            break;
        }
        case BC_SUB_F: {
            regs[instr.out] = regs[instr.a] - regs[instr.b];
            break;
        }
        case BC_MUL_F: {
            regs[instr.out] = regs[instr.a] * regs[instr.b];
            break;
        }
        case BC_NEG_F: {
            regs[instr.out] = felt_t::zero() - regs[instr.a];
            break;
        }
        default:
            break;
        }
    }

    // Sum `α[chip_alpha_offset + αᵢ] · regs[root]` over this chunk's asserts.
    ext_t acc = ext_t::zero();
    for (uint32_t i = 0; i < stc.n_asserts; i++) {
        uint16_t reg = stc.assert_regs[i];
        uint32_t alpha_idx = stc.chip_alpha_offset + stc.assert_alphas[i];
        ext_t alpha = ext_t::load(powers_of_alpha, alpha_idx);
        acc += alpha * regs[reg];
    }

    ext_t::store(output, chunk_idx, acc);
}

}  // namespace

extern "C" void* zerocheck_pad_adj_32_kernel() {
    return (void*)zerocheck_pad_adj<32>;
}
extern "C" void* zerocheck_pad_adj_64_kernel() {
    return (void*)zerocheck_pad_adj<64>;
}
extern "C" void* zerocheck_pad_adj_128_kernel() {
    return (void*)zerocheck_pad_adj<128>;
}
extern "C" void* zerocheck_pad_adj_256_kernel() {
    return (void*)zerocheck_pad_adj<256>;
}
extern "C" void* zerocheck_pad_adj_512_kernel() {
    return (void*)zerocheck_pad_adj<512>;
}
extern "C" void* zerocheck_pad_adj_1024_kernel() {
    return (void*)zerocheck_pad_adj<1024>;
}
