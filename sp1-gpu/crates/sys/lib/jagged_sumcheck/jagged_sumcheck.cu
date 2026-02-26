#include "jagged_sumcheck/jagged_sumcheck.cuh"
#include "sum_and_reduce/reduce.cuh"
#include "tracegen/jagged_tracegen/jagged.cuh"
#include "challenger/challenger.cuh"


#include <cooperative_groups.h>
#include <cooperative_groups/reduce.h>

template <typename F, typename EF>
__device__ void interpolateQuadratic(F x_0, F x_1, F x_2, EF y_0, EF y_1, EF y_2, EF coeffs[3]) {
    F x0102 = (x_0 - x_1) * (x_0 - x_2);
    F x1012 = (x_1 - x_0) * (x_1 - x_2);
    F x2021 = (x_2 - x_0) * (x_2 - x_1);
    F x0102x1012 = x0102 * x1012;
    F denom = x0102x1012 * x2021;
    F inv = denom.reciprocal();

    EF coeff_0 = y_0 * inv * x1012 * x2021;
    EF coeff_1 = y_1 * inv * x0102 * x2021;
    EF coeff_2 = y_2 * inv * x0102x1012;

    EF c0c1 = coeff_0 + coeff_1;
    EF c0x1 = coeff_0 * x_1;
    EF c1x0 = coeff_1 * x_0;
    EF c2x0 = coeff_2 * x_0;
    EF c0c1x2 = c0c1 * x_2;
    F x0x1 = x_0 + x_1;

    EF t2 = c0c1 + coeff_2;

    EF t1 = coeff_2 * x0x1;
    t1 += c0x1;
    t1 += c1x0;
    t1 += c0c1x2;

    EF t0 = c0x1 + c1x0;
    t0 *= x_2;
    t0 += c2x0 * x_1;

    coeffs[2] = t2;
    coeffs[1] = -t1;
    coeffs[0] = t0;
}


__global__ void
jaggedSumAsPoly(ext_t* evaluations, const JaggedMle<JaggedSumcheckData> inputJaggedMle) {

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height;
         i += blockDim.x * gridDim.x) {

        size_t colIdx = inputJaggedMle.colIndex[i];
        size_t startIdx = inputJaggedMle.startIndices[colIdx];

        size_t rowIdx = i - startIdx;
        size_t baseZeroIdx = i << 1;

        ext_t eqZCol = ext_t::load(inputJaggedMle.denseData.eqZCol, colIdx);
        ext_t eqZRowZero = ext_t::load(inputJaggedMle.denseData.eqZRow, rowIdx << 1);
        // This is fine because columns are padded to a multiple of 16.
        ext_t eqZRowOne = ext_t::load(inputJaggedMle.denseData.eqZRow, (rowIdx << 1) + 1);

        ext_t jaggedValZero = eqZCol * eqZRowZero;
        ext_t jaggedValOne = eqZCol * eqZRowOne;

        felt_t baseZeroValue = felt_t::load(inputJaggedMle.denseData.base, baseZeroIdx);
        felt_t baseOneValue = felt_t::load(inputJaggedMle.denseData.base, baseZeroIdx + 1);

        evalZero += baseZeroValue * jaggedValZero;
        evalHalf += (baseZeroValue + baseOneValue) * (jaggedValZero + jaggedValOne);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(evaluations, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            evaluations,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}


__global__ void jaggedFixAndSum(
    ext_t* evaluations,
    const JaggedMle<JaggedSumcheckData> inputJaggedMle,
    ext_t* output_p,
    ext_t* output_q,
    ext_t alpha) {

    Hadamard hadamard;
    hadamard.p = output_p;
    hadamard.q = output_q;

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height >> 1;
         i += blockDim.x * gridDim.x) {

        // The inputs column lengths are padded to a multiple of 16. So therefore we can do two
        // fixes without checking bounds and handling padding.
#pragma unroll
        for (size_t j = i << 1; j < (i << 1) + 2; j++) {

            size_t colIdx = inputJaggedMle.colIndex[j];
            size_t startIdx = inputJaggedMle.startIndices[colIdx];

            size_t rowIdx = j - startIdx;
            size_t zeroIdx = j << 1;
            size_t restrictedIndex = j;

            inputJaggedMle.denseData
                .fixLastVariable(&hadamard, restrictedIndex, zeroIdx, colIdx, rowIdx << 1, alpha);
        }

        // Todo: directly return the result of fixlastvariable, unclear if this turns into another
        // global access or not maybe not a huge speedup because of cache locality though
        ext_t zeroValP = ext_t::load(hadamard.p, i << 1);
        ext_t oneValP = ext_t::load(hadamard.p, (i << 1) + 1);
        ext_t zeroValQ = ext_t::load(hadamard.q, i << 1);
        ext_t oneValQ = ext_t::load(hadamard.q, (i << 1) + 1);

        evalZero += zeroValQ * zeroValP;
        evalHalf += (zeroValQ + oneValQ) * (zeroValP + oneValP);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(evaluations, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            evaluations,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

__global__ void jaggedFixAndSumWithAlphaPtr(
    ext_t* evaluations,
    const JaggedMle<JaggedSumcheckData> inputJaggedMle,
    ext_t* output_p,
    ext_t* output_q,
    const ext_t* alpha_ptr) {
    ext_t alpha = alpha_ptr[0];

    Hadamard hadamard;
    hadamard.p = output_p;
    hadamard.q = output_q;

    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    for (size_t i = blockIdx.x * blockDim.x + threadIdx.x; i < inputJaggedMle.denseData.height >> 1;
         i += blockDim.x * gridDim.x) {
#pragma unroll
        for (size_t j = i << 1; j < (i << 1) + 2; j++) {
            size_t colIdx = inputJaggedMle.colIndex[j];
            size_t startIdx = inputJaggedMle.startIndices[colIdx];

            size_t rowIdx = j - startIdx;
            size_t zeroIdx = j << 1;
            size_t restrictedIndex = j;

            inputJaggedMle.denseData
                .fixLastVariable(&hadamard, restrictedIndex, zeroIdx, colIdx, rowIdx << 1, alpha);
        }

        ext_t zeroValP = ext_t::load(hadamard.p, i << 1);
        ext_t oneValP = ext_t::load(hadamard.p, (i << 1) + 1);
        ext_t zeroValQ = ext_t::load(hadamard.q, i << 1);
        ext_t oneValQ = ext_t::load(hadamard.q, (i << 1) + 1);

        evalZero += zeroValQ * zeroValP;
        evalHalf += (zeroValQ + oneValQ) * (zeroValP + oneValP);
    }

    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(evaluations, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            evaluations,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

__global__ void paddedHadamardFixAndSum(
    const ext_t* base_input,
    const ext_t* ext_input,
    ext_t* __restrict base_output,
    ext_t* __restrict ext_output,
    ext_t alpha,
    ext_t* univariate_result,
    size_t inputHeight) {

    size_t outputHeight = (inputHeight + 1) >> 1;
    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<2>(block);

    size_t halfOutputHeight = (outputHeight + 1) >> 1;


    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < halfOutputHeight;
         i += blockDim.x * gridDim.x) {
        size_t firstIdx = i << 1;
        size_t secondIdx = (i << 1) + 1;

        // Fix last variable for the actual layer. TODO: this has some padding checks that aren't
        // needed.
        Pair pair1 = fixLastVariableInner(base_input, ext_input, alpha, inputHeight, firstIdx);
        ext_t::store(base_output, firstIdx, pair1.p);
        ext_t::store(ext_output, firstIdx, pair1.q);

        // Todo: instead of checking padding conditions twice here ad in sumAsPoly, we should do it
        // once.
        Pair pair2;
        if (secondIdx < outputHeight) {
            pair2 = fixLastVariableInner(base_input, ext_input, alpha, inputHeight, secondIdx);
        } else {
            pair2 = Pair{ext_t::zero(), ext_t::zero()};
        }

        ext_t::store(base_output, secondIdx, pair2.p);
        ext_t::store(ext_output, secondIdx, pair2.q);

        evalZero += pair1.p * pair1.q;
        evalHalf += (pair1.p + pair2.p) * (pair1.q + pair2.q);
    }

    // Allocate shared memory
    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto reduce_tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, reduce_tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, reduce_tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(univariate_result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            univariate_result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

__global__ void paddedHadamardFixAndSumWithAlphaPtr(
    const ext_t* base_input,
    const ext_t* ext_input,
    ext_t* __restrict base_output,
    ext_t* __restrict ext_output,
    const ext_t* alpha_ptr,
    ext_t* univariate_result,
    size_t inputHeight) {
    ext_t alpha = alpha_ptr[0];
    size_t outputHeight = (inputHeight + 1) >> 1;
    ext_t evalZero = ext_t::zero();
    ext_t evalHalf = ext_t::zero();

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<2>(block);

    size_t halfOutputHeight = (outputHeight + 1) >> 1;

    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < halfOutputHeight;
         i += blockDim.x * gridDim.x) {
        size_t firstIdx = i << 1;
        size_t secondIdx = (i << 1) + 1;

        Pair pair1 = fixLastVariableInner(base_input, ext_input, alpha, inputHeight, firstIdx);
        ext_t::store(base_output, firstIdx, pair1.p);
        ext_t::store(ext_output, firstIdx, pair1.q);

        Pair pair2;
        if (secondIdx < outputHeight) {
            pair2 = fixLastVariableInner(base_input, ext_input, alpha, inputHeight, secondIdx);
        } else {
            pair2 = Pair{ext_t::zero(), ext_t::zero()};
        }

        ext_t::store(base_output, secondIdx, pair2.p);
        ext_t::store(ext_output, secondIdx, pair2.q);

        evalZero += pair1.p * pair1.q;
        evalHalf += (pair1.p + pair2.p) * (pair1.q + pair2.q);
    }

    extern __shared__ unsigned char memory[];
    ext_t* shared = reinterpret_cast<ext_t*>(memory);

    auto reduce_tile = cg::tiled_partition<32>(block);
    ext_t evalZeroblockSum = partialBlockReduce(block, reduce_tile, evalZero, shared);
    ext_t evalHalfblockSum = partialBlockReduce(block, reduce_tile, evalHalf, shared);

    if (threadIdx.x == 0) {
        ext_t::store(univariate_result, gridDim.x * blockIdx.y + blockIdx.x, evalZeroblockSum);
        ext_t::store(
            univariate_result,
            gridDim.x * gridDim.y + gridDim.x * blockIdx.y + blockIdx.x,
            evalHalfblockSum);
    }
}

template <typename Challenger>
__global__ void jaggedInterpolateObserveAndSample(
    const ext_t* reduced_evaluations,
    Challenger challenger,
    ext_t* coefficients_out,
    ext_t* sampled_alpha,
    ext_t* claim_inout) {
    if (blockIdx.x == 0 && threadIdx.x == 0) {
        ext_t y_0 = reduced_evaluations[0];
        ext_t y_1 = claim_inout[0] - y_0;
        ext_t y_half = reduced_evaluations[1];
        y_half *= felt_t::from_canonical_u16(4).reciprocal();

        felt_t x_0 = felt_t::zero();
        felt_t x_1 = felt_t::one();
        felt_t x_half = felt_t::two().reciprocal();

        ext_t coefficients[3];
        interpolateQuadratic<felt_t, ext_t>(x_0, x_1, x_half, y_0, y_1, y_half, coefficients);

        coefficients_out[0] = coefficients[0];
        coefficients_out[1] = coefficients[1];
        coefficients_out[2] = coefficients[2];

        challenger.observe_ext(&coefficients[0]);
        challenger.observe_ext(&coefficients[1]);
        challenger.observe_ext(&coefficients[2]);

        ext_t alpha = challenger.sample_ext();
        sampled_alpha[0] = alpha;

        ext_t next_claim(coefficients[2]);
        next_claim *= alpha;
        next_claim += coefficients[1];
        next_claim *= alpha;
        next_claim += coefficients[0];
        claim_inout[0] = next_claim;
    }
}

__global__ void jaggedLastRoundsDuplexKernel(
    const ext_t* p_input,
    const ext_t* q_input,
    size_t input_height,
    size_t tail_start_round,
    size_t num_variables,
    ext_t* coefficients_out,
    ext_t* alphas,
    DuplexChallenger challenger,
    ext_t* claim_inout,
    ext_t* final_evals_out) {
    if (blockIdx.x != 0) {
        return;
    }

    const size_t shared_capacity = (input_height + 1) >> 1;
    extern __shared__ unsigned char memory[];
    ext_t* p_buf_0 = reinterpret_cast<ext_t*>(memory);
    ext_t* q_buf_0 = p_buf_0 + shared_capacity;
    ext_t* p_buf_1 = q_buf_0 + shared_capacity;
    ext_t* q_buf_1 = p_buf_1 + shared_capacity;
    const size_t num_warps = (blockDim.x + 31) >> 5;
    ext_t* shared_zero = q_buf_1 + shared_capacity;
    ext_t* shared_half = shared_zero + num_warps;

    auto block = cg::this_thread_block();
    auto tile = cg::tiled_partition<32>(block);

    __shared__ ext_t shared_alpha;
    __shared__ ext_t shared_claim;
    __shared__ size_t shared_height;

    if (threadIdx.x == 0) {
        shared_alpha = alphas[tail_start_round - 1];
        shared_claim = claim_inout[0];
        shared_height = input_height;
    }
    block.sync();

    const size_t tail_rounds = num_variables - tail_start_round;
    for (size_t round_offset = 0; round_offset < tail_rounds; round_offset++) {
        const size_t round = tail_start_round + round_offset;

        ext_t current_alpha = shared_alpha;
        ext_t current_claim = shared_claim;
        size_t current_height = shared_height;
        size_t output_height = (current_height + 1) >> 1;
        size_t half_output_height = (output_height + 1) >> 1;

        ext_t local_eval_zero = ext_t::zero();
        ext_t local_eval_half = ext_t::zero();

        bool use_global_input = (round_offset == 0);
        const ext_t* current_p;
        const ext_t* current_q;
        ext_t* next_p;
        ext_t* next_q;
        if (use_global_input) {
            current_p = p_input;
            current_q = q_input;
            next_p = p_buf_0;
            next_q = q_buf_0;
        } else if ((round_offset & 1) == 1) {
            current_p = p_buf_0;
            current_q = q_buf_0;
            next_p = p_buf_1;
            next_q = q_buf_1;
        } else {
            current_p = p_buf_1;
            current_q = q_buf_1;
            next_p = p_buf_0;
            next_q = q_buf_0;
        }

        for (size_t i = threadIdx.x; i < half_output_height; i += blockDim.x) {
            size_t first_idx = i << 1;
            size_t second_idx = first_idx + 1;

            Pair pair1 =
                fixLastVariableInner(current_p, current_q, current_alpha, current_height, first_idx);
            ext_t::store(next_p, first_idx, pair1.p);
            ext_t::store(next_q, first_idx, pair1.q);

            Pair pair2;
            if (second_idx < output_height) {
                pair2 = fixLastVariableInner(
                    current_p,
                    current_q,
                    current_alpha,
                    current_height,
                    second_idx);
                ext_t::store(next_p, second_idx, pair2.p);
                ext_t::store(next_q, second_idx, pair2.q);
            } else {
                pair2 = Pair{ext_t::zero(), ext_t::zero()};
            }

            local_eval_zero += pair1.p * pair1.q;
            local_eval_half += (pair1.p + pair2.p) * (pair1.q + pair2.q);
        }

        ext_t eval_zero = partialBlockReduce(block, tile, local_eval_zero, shared_zero);
        ext_t eval_half = partialBlockReduce(block, tile, local_eval_half, shared_half);

        if (threadIdx.x == 0) {
            ext_t y_0 = eval_zero;
            ext_t y_1 = current_claim - y_0;
            ext_t y_half = eval_half;
            y_half *= felt_t::from_canonical_u16(4).reciprocal();

            ext_t coeffs[3];
            interpolateQuadratic<felt_t, ext_t>(
                felt_t::zero(),
                felt_t::one(),
                felt_t::two().reciprocal(),
                y_0,
                y_1,
                y_half,
                coeffs);

            ext_t::store(coefficients_out, round * 3, coeffs[0]);
            ext_t::store(coefficients_out, round * 3 + 1, coeffs[1]);
            ext_t::store(coefficients_out, round * 3 + 2, coeffs[2]);

            challenger.observe_ext(&coeffs[0]);
            challenger.observe_ext(&coeffs[1]);
            challenger.observe_ext(&coeffs[2]);

            ext_t sampled_alpha = challenger.sample_ext();
            ext_t::store(alphas, round, sampled_alpha);

            ext_t next_claim(coeffs[2]);
            next_claim *= sampled_alpha;
            next_claim += coeffs[1];
            next_claim *= sampled_alpha;
            next_claim += coeffs[0];

            shared_alpha = sampled_alpha;
            shared_claim = next_claim;
            shared_height = output_height;
        }
        block.sync();
    }

    if (threadIdx.x == 0) {
        const bool final_in_buf_0 = (tail_rounds & 1) == 1;
        const ext_t* final_p = final_in_buf_0 ? p_buf_0 : p_buf_1;
        const ext_t* final_q = final_in_buf_0 ? q_buf_0 : q_buf_1;
        Pair final_pair = fixLastVariableInner(final_p, final_q, shared_alpha, shared_height, 0);
        ext_t::store(final_evals_out, 0, final_pair.p);
        ext_t::store(final_evals_out, 1, final_pair.q);
        claim_inout[0] = shared_claim;
    }
}


extern "C" void* jagged_sum_as_poly() { return (void*)jaggedSumAsPoly; }

extern "C" void* jagged_fix_and_sum() { return (void*)jaggedFixAndSum; }

extern "C" void* padded_hadamard_fix_and_sum() { return (void*)paddedHadamardFixAndSum; }

extern "C" void* jagged_fix_and_sum_with_alpha_ptr() { return (void*)jaggedFixAndSumWithAlphaPtr; }

extern "C" void* padded_hadamard_fix_and_sum_with_alpha_ptr() {
    return (void*)paddedHadamardFixAndSumWithAlphaPtr;
}

extern "C" void* jagged_interpolate_and_observe_duplex() {
    return (void*)jaggedInterpolateObserveAndSample<DuplexChallenger>;
}

extern "C" void* jagged_interpolate_and_observe_multi_field_32() {
    return (void*)jaggedInterpolateObserveAndSample<MultiField32Challenger>;
}

extern "C" void* jagged_last_rounds_duplex_kernel() { return (void*)jaggedLastRoundsDuplexKernel; }
