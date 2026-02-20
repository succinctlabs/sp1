#include <cooperative_groups.h>

#include "mle/mle.cuh"
#include "fields/kb31_extension_t.cuh"
#include "fields/kb31_t.cuh"

namespace cg = cooperative_groups;

/*
// TODO: This kernel does not work currently. It's rougtly a 2x over the naive kernel which might
// not be the
This kernel computes the next log2(block.size()) variables of the partial Lagrange evaluation.
We follow the tree-based approach of Vu. The approach starts from loading the value 1 as the root
of the tree. Then, for each variable, the left subchild represents adding a `0` to the bit string
and the right subchild represents adding a `1` to the bit string. This means that we need to write
the values
    tree[left_child] = tree[parent] * (1 - point[variable])
    tree[right_child] = tree[parent] * point[variable]

    Let's do an example with 2 variables.

    First, we load the value 1 as the root of the tree.
        shared= [1, .., ..]
    In step 0, we want stride = 1 and so only thread 0 will be active.
        - thread_rank = 0: parent = 0, left_child = 1, right_child = 2
    at the end of the step, we have:
        shared= [1, 1 - z0, z0, ..]
    In step 1, we want stride = 2 and so only thread 0 and thread 1 will be active.
        - thread_rank = 0: parent = 1, left_child = 3, right_child = 4
        - thread_rank = 1: parent = 2, left_child = 5, right_child = 6
    at the end of the step, we have:
        shared= [1, 1 - z0, z0, (1 - z0) * (1 - z1), (1 - z0) * z1, z0 * (1 - z1), z0 * z1]

    Then, the general formula for the indices for each thread at each `stride` is:
        - parent = thread_rank + stride - 1
        - left_child = (parent << 1) + 1
        - right_child = left_child + 1

*/
template <typename F>
__global__ void partial_lagrange_eval_step(
    F* __restrict__ output,
    F* __restrict__ memory,
    F* point,
    size_t computed_num_variables,
    size_t total_num_variables) {
    auto block = cg::this_thread_block();

    extern __shared__ unsigned char shared_memory[];
    F* shared = reinterpret_cast<F*>(shared_memory);

    // Load the latest computed layer to shared memory.
    if (block.thread_rank() == 0) {
        if (computed_num_variables == 0) {
            memory[0] = F::one();
            block.sync();
        }
        shared[0] = memory[(1 << computed_num_variables) - 1 + blockIdx.x];
    }
    block.sync();

    // Perform tree-based traversal of the values.
    for (int stride = 1; stride <= block.size(); stride *= 2) {
        if (block.thread_rank() < stride) {
            size_t parentIdx = block.thread_rank() + stride - 1;
            size_t leftIdx = (parentIdx << 1) + 1;
            size_t rightIdx = leftIdx + 1;

            F z = point[computed_num_variables + 31 - __clz(stride)];

            F parentTimesCoordinate = shared[parentIdx] * z;
            shared[leftIdx] = parentTimesCoordinate;
            shared[rightIdx] = parentTimesCoordinate - shared[parentIdx];
        }
        block.sync();
    }

    // Write the values to the output. If this is the last step, we need to write the values to the
    // output buffer, otherwise, we write the memory buffer.
    size_t step_size = 31 - __clz(block.size());

    size_t new_total_computed = computed_num_variables + step_size;

    size_t lastParentIdx = block.size() - 1 + block.thread_rank();
    size_t lastLeftChildIdx = (lastParentIdx << 1) + 1;
    size_t lastRightChildIdx = lastLeftChildIdx + 1;
    F lastLeftChildValue = shared[lastLeftChildIdx];
    F lastRightChildValue = shared[lastRightChildIdx];
    if (new_total_computed == total_num_variables) {
        size_t parentIdx = blockIdx.x * blockDim.x + threadIdx.x;
        size_t leftChildIdx = (parentIdx << 1);
        size_t rightChildIdx = leftChildIdx + 1;
        output[leftChildIdx] = lastLeftChildValue;
        output[rightChildIdx] = lastRightChildValue;
    } else {
        size_t parentIdx = (1 << new_total_computed) - 1 + blockIdx.x * blockDim.x + threadIdx.x;
        size_t leftChildIdx = (parentIdx << 1) + 1;
        size_t rightChildIdx = leftChildIdx + 1;
        memory[parentIdx] = lastLeftChildValue;
        memory[rightChildIdx] = lastRightChildValue;
    }
}

template <typename F, typename EF>
__global__ void
partial_lagrange_naive(EF* __restrict__ output, EF* point, size_t total_num_variables) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < (1 << total_num_variables);
         i += blockDim.x * gridDim.x) {
        EF value = EF::one();
        for (size_t k = 0; k < total_num_variables; k++) {
            bool bit = ((i >> (total_num_variables - 1 - k)) & 1) != 0;
            EF z = EF::load(point, k);
            value *= bit ? z : (EF::one() - z);
        }
        EF::store(output, i, value);
    }
}

extern "C" void* partial_lagrange_koala_bear() {
    return (void*)partial_lagrange_naive<kb31_t, kb31_t>;
}

extern "C" void* partial_lagrange_koala_bear_extension() {
    return (void*)partial_lagrange_naive<kb31_t, kb31_extension_t>;
}


template <typename F>
__global__ void
partial_geq_naive(F* __restrict__ output, size_t threshold, size_t total_num_variables) {
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < (1 << total_num_variables);
         i += blockDim.x * gridDim.x) {
        F value;
        if (i >= threshold) {
            value = F::one();
        } else {
            value = F::zero();
        }

        F::store(output, i, value);
    }
}

extern "C" void* partial_geq_koala_bear() { return (void*)partial_geq_naive<kb31_t>; }





template <typename F>
__global__ void fixLastVariableInPlace(F* inout, F alpha, size_t outputHeight, size_t width) {
    size_t inputHeight = outputHeight << 1;
    for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
         i += blockDim.x * gridDim.x) {
        for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < width;
             j += blockDim.y * gridDim.y) {
            F zeroValue = F::load(inout, j * inputHeight + (i << 1));
            F oneValue = F::load(inout, j * inputHeight + (i << 1) + 1);
            // Compute value = zeroValue * (1 - alpha) + oneValue * alpha
            F value = alpha.interpolateLinear(oneValue, zeroValue);
            F::store(inout, j * outputHeight + i, value);
        }
    }
}

extern "C" void* mle_fix_last_variable_in_place_koala_bear_base() {
    return (void*)fixLastVariableInPlace<kb31_t>;
}

extern "C" void* mle_fix_last_variable_in_place_koala_bear_extension() {
    return (void*)fixLastVariableInPlace<kb31_extension_t>;
}

template <typename F, typename EF>
__global__ void
foldMle(const F* input, EF* __restrict__ output, EF beta, size_t outputHeight, size_t width) {
    size_t inputHeight = outputHeight << 1;
    for (size_t j = blockDim.y * blockIdx.y + threadIdx.y; j < width; j += blockDim.y * gridDim.y) {
        for (size_t i = blockDim.x * blockIdx.x + threadIdx.x; i < outputHeight;
             i += blockDim.x * gridDim.x) {
            F evenValue = F::load(input, j * inputHeight + (i << 1));
            F oddValue = F::load(input, j * inputHeight + (i << 1) + 1);
            EF value = beta * oddValue + evenValue;
            EF::store(output, j * outputHeight + i, value);
        }
    }
}

extern "C" void* mle_fold_koala_bear_base_base() { return (void*)foldMle<kb31_t, kb31_t>; }

extern "C" void* mle_fold_koala_bear_base_extension() {
    return (void*)foldMle<kb31_t, kb31_extension_t>;
}

extern "C" void* mle_fold_koala_bear_ext_ext() {
    return (void*)foldMle<kb31_extension_t, kb31_extension_t>;
}
