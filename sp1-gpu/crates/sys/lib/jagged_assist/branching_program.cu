#include "jagged_assist/branching_program.cuh"
#include "fields/kb31_extension_t.cuh"
#include "fields/kb31_t.cuh"
#include "challenger/challenger.cuh"
#include <cstdio>

// The points are stored in column major order.
template<typename F>
__device__ static inline F getIthLeastSignificantValFromPoints(
    const F *points,
    size_t dim,
    size_t point_idx,
    size_t num_points,
    size_t i)
{
    if (dim <= i) {
        return F::zero();
    } else {
        return points[(dim - i - 1) * num_points + point_idx];
    }
}

template<typename EF>
__device__ static inline EF getIthLeastSignificantVal(
    const EF *point,
    size_t dim,
    size_t i)
{
    if (dim <= i) {
        return EF::zero();
    } else {
        return point[dim - i - 1];
    }
}

template<typename F, typename EF>
__device__ static inline EF getPrefixSumValue(
    int lambda_layer_idx,
    EF lambda,
    Range prefix_sum_layer_idx_range,
    Range rho_layer_idx_range,
    int layer_idx,
    size_t column_idx,
    size_t num_columns,
    const F *prefix_sum,
    size_t prefix_sum_length,
    const EF *rho,
    size_t rho_length)
{
    if (layer_idx == lambda_layer_idx) {
        return lambda;
    } else if (prefix_sum_layer_idx_range.in_range(layer_idx)) {
        return EF(getIthLeastSignificantValFromPoints<F>(
            prefix_sum,
            prefix_sum_length,
            column_idx,
            num_columns,
            layer_idx
        ));
    } else if (rho_layer_idx_range.in_range(layer_idx)) {
        return getIthLeastSignificantVal<EF>(
            rho,
            rho_length,
            layer_idx
        );
    }

    assert(false);
}

template<typename F, typename EF>
__device__ void computePartialLagrange(
    EF point_0,
    EF point_1,
    EF point_2,
    EF point_3,
    EF *output) 
{

    EF point_0_vals[2] = {(EF::one() - point_0), point_0};
    // Memoize the two-variable eq.
    EF two_vals_memoized[4];
    for (uint8_t i = 0; i < 2; i++) {
        EF prod = point_0_vals[i] * point_1;
        two_vals_memoized[i * 2 + 1] = prod;
        two_vals_memoized[i * 2] = point_0_vals[i]-prod;
    }

    // Memoize three-variate eq.
    EF three_vals_memoized[8];
    for (uint8_t i = 0; i < 4; i++) {
        EF prod = two_vals_memoized[i] * point_2;
        three_vals_memoized[i * 2 + 1] = prod;
        three_vals_memoized[i * 2] = two_vals_memoized[i]-prod;
    }

    // Write the output values.
    for (uint8_t i = 0; i < 8; i++) {
        EF prod = three_vals_memoized[i] * point_3;
        output[i * 2 + 1] = prod;
        output[i * 2] = three_vals_memoized[i]-prod;
    }
}

template<typename F, typename EF>
__device__ static inline EF getEqVal(
    size_t lambda_idx,
    size_t column_idx,
    size_t num_columns,
    const F* current_prefix_sums,
    const F* next_prefix_sums,
    size_t prefix_sum_length,
    int curr_prefix_eq_val_least_sig_bit,
    int next_prefix_eq_val_least_sig_bit,
    EF half)
{
    if (lambda_idx == 1) {
        return half;
    }

    assert(lambda_idx == 0);

    if (curr_prefix_eq_val_least_sig_bit != -1) {
        return EF(F::one() - getIthLeastSignificantValFromPoints(
            current_prefix_sums,
            prefix_sum_length,
            column_idx,
            num_columns,
            curr_prefix_eq_val_least_sig_bit));
    }

    if (next_prefix_eq_val_least_sig_bit != -1) {
        return EF(F::one() - getIthLeastSignificantValFromPoints(
            next_prefix_sums,
            prefix_sum_length,
            column_idx,
            num_columns,
            next_prefix_eq_val_least_sig_bit));
    }

    assert(false);
}

template<typename F, typename EF, typename Challenger>
__global__ void interpolateAndObserve(
    const EF *results,
    Challenger challenger,
    EF *sampled_value,
    int8_t round_num,
    EF *sum_values,
    EF *round_claim  // device-resident: read current claim, write new claim
){
    if (blockIdx.x == 0 && threadIdx.x == 0 && blockIdx.y == 0 && threadIdx.y == 0) {
    EF y_0 = results[0];
    EF y_half = results[1];
    EF y_1 = round_claim[0] - y_0;

    sum_values[3*round_num + 0] = y_0;
    sum_values[3*round_num + 1] = y_half;
    sum_values[3*round_num + 2] = y_1;

    // Closed-form interpolation for fixed x-values (0, 1/2, 1):
    //   p(x) = c0 + c1*x + c2*x^2
    //   c0 = y_0
    //   c1 = -3*y_0 + 4*y_half - y_1
    //   c2 = 2*(y_0 + y_1) - 4*y_half
    EF c0 = y_0;
    EF sum_01 = y_0 + y_1;
    EF two_y_half = y_half + y_half;
    EF c2 = sum_01 + sum_01 - two_y_half - two_y_half;
    EF c1 = y_1 - y_0 - c2;

    challenger.observe_ext(&c0);
    challenger.observe_ext(&c1);
    challenger.observe_ext(&c2);

    EF alpha = challenger.sample_ext();
    sampled_value[0] = alpha;

    // Horner evaluation: p(alpha) = c0 + alpha*(c1 + alpha*c2)
    EF t(c2);
    t *= alpha;
    t += c1;
    t *= alpha;
    t += c0;
    round_claim[0] = t;
    }
}

template<typename F, typename EF>
__global__ void fixLastVariable(
    F *merged_prefix_sums,
    EF *intermediate_eq_full_evals,
    EF *rho,
    size_t merged_prefix_sum_dim,
    size_t num_columns,
    size_t round_num,
    size_t randomness_point_length

)
{

    EF alpha = rho[0];

   for (size_t column_idx = blockDim.x * blockIdx.x + threadIdx.x; column_idx < num_columns; column_idx += blockDim.x * gridDim.x)
    {

        if (column_idx >= num_columns){
            return;
        }
        F value = merged_prefix_sums[ column_idx * merged_prefix_sum_dim + merged_prefix_sum_dim - 1 - round_num];

        // EF new_value = alpha * EF(value) + (EF::one() - alpha) * (EF::one() - EF(value));

        EF v(value);
        EF new_value = alpha * v;
        new_value += new_value;
        new_value -= alpha;
        new_value -= v;
        new_value += EF::one();

        intermediate_eq_full_evals[column_idx] *= new_value;
    }
}

template<typename F, typename EF>
__global__ void branchingProgram(
    // The prefix sums.  The current and next prefix sums must be the same length.
    // Note that the number of layers is prefix_sum_length.
    const F *current_prefix_sums,
    const F *next_prefix_sums,
    size_t prefix_sum_length,

    // The z_row and z_index points.
    const EF *z_row,
    size_t z_row_length,
    const EF *z_index,
    size_t z_index_length,

    // The rho values that is set from sumcheck's fix_last_point.
    const EF *current_prefix_sum_rho,
    size_t current_prefix_sum_rho_length,
    const EF *next_prefix_sum_rho,
    size_t next_prefix_sum_rho_length,

    // The total number of columns.
    size_t num_columns,

    // The sumcheck round number.  If this is -1, then that means that none of the prefix sums values
    // should be substituted with the rho or lambda values.
    int8_t round_num,

    // The lambda points.
    const EF *lambdas,

    // The z_col_eq_vals.  This has length num_columns.
    const EF *z_col_eq_vals,

    // The intermediate_eq_full_evals.  This has length num_columns.
    const EF *intermediate_eq_full_evals,

    // The output.
    EF *__restrict__ output

)
{
    int num_layers = static_cast<int>(max(z_index_length, z_row_length)) + 1;

    int curr_prefix_sum_lambda_layer_idx;
    int next_prefix_sum_lambda_layer_idx;
    Range curr_rho_layer_idx_range;
    Range next_rho_layer_idx_range;
    Range curr_prefix_sum_layer_idx_range;
    Range next_prefix_sum_layer_idx_range;
    int curr_prefix_eq_val_least_sig_bit;
    int next_prefix_eq_val_least_sig_bit;

    if (round_num == -1) {
        curr_prefix_eq_val_least_sig_bit = -1;
        next_prefix_eq_val_least_sig_bit = -1;
        curr_prefix_sum_lambda_layer_idx = -1;
        next_prefix_sum_lambda_layer_idx = -1;
        curr_rho_layer_idx_range = Range{-1, -1};
        next_rho_layer_idx_range = Range{-1, -1};
        curr_prefix_sum_layer_idx_range = Range{0, num_layers};
        next_prefix_sum_layer_idx_range = Range{0, num_layers};
    } else if (round_num < prefix_sum_length) {
        curr_prefix_eq_val_least_sig_bit = -1;
        next_prefix_eq_val_least_sig_bit = round_num;
        curr_prefix_sum_lambda_layer_idx = -1;
        next_prefix_sum_lambda_layer_idx = round_num;
        curr_rho_layer_idx_range = Range{-1, -1};
        next_rho_layer_idx_range = Range{0, next_prefix_sum_lambda_layer_idx};
        curr_prefix_sum_layer_idx_range = Range{0, num_layers};
        next_prefix_sum_layer_idx_range = Range{next_prefix_sum_lambda_layer_idx + 1, num_layers};
    } else {  // round_num >= prefix_sum_length
        curr_prefix_eq_val_least_sig_bit = round_num - prefix_sum_length;
        next_prefix_eq_val_least_sig_bit = -1;
        curr_prefix_sum_lambda_layer_idx = round_num - prefix_sum_length;
        next_prefix_sum_lambda_layer_idx = -1;
        curr_rho_layer_idx_range = Range{0, curr_prefix_sum_lambda_layer_idx};
        next_rho_layer_idx_range = Range{0, num_layers};
        curr_prefix_sum_layer_idx_range = Range{curr_prefix_sum_lambda_layer_idx + 1, num_layers};
        next_prefix_sum_layer_idx_range = Range{-1, -1};
    }

    for (size_t column_idx = blockDim.x * blockIdx.x + threadIdx.x; column_idx < num_columns; column_idx += blockDim.x * gridDim.x)
    {
        for (size_t lambda_idx = blockDim.y * blockIdx.y + threadIdx.y; lambda_idx < 2; lambda_idx += blockDim.y * gridDim.y) {
            EF lambda = lambdas[lambda_idx];
            EF state_by_state_results[MEMORY_STATE_COUNT] = {EF::zero(), EF::zero(), EF::zero(), EF::zero(), EF::zero()};
            state_by_state_results[SUCCESS_STATE] = EF::one();

            for (int layer_idx = num_layers - 1; layer_idx >= 0; layer_idx--)
            {
                EF partial_lagrange[16];

                EF point[4] = {
                    getIthLeastSignificantVal<EF>(z_row, z_row_length, layer_idx),
                    getIthLeastSignificantVal<EF>(z_index, z_index_length, layer_idx),
                    getPrefixSumValue<F, EF>(
                        curr_prefix_sum_lambda_layer_idx,
                        lambda,
                        curr_prefix_sum_layer_idx_range,
                        curr_rho_layer_idx_range,
                        layer_idx,
                        column_idx,
                        num_columns,
                        current_prefix_sums,
                        prefix_sum_length,
                        current_prefix_sum_rho,
                        current_prefix_sum_rho_length
                    ),
                    getPrefixSumValue<F, EF>(
                        next_prefix_sum_lambda_layer_idx,
                        lambda,
                        next_prefix_sum_layer_idx_range,
                        next_rho_layer_idx_range,
                        layer_idx,
                        column_idx,
                        num_columns,
                        next_prefix_sums,
                        prefix_sum_length,
                        next_prefix_sum_rho,
                        next_prefix_sum_rho_length
                    ),
                };

                computePartialLagrange<F, EF>(
                    point[0],
                    point[1],
                    point[2],
                    point[3],
                    partial_lagrange
                );

                EF new_state_by_state_results[MEMORY_STATE_COUNT] = {EF::zero(), EF::zero(), EF::zero(), EF::zero(), EF::zero()};

                #pragma unroll
                for (int input_memory_state = 0; input_memory_state < MEMORY_STATE_COUNT; input_memory_state++) {
                    if (input_memory_state == FAIL) {
                        continue;
                    }

                    EF accum_elems[MEMORY_STATE_COUNT] = {EF::zero(), EF::zero(), EF::zero(), EF::zero(), EF::zero()};
                    #pragma unroll
                    for (size_t bit_state = 0; bit_state < BIT_STATE_COUNT; bit_state++) {
                        EF value = partial_lagrange[bit_state];
                        MemoryState output_memory_state = TRANSITIONS[bit_state][input_memory_state];
                        if (output_memory_state != FAIL) {
                            accum_elems[output_memory_state] += value;
                        }
                    }

                    EF accum = EF::zero();
                    #pragma unroll
                    for (int output_memory_state = 0; output_memory_state < MEMORY_STATE_COUNT; output_memory_state++) {
                        accum += accum_elems[output_memory_state] * state_by_state_results[output_memory_state];
                    }

                    new_state_by_state_results[input_memory_state] = accum;
                }

                #pragma unroll
                for (int i = 0; i < MEMORY_STATE_COUNT; i++) {
                    state_by_state_results[i] = new_state_by_state_results[i];
                }
            }

            if (round_num != -1) {
                EF eq_eval = getEqVal<F, EF>(
                    lambda_idx,
                    column_idx,
                    num_columns,
                    current_prefix_sums,
                    next_prefix_sums,
                    prefix_sum_length,
                    curr_prefix_eq_val_least_sig_bit,
                    next_prefix_eq_val_least_sig_bit,
                    lambdas[1]) * intermediate_eq_full_evals[column_idx];
                EF z_col_eq_val = z_col_eq_vals[column_idx];
                EF::store(output, lambda_idx * num_columns + column_idx, state_by_state_results[INITIAL_MEMORY_STATE] * z_col_eq_val * eq_eval);
            } else {
                EF::store(output, lambda_idx * num_columns + column_idx, state_by_state_results[INITIAL_MEMORY_STATE]);
            }
        }
    }
}

// ============================================================================
// Width-8 interleaved branching program kernels (precomputed prefix states)
// ============================================================================

/// Compute the 3-variable partial Lagrange basis (8 entries) for variables (a, b, c).
/// Output indices follow: index = (a_bit << 2) | (b_bit << 1) | c_bit
template<typename EF>
__device__ void computeThreeVarPartialLagrange(EF a, EF b, EF c, EF *output) {
    EF a_vals[2] = {EF::one() - a, a};
    EF ab_vals[4];
    for (int i = 0; i < 2; i++) {
        EF prod = a_vals[i] * b;
        ab_vals[i * 2 + 1] = prod;
        ab_vals[i * 2] = a_vals[i] - prod;
    }
    for (int i = 0; i < 4; i++) {
        EF prod = ab_vals[i] * c;
        output[i * 2 + 1] = prod;
        output[i * 2] = ab_vals[i] - prod;
    }
}

/// Compute the 1-variable partial Lagrange basis (2 entries) for variable a.
template<typename EF>
__device__ void computeOneVarPartialLagrange(EF a, EF *output) {
    output[0] = EF::one() - a;
    output[1] = a;
}

/// Precompute prefix states for all columns via backward DP through all layers.
///
/// Layout: prefix_states[(layer * WIDE_BP_WIDTH + state) * num_columns + col]
/// Stores (num_layers+1) layers, where layer num_layers is the success initialization.
template<typename F, typename EF>
__global__ void precomputePrefixStates(
    const F *current_prefix_sums,  // [prefix_sum_length, num_columns] col-major
    const F *next_prefix_sums,     // [prefix_sum_length, num_columns] col-major
    size_t prefix_sum_length,
    const EF *z_row, size_t z_row_length,
    const EF *z_index, size_t z_index_length,
    size_t num_columns,
    EF *prefix_states  // [(num_layers+1) * WIDE_BP_WIDTH * num_columns]
) {
    size_t num_layers = 2 * (max(z_row_length, z_index_length) + 1);

    for (size_t col = blockDim.x * blockIdx.x + threadIdx.x; col < num_columns; col += blockDim.x * gridDim.x) {
        // Initialize success states at layer num_layers
        for (int s = 0; s < WIDE_BP_WIDTH; s++) {
            EF val = (s == WIDE_SUCCESS_STATE_0 || s == WIDE_SUCCESS_STATE_1) ? EF::one() : EF::zero();
            prefix_states[(num_layers * WIDE_BP_WIDTH + s) * num_columns + col] = val;
        }

        EF state[8];
        for (int s = 0; s < WIDE_BP_WIDTH; s++) {
            state[s] = (s == WIDE_SUCCESS_STATE_0 || s == WIDE_SUCCESS_STATE_1) ? EF::one() : EF::zero();
        }

        // Backward DP
        for (int layer = static_cast<int>(num_layers) - 1; layer >= 0; layer--) {
            int k = layer / 2;
            EF new_state[8];
            for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                new_state[s] = EF::zero();
            }

            if (layer % 2 == 0) {
                // Even layer: reads z_row[k], z_index[k], curr_prefix_sum[k]
                EF z_row_val = getIthLeastSignificantVal<EF>(z_row, z_row_length, k);
                EF z_index_val = getIthLeastSignificantVal<EF>(z_index, z_index_length, k);
                EF curr_ps_val = EF(getIthLeastSignificantValFromPoints<F>(
                    current_prefix_sums, prefix_sum_length, col, num_columns, k));

                EF three_var_eq[8];
                // Layout: (curr_ps_bit << 2) | (index_bit << 1) | row_bit
                // to match CURR_TRANSITIONS_W8 bit state indexing.
                computeThreeVarPartialLagrange<EF>(curr_ps_val, z_index_val, z_row_val, three_var_eq);

                for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
                    EF accum_elems[8];
                    for (int s = 0; s < WIDE_BP_WIDTH; s++) accum_elems[s] = EF::zero();

                    for (int bs = 0; bs < 8; bs++) {
                        uint8_t out_ms = CURR_TRANSITIONS_W8[bs][ms];
                        if (out_ms != WIDE_FAIL) {
                            accum_elems[out_ms] += three_var_eq[bs];
                        }
                    }

                    EF accum = EF::zero();
                    for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                        accum += accum_elems[s] * state[s];
                    }
                    new_state[ms] = accum;
                }
            } else {
                // Odd layer: reads next_prefix_sum[k]
                EF next_ps_val = EF(getIthLeastSignificantValFromPoints<F>(
                    next_prefix_sums, prefix_sum_length, col, num_columns, k));

                EF one_var_eq[2];
                computeOneVarPartialLagrange<EF>(next_ps_val, one_var_eq);

                for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
                    EF accum_elems[8];
                    for (int s = 0; s < WIDE_BP_WIDTH; s++) accum_elems[s] = EF::zero();

                    for (int bs = 0; bs < 2; bs++) {
                        uint8_t out_ms = NEXT_TRANSITIONS_W8[bs][ms];
                        // Next transitions never fail
                        accum_elems[out_ms] += one_var_eq[bs];
                    }

                    EF accum = EF::zero();
                    for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                        accum += accum_elems[s] * state[s];
                    }
                    new_state[ms] = accum;
                }
            }

            for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                state[s] = new_state[s];
                prefix_states[(layer * WIDE_BP_WIDTH + s) * num_columns + col] = new_state[s];
            }
        }
    }
}

/// Evaluate the branching program at lambda=0 and lambda=1/2 using cached prefix states.
///
/// Each thread processes one column. Uses precomputed prefix_states at (round_num+1) and
/// applies a single layer step for lambda=0 and lambda=1/2, then dots with suffix_vector.
template<typename F, typename EF>
__global__ void evalWithCachedAtZeroAndHalf(
    const EF *prefix_states,       // [(num_layers+1) * 8 * num_columns]
    const EF *suffix_vector,       // [8] elements
    const EF *z_row, size_t z_row_length,
    const EF *z_index, size_t z_index_length,
    const F *current_prefix_sums,
    const F *next_prefix_sums,
    size_t prefix_sum_length,
    const EF *z_col_eq_vals,
    const EF *intermediate_eq_full_evals,
    size_t num_columns,
    size_t round_num,
    EF half,
    EF *output  // [2 * num_columns]: [y_0_values..., y_half_values...]
) {
    size_t layer = round_num;
    int k = static_cast<int>(layer / 2);

    for (size_t col = blockDim.x * blockIdx.x + threadIdx.x; col < num_columns; col += blockDim.x * gridDim.x) {
        // Load prefix state at layer+1 (8 values)
        EF pstate[8];
        for (int s = 0; s < WIDE_BP_WIDTH; s++) {
            pstate[s] = prefix_states[((layer + 1) * WIDE_BP_WIDTH + s) * num_columns + col];
        }

        // Load suffix vector
        EF suffix[8];
        for (int s = 0; s < WIDE_BP_WIDTH; s++) {
            suffix[s] = suffix_vector[s];
        }

        EF y_0_result;
        EF y_half_result;

        if (layer % 2 == 0) {
            // Even layer: z_row[k], z_index[k], curr_ps[k]
            EF z_row_val = getIthLeastSignificantVal<EF>(z_row, z_row_length, k);
            EF z_index_val = getIthLeastSignificantVal<EF>(z_index, z_index_length, k);

            // === At zero: only curr_ps=0 bit states contribute ===
            // two_var_eq index layout: (index_bit << 1) | row_bit
            // to match CURR_TRANSITIONS_W8[0..3] = (0 << 2) | (index_bit << 1) | row_bit
            EF two_var_eq[4];
            {
                EF a_vals[2] = {EF::one() - z_index_val, z_index_val};
                for (int i = 0; i < 2; i++) {
                    EF prod = a_vals[i] * z_row_val;
                    two_var_eq[i * 2 + 1] = prod;
                    two_var_eq[i * 2] = a_vals[i] - prod;
                }
            }

            EF after_zero[8];
            for (int s = 0; s < WIDE_BP_WIDTH; s++) after_zero[s] = EF::zero();

            for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
                EF accum_elems[8];
                for (int s = 0; s < WIDE_BP_WIDTH; s++) accum_elems[s] = EF::zero();

                // curr_ps=0 bit states: indices 0..3 in CURR_TRANSITIONS_W8
                // half_i = (index_bit << 1) | row_bit, matching two_var_eq layout
                for (int half_i = 0; half_i < 4; half_i++) {
                    uint8_t out_ms = CURR_TRANSITIONS_W8[half_i][ms];
                    if (out_ms != WIDE_FAIL) {
                        accum_elems[out_ms] += two_var_eq[half_i];
                    }
                }

                EF accum = EF::zero();
                for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                    accum += accum_elems[s] * pstate[s];
                }
                after_zero[ms] = accum;
            }

            y_0_result = EF::zero();
            for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                y_0_result += after_zero[s] * suffix[s];
            }

            // === At half: both curr_ps=0 and curr_ps=1 contribute, multiply by half ===
            EF after_half[8];
            for (int s = 0; s < WIDE_BP_WIDTH; s++) after_half[s] = EF::zero();

            for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
                EF accum_elems[8];
                for (int s = 0; s < WIDE_BP_WIDTH; s++) accum_elems[s] = EF::zero();

                for (int half_i = 0; half_i < 4; half_i++) {
                    // Both bit=0 and bit=1 for curr_ps
                    for (int bit = 0; bit < 2; bit++) {
                        int bs = (bit << 2) | half_i;
                        uint8_t out_ms = CURR_TRANSITIONS_W8[bs][ms];
                        if (out_ms != WIDE_FAIL) {
                            accum_elems[out_ms] += two_var_eq[half_i];
                        }
                    }
                }

                EF accum = EF::zero();
                for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                    accum += accum_elems[s] * pstate[s];
                }
                after_half[ms] = accum * half;
            }

            y_half_result = EF::zero();
            for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                y_half_result += after_half[s] * suffix[s];
            }
        } else {
            // Odd layer: next_prefix_sum[k]

            // === At zero: only next_ps_bit=0 contributes with weight 1 ===
            EF after_zero[8];
            for (int s = 0; s < WIDE_BP_WIDTH; s++) after_zero[s] = EF::zero();

            for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
                uint8_t out_ms = NEXT_TRANSITIONS_W8[0][ms];
                after_zero[ms] = pstate[out_ms];
            }

            y_0_result = EF::zero();
            for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                y_0_result += after_zero[s] * suffix[s];
            }

            // === At half: both bits contribute, multiply by half ===
            EF after_half[8];
            for (int s = 0; s < WIDE_BP_WIDTH; s++) after_half[s] = EF::zero();

            for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
                EF accum_elems[8];
                for (int s = 0; s < WIDE_BP_WIDTH; s++) accum_elems[s] = EF::zero();

                for (int bit = 0; bit < 2; bit++) {
                    uint8_t out_ms = NEXT_TRANSITIONS_W8[bit][ms];
                    accum_elems[out_ms] += EF::one();
                }

                EF accum = EF::zero();
                for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                    accum += accum_elems[s] * pstate[s];
                }
                after_half[ms] = accum * half;
            }

            y_half_result = EF::zero();
            for (int s = 0; s < WIDE_BP_WIDTH; s++) {
                y_half_result += after_half[s] * suffix[s];
            }
        }

        // Multiply by eq_eval and z_col_eq_val
        // eq_eval for lambda=0: (1 - prefix_sum_val_at_round)
        // eq_eval for lambda=1/2: half
        EF eq_zero;
        EF eq_half = half;

        // Access the k-th least-significant bit of the relevant prefix sum.
        // Even layers use current_prefix_sums, odd layers use next_prefix_sums.
        if (layer % 2 == 0) {
            // curr prefix sum value
            EF ps_val = EF(getIthLeastSignificantValFromPoints<F>(
                current_prefix_sums, prefix_sum_length, col, num_columns, k));
            eq_zero = EF::one() - ps_val;
        } else {
            EF ps_val = EF(getIthLeastSignificantValFromPoints<F>(
                next_prefix_sums, prefix_sum_length, col, num_columns, k));
            eq_zero = EF::one() - ps_val;
        }

        EF z_col_eq_val = z_col_eq_vals[col];
        EF intermed = intermediate_eq_full_evals[col];

        EF::store(output, col, y_0_result * z_col_eq_val * eq_zero * intermed);
        EF::store(output, num_columns + col, y_half_result * z_col_eq_val * eq_half * intermed);
    }
}

/// Update the suffix vector in-place on device after sampling alpha.
///
/// This is the transposed DP step: for each old state s, pushes weighted
/// contributions to output states t = transition(s, b).
template<typename F, typename EF>
__global__ void updateSuffixVector(
    EF *suffix_vector,     // [8], modified in-place
    const EF *alpha_ptr,   // [1], sampled value from interpolateAndObserve
    const EF *z_row, size_t z_row_length,
    const EF *z_index, size_t z_index_length,
    const F *current_prefix_sums,
    const F *next_prefix_sums,
    size_t prefix_sum_length,
    size_t num_columns,
    size_t round_num,
    size_t num_layers
) {
    if (blockIdx.x != 0 || threadIdx.x != 0) return;

    EF alpha = alpha_ptr[0];
    size_t layer = round_num;
    int k = static_cast<int>(layer / 2);

    EF suffix[8];
    for (int s = 0; s < WIDE_BP_WIDTH; s++) {
        suffix[s] = suffix_vector[s];
    }

    EF result[8];
    for (int s = 0; s < WIDE_BP_WIDTH; s++) {
        result[s] = EF::zero();
    }

    if (layer % 2 == 0) {
        // Even layer: transposed step with 3-var eq from (z_row[k], z_index[k], alpha)
        EF z_row_val = getIthLeastSignificantVal<EF>(z_row, z_row_length, k);
        EF z_index_val = getIthLeastSignificantVal<EF>(z_index, z_index_length, k);

        EF three_var_eq[8];
        // Layout: (alpha_bit << 2) | (index_bit << 1) | row_bit
        // to match CURR_TRANSITIONS_W8 bit state indexing (alpha replaces curr_ps).
        computeThreeVarPartialLagrange<EF>(alpha, z_index_val, z_row_val, three_var_eq);

        for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
            for (int bs = 0; bs < 8; bs++) {
                uint8_t out_ms = CURR_TRANSITIONS_W8[bs][ms];
                if (out_ms != WIDE_FAIL) {
                    result[out_ms] += suffix[ms] * three_var_eq[bs];
                }
            }
        }
    } else {
        // Odd layer: transposed step with 1-var eq from alpha
        EF one_var_eq[2];
        computeOneVarPartialLagrange<EF>(alpha, one_var_eq);

        for (int ms = 0; ms < WIDE_BP_WIDTH; ms++) {
            for (int bs = 0; bs < 2; bs++) {
                uint8_t out_ms = NEXT_TRANSITIONS_W8[bs][ms];
                result[out_ms] += suffix[ms] * one_var_eq[bs];
            }
        }
    }

    for (int s = 0; s < WIDE_BP_WIDTH; s++) {
        suffix_vector[s] = result[s];
    }
}

__global__ void transition(
    size_t *__restrict__ output
) {
    for (size_t bit_state = 0; bit_state < BIT_STATE_COUNT; bit_state++) {
        for (size_t output_memory_state = 0; output_memory_state < MEMORY_STATE_COUNT; output_memory_state++) {
            output[bit_state * MEMORY_STATE_COUNT + output_memory_state] = TRANSITIONS[bit_state][output_memory_state];
        }
    }
}

// Output the width-8 transition tables: CURR_TRANSITIONS_W8[8][8] followed by NEXT_TRANSITIONS_W8[2][8].
// Total output: (8*8 + 2*8) = 80 entries as size_t.
template<typename F, typename EF>
__global__ void transition_w8(
    size_t *__restrict__ output
) {
    size_t idx = 0;
    for (size_t bs = 0; bs < 8; bs++) {
        for (size_t ms = 0; ms < WIDE_BP_WIDTH; ms++) {
            output[idx++] = CURR_TRANSITIONS_W8[bs][ms];
        }
    }
    for (size_t bs = 0; bs < 2; bs++) {
        for (size_t ms = 0; ms < WIDE_BP_WIDTH; ms++) {
            output[idx++] = NEXT_TRANSITIONS_W8[bs][ms];
        }
    }
}

extern "C" void *branching_program_kernel()
{
    return (void *)branchingProgram<kb31_t, kb31_extension_t>;
}


extern "C" void *transition_kernel()
{
    return (void *)transition<kb31_t, kb31_extension_t>;
}

extern "C" void *transition_w8_kernel()
{
    return (void *)transition_w8<kb31_t, kb31_extension_t>;
}


extern "C" void *interpolateAndObserve_kernel_duplex()
{
    return (void *)interpolateAndObserve<kb31_t, kb31_extension_t, DuplexChallenger>;
}

extern "C" void *interpolateAndObserve_kernel_multi_field_32()
{
    return (void *)interpolateAndObserve<kb31_t, kb31_extension_t, MultiField32Challenger>;
}

extern "C" void *fixLastVariable_kernel()
{
    return (void *)fixLastVariable<kb31_t, kb31_extension_t>;
}

extern "C" void *precomputePrefixStates_kernel()
{
    return (void *)precomputePrefixStates<kb31_t, kb31_extension_t>;
}

extern "C" void *evalWithCachedAtZeroAndHalf_kernel()
{
    return (void *)evalWithCachedAtZeroAndHalf<kb31_t, kb31_extension_t>;
}

extern "C" void *updateSuffixVector_kernel()
{
    return (void *)updateSuffixVector<kb31_t, kb31_extension_t>;
}
