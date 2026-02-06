//! This module contains the implementation of the special multilinear polynomial appearing in the
//! jagged sumcheck protocol.
//!
//! More precisely, given a collection of L columns with heights [a_1, a_2, ..., a_L] lay out those
//! tables in a 2D array, aligning their first entries at the top row of the array. Then,
//! imagine padding all the columns with zeroes so that they have the same number of rows. On the
//! other hand, imagine laying out all the columns in a single long vector. The jagged multilinear
//! polynomial is the multilinear extension of the function which determines, given row and column
//! indices r and c in the 2D array, and an index i in the long vector, whether entry (r, c)
//! in the 2D array corresponds to entry i in the long vector.
//!
//! Since there is an efficient algorithm to implement this "indicator" function as a branching
//! program, following [HR18](https://eccc.weizmann.ac.il/report/2018/161/) there is a concise
//! algorithm for the evaluation of the corresponding multilinear polynomial. The algorithm to
//! compute the indicator uses the prefix sums [t_0=0, t_1=a_1, t_2 = a_1+a_2, ..., t_L], reads
//! t_{c}, t_{c+1}, i, r bit-by-bit from LSB to MSB, checks the equality
//!
//! i = t_c + r.
//!
//! and also checks that i < t_{c+1}. The addition is checked via the grade-school algorithm. This
//! is for a fixed column c. To check over all the columns, we combine via a random linear
//! combination with coefficients eq(z_col, _).
use core::fmt;
use std::{array, cmp::max, iter::once};

use rayon::prelude::*;

use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, Field};
use slop_utils::log2_ceil_usize;

use slop_multilinear::{Mle, Point};

/// A struct recording the state of the memory of the branching program. Because the program
/// performs a two-way addition and one u32 comparison, the memory needed is a carry (which lies in
/// {0,1}) and a boolean to store the comparison of the u32s up to the current bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemoryState {
    pub carry: bool,

    pub comparison_so_far: bool,
}

impl fmt::Display for MemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "COMPARISON_SO_FAR_{}__CARRY_{}",
            self.comparison_so_far as usize, self.carry as usize
        )
    }
}

impl MemoryState {
    pub fn get_index(&self) -> usize {
        (self.carry as usize) + ((self.comparison_so_far as usize) << 1)
    }
}

impl MemoryState {
    /// The memory state which indicates success in the last layer of the branching program.
    fn success() -> Self {
        MemoryState { carry: false, comparison_so_far: true }
    }

    fn initial_state() -> Self {
        MemoryState { carry: false, comparison_so_far: false }
    }
}

/// An enum to represent a potentially failed computation at a layer of the branching program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StateOrFail {
    State(MemoryState),
    Fail,
}

impl fmt::Display for StateOrFail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateOrFail::State(memory_state) => write!(f, "{memory_state}"),
            StateOrFail::Fail => write!(f, "FAIL"),
        }
    }
}

/// A struct representing the four bits the branching program needs to read in order to go to the
/// next layer of the program. The program streams the bits of the row, column, index, and the
/// "table area prefix sum".
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BitState<T> {
    pub row_bit: T,
    pub index_bit: T,
    pub curr_col_prefix_sum_bit: T,
    pub next_col_prefix_sum_bit: T,
}

/// Enumerate all the possible memory states.
pub fn all_memory_states() -> Vec<MemoryState> {
    (0..2)
        .flat_map(|comparison_so_far| {
            (0..2).map(move |carry| MemoryState {
                carry: carry != 0,
                comparison_so_far: comparison_so_far != 0,
            })
        })
        .collect()
}

/// Enumerate all the possible bit states.
pub fn all_bit_states() -> Vec<BitState<bool>> {
    (0..2)
        .flat_map(|row_bit| {
            (0..2).flat_map(move |index_bit| {
                (0..2).flat_map(move |curr_col_bit| {
                    (0..2).map(move |next_col_bit| BitState {
                        row_bit: row_bit != 0,
                        index_bit: index_bit != 0,
                        curr_col_prefix_sum_bit: curr_col_bit != 0,
                        next_col_prefix_sum_bit: next_col_bit != 0,
                    })
                })
            })
        })
        .collect()
}

/// The transition function that determines the next memory state given the current memory state and
/// the current bits being read. The branching program reads bits from LSB to MSB.
pub fn transition_function(bit_state: BitState<bool>, memory_state: MemoryState) -> StateOrFail {
    // If the current (most significant bit read so far) index_bit matches the current next_tab_bit,
    // then defer to the comparison so far. Otherwise, the comparison is correct only if
    // `next_tab_bit` is 1 and `index_bit` is 0.
    let new_comparison_so_far = if bit_state.index_bit == bit_state.next_col_prefix_sum_bit {
        memory_state.comparison_so_far
    } else {
        bit_state.next_col_prefix_sum_bit
    };

    // Compute the carry according to the logic of three-way addition, or fail if the current bits
    // are not consistent with the three-way addition.
    //
    // However, we are checking that index = curr_tab + row * (1<<log_column_count) + col, so we
    // need to read the row bit only if the layer is after log_column_count.
    let new_carry = {
        if (bit_state.index_bit as usize)
            != ((bit_state.row_bit as usize)
                + Into::<usize>::into(memory_state.carry)
                + bit_state.curr_col_prefix_sum_bit as usize)
                & 1
        {
            return StateOrFail::Fail;
        }
        (bit_state.row_bit as usize
            + Into::<usize>::into(memory_state.carry)
            + bit_state.curr_col_prefix_sum_bit as usize)
            >> 1
    };
    // Successful transition.
    StateOrFail::State(MemoryState {
        carry: new_carry != 0,
        comparison_so_far: new_comparison_so_far,
    })
}

/// A struct to hold all the parameters sufficient to determine the special multilinear polynopmial
/// appearing in the jagged sumcheck protocol.
#[derive(Clone, Debug)]
pub struct JaggedLittlePolynomialProverParams {
    pub col_prefix_sums_usize: Vec<usize>,
    pub(crate) max_log_row_count: usize,
}

/// A struct to hold all the parameters sufficient to determine the special multilinear polynopmial
/// appearing in the jagged sumcheck protocol. All usize parameters are intended to be inferred from
/// the proving context, while the `Vec<Point<K>>` fields are intended to be recieved directly from
/// the prover as field elements. The verifier program thus depends only on the usize parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JaggedLittlePolynomialVerifierParams<K> {
    pub col_prefix_sums: Vec<Point<K>>,
}

impl<F: AbstractField + 'static + Send + Sync> JaggedLittlePolynomialVerifierParams<F> {
    /// Given `z_index`, evaluate the special multilinear polynomial appearing in the jagged
    /// sumcheck protocol.
    pub fn full_jagged_little_polynomial_evaluation<
        EF: AbstractExtensionField<F> + 'static + Send + Sync,
    >(
        &self,
        z_row: &Point<EF>,
        z_col: &Point<EF>,
        z_index: &Point<EF>,
    ) -> EF {
        let z_col_partial_lagrange = Mle::blocking_partial_lagrange(z_col);
        let z_col_partial_lagrange = z_col_partial_lagrange.guts().as_slice();

        let branching_program = BranchingProgram::new(z_row.clone(), z_index.clone());

        // Iterate over all columns. For each column, we need to know the total length of all the
        // columns up to the current one, this number - 1, and the
        // number of rows in the current column.
        let mut branching_program_evals = Vec::with_capacity(self.col_prefix_sums.len() - 1);
        #[allow(clippy::uninit_vec)]
        unsafe {
            branching_program_evals.set_len(self.col_prefix_sums.len() - 1);
        }
        let next_col_prefix_sums = self.col_prefix_sums.iter().skip(1);
        let res = self
            .col_prefix_sums
            .iter()
            .zip(next_col_prefix_sums)
            .zip(branching_program_evals.iter_mut())
            .enumerate()
            .par_bridge()
            .map(|(col_num, ((prefix_sum, next_prefix_sum), branching_program_eval))| {
                // For `z_col` on the Boolean hypercube, this is the delta function to pick out
                // the right column for the current index.
                let z_col_correction = z_col_partial_lagrange[col_num].clone();

                let prefix_sum_ef =
                    prefix_sum.iter().map(|x| EF::from(x.clone())).collect::<Point<EF>>();
                let next_prefix_sum_ef =
                    next_prefix_sum.iter().map(|x| EF::from(x.clone())).collect::<Point<EF>>();
                *branching_program_eval =
                    branching_program.eval(&prefix_sum_ef, &next_prefix_sum_ef);

                z_col_correction.clone() * branching_program_eval.clone()
            })
            .sum::<EF>();

        res
    }
}

impl JaggedLittlePolynomialProverParams {
    pub fn new(row_counts_usize: Vec<usize>, max_log_row_count: usize) -> Self {
        let mut prefix_sums_usize = row_counts_usize
            .iter()
            .scan(0, |state, row_count| {
                let result = *state;
                *state += row_count;
                Some(result)
            })
            .collect::<Vec<_>>();

        prefix_sums_usize
            .push(*prefix_sums_usize.last().unwrap() + row_counts_usize.last().unwrap());

        JaggedLittlePolynomialProverParams {
            col_prefix_sums_usize: prefix_sums_usize,
            max_log_row_count,
        }
    }

    /// Compute the "guts" of the multilinear polynomial represented by the fixed prover parameters.
    pub fn partial_jagged_little_polynomial_evaluation<K: Field>(
        &self,
        z_row: &Point<K>,
        z_col: &Point<K>,
    ) -> Mle<K> {
        let log_total_area = log2_ceil_usize(*self.col_prefix_sums_usize.last().unwrap());
        let total_area = 1 << log_total_area;

        let col_eq = Mle::blocking_partial_lagrange(
            &z_col.last_k(log2_ceil_usize(self.col_prefix_sums_usize.len() - 1)),
        );
        let row_eq = Mle::blocking_partial_lagrange(&z_row.last_k(self.max_log_row_count));

        let mut result: Vec<K> = Vec::with_capacity(total_area);

        #[allow(clippy::uninit_vec)]
        unsafe {
            result.set_len(total_area);
        }

        let col_ranges = ColRanges::new(&self.col_prefix_sums_usize, total_area);

        let result_chunk_size = max(total_area / num_cpus::get(), 1);
        tracing::debug_span!("compute jagged values").in_scope(|| {
            (result.chunks_mut(result_chunk_size).enumerate().par_bridge()).for_each(
                |(chunk_idx, chunk)| {
                    let i = chunk_idx * result_chunk_size;
                    let mut col_range_iter = col_ranges.get_col_range(i).peekable();
                    let mut current_col_range = col_range_iter.next().unwrap();
                    let mut current_row = i - current_col_range.start_i;

                    chunk.iter_mut().for_each(|val| {
                        *val = if current_col_range.is_last {
                            K::zero()
                        } else {
                            col_eq.guts().as_slice()[current_col_range.col_idx]
                                * row_eq.guts().as_slice()[current_row]
                        };

                        current_row += 1;
                        while current_row == current_col_range.col_size {
                            if col_range_iter.peek().is_none() {
                                break;
                            }
                            current_col_range = col_range_iter.next().unwrap();
                            current_row = 0;
                        }
                    });
                },
            );
        });

        result.into()
    }

    /// Convert the prover parameters into verifier parameters so that the verifier can run its
    /// evaluation algorithm.
    pub fn into_verifier_params<K: Field>(self) -> JaggedLittlePolynomialVerifierParams<K> {
        let log_m = log2_ceil_usize(*self.col_prefix_sums_usize.last().unwrap());
        let col_prefix_sums =
            self.col_prefix_sums_usize.iter().map(|&x| Point::from_usize(x, log_m + 1)).collect();
        JaggedLittlePolynomialVerifierParams { col_prefix_sums }
    }
}

#[derive(Debug, Clone, Copy)]
struct ColRange {
    col_idx: usize,
    start_i: usize,
    end_i: usize,
    col_size: usize,
    is_last: bool,
}

impl ColRange {
    #[inline]
    fn in_range(&self, i: usize) -> bool {
        i >= self.start_i && i < self.end_i
    }
}

#[derive(Debug)]
struct ColRanges {
    col_ranges: Vec<ColRange>,
}

impl ColRanges {
    fn new(col_prefix_sums_usizes: &[usize], last_prefix_sum: usize) -> Self {
        let num_col_prefix_sums = col_prefix_sums_usizes.len();

        let last_range = ColRange {
            col_idx: num_col_prefix_sums - 1,
            start_i: col_prefix_sums_usizes[num_col_prefix_sums - 1],
            end_i: last_prefix_sum,
            col_size: last_prefix_sum - col_prefix_sums_usizes[num_col_prefix_sums - 1],
            is_last: true,
        };

        ColRanges {
            col_ranges: col_prefix_sums_usizes
                .iter()
                .take(num_col_prefix_sums - 1)
                .enumerate()
                .map(|(i, prefix_sum)| ColRange {
                    col_idx: i,
                    start_i: *prefix_sum,
                    end_i: col_prefix_sums_usizes[i + 1],
                    col_size: col_prefix_sums_usizes[i + 1] - *prefix_sum,
                    is_last: false,
                })
                .chain(once(last_range))
                .collect::<Vec<_>>(),
        }
    }

    #[inline]
    fn get_col_range(&self, i: usize) -> impl Iterator<Item = &ColRange> {
        let mut col_range_iter = self.col_ranges.iter().peekable();
        loop {
            let col_range = col_range_iter.peek().expect("i is out of range");
            if col_range.in_range(i) {
                return col_range_iter;
            }
            col_range_iter.next().expect("must have next element");
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BranchingProgram<K: AbstractField> {
    z_row: Point<K>,
    z_index: Point<K>,
    memory_states: Vec<MemoryState>,
    bit_states: Vec<BitState<bool>>,
    pub(crate) num_vars: usize,
}

impl<K: AbstractField + 'static> BranchingProgram<K> {
    pub fn new(z_row: Point<K>, z_index: Point<K>) -> Self {
        let log_m = z_index.dimension().max(z_row.dimension());

        Self {
            z_row,
            z_index,
            memory_states: all_memory_states(),
            bit_states: all_bit_states(),
            num_vars: log_m,
        }
    }

    pub fn eval(&self, prefix_sum: &Point<K>, next_prefix_sum: &Point<K>) -> K {
        let mut state_by_state_results: [K; 4] = array::from_fn(|_| K::zero());
        state_by_state_results[MemoryState::success().get_index()] = K::one();

        // The dynamic programming algorithm to output the result of the branching
        // iterates over the layers of the branching program in reverse order.
        for layer in (0..self.num_vars + 1).rev() {
            let mut new_state_by_state_results: [K; 4] =
                [K::zero(), K::zero(), K::zero(), K::zero()];

            // We assume that bits are aligned in big-endian order. The algorithm,
            // in the ith layer, looks at the ith least significant bit, which is
            // the m - 1 - i th bit if the bits are in a bit array in big-endian.
            let point = [
                Self::get_ith_least_significant_val(&self.z_row, layer),
                Self::get_ith_least_significant_val(&self.z_index, layer),
                Self::get_ith_least_significant_val(prefix_sum, layer),
                Self::get_ith_least_significant_val(next_prefix_sum, layer),
            ]
            .into_iter()
            .collect::<Point<K>>();

            let four_var_eq: Mle<K> = Mle::blocking_partial_lagrange(&point);

            // For each memory state in the new layer, compute the result of the branching
            // program that starts at that memory state.
            for memory_state in &self.memory_states {
                // For each possible bit state, compute the result of the branching
                // program transition function and modify the weight associated to the output
                // accordingly.
                let mut accum_elems: [K; 4] = array::from_fn(|_| K::zero());

                for (i, elem) in four_var_eq.guts().as_slice().iter().enumerate() {
                    let bit_state = &self.bit_states[i];

                    let state_or_fail = transition_function(*bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        accum_elems[output_state.get_index()] += elem.clone();
                    }
                    // If the state is a fail state, we don't need to add anything to the
                    // accumulator.
                }

                let accum = accum_elems.iter().zip(state_by_state_results.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_by_state_result)| {
                        acc + accum_elem.clone() * state_by_state_result.clone()
                    },
                );

                new_state_by_state_results[memory_state.get_index()] = accum;
            }
            state_by_state_results = new_state_by_state_results;
        }

        state_by_state_results[MemoryState::initial_state().get_index()].clone()
    }

    /// We assume that the point is in big-endian order.
    fn get_ith_least_significant_val(point: &Point<K>, i: usize) -> K {
        let dim = point.dimension();
        if dim <= i {
            K::zero()
        } else {
            point.get(dim - i - 1).expect("index out of bounds").clone()
        }
    }
}

#[cfg(test)]
pub mod tests {

    use rand::Rng;
    use slop_algebra::AbstractField;
    use slop_baby_bear::BabyBear;
    use slop_multilinear::Point;
    use slop_utils::log2_ceil_usize;

    type F = BabyBear;

    use crate::StateOrFail;

    use super::{
        all_bit_states, all_memory_states, transition_function, JaggedLittlePolynomialProverParams,
        JaggedLittlePolynomialVerifierParams,
    };

    #[test]
    fn test_transition_function() {
        for bit_state in all_bit_states() {
            for memory_state in all_memory_states() {
                println!("Bit state {bit_state:?}, Memory State {memory_state:?}");
                let result = super::transition_function(bit_state, memory_state);
                println!("Result: {result:?}");
            }
        }
    }

    #[test]
    fn test_single_table_jagged_eval() {
        for log_num_rows in 0..5 {
            for log_num_cols in 0..5 {
                for index in 0..(1 << (log_num_cols + log_num_rows)) {
                    let log_m = log_num_cols + log_num_rows;
                    let row = index % (1 << log_num_rows);
                    let col = index / (1 << log_num_rows);

                    let mut z_row = Point::<F>::from_usize(row, log_num_rows + 1);
                    let mut z_col = Point::from_usize(col, log_num_cols + 1);
                    let z_index = Point::from_usize(index, log_m + 1);

                    let prover_params = super::JaggedLittlePolynomialProverParams::new(
                        std::iter::repeat_n(1 << log_num_rows, 1 << log_num_cols).collect(),
                        log_num_rows,
                    );

                    let verifier_params = prover_params.clone().into_verifier_params();

                    let result = verifier_params.full_jagged_little_polynomial_evaluation(
                        &z_row,
                        &z_col,
                        &z_index.clone(),
                    );
                    assert_eq!(result, F::one());

                    let prover_result = prover_params
                        .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                        .blocking_eval_at(&z_index);

                    assert_eq!(result, prover_result.to_vec()[0]);

                    for other_index in 0..(1 << (log_num_cols + log_num_rows)) {
                        if other_index != index {
                            assert!(
                                verifier_params.full_jagged_little_polynomial_evaluation(
                                    &z_row,
                                    &z_col,
                                    &Point::<F>::from_usize(other_index, log_m)
                                ) == F::zero()
                            );
                            assert_eq!(
                                prover_params
                                    .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                                    .blocking_eval_at(&Point::<F>::from_usize(other_index, log_m))
                                    .to_vec()[0],
                                F::zero()
                            );
                        }
                    }

                    z_row = Point::<F>::from_usize(row ^ 1, log_num_rows + 1);

                    let wrong_result = verifier_params.full_jagged_little_polynomial_evaluation(
                        &z_row,
                        &z_col,
                        &z_index.clone(),
                    );
                    assert_eq!(wrong_result, F::zero());

                    z_row = Point::<F>::from_usize(row, log_num_rows + 1);
                    z_col = Point::<F>::from_usize(col ^ 1, log_num_cols + 1);

                    let wrong_result = verifier_params
                        .full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index);
                    assert_eq!(wrong_result, F::zero());

                    z_col = Point::<F>::from_usize(col, log_num_cols + 1);
                    let wrong_result = verifier_params.full_jagged_little_polynomial_evaluation(
                        &z_row,
                        &z_col,
                        &Point::<F>::from_usize(index ^ 1, log_num_cols + 1),
                    );
                    assert_eq!(wrong_result, F::zero());

                    let mut rng = rand::thread_rng();

                    for _ in 0..3 {
                        let z_index: Point<F> = (0..log_m).map(|_| rng.gen::<F>()).collect();
                        assert_eq!(
                            verifier_params
                                .full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index),
                            prover_params
                                .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                                .blocking_eval_at(&z_index)
                                .to_vec()[0]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_multi_table_jagged_eval() {
        let row_counts = [12, 1, 2, 1, 17, 0];

        let mut prefix_sums = row_counts
            .iter()
            .scan(0, |state, row_count| {
                let result = *state;
                *state += row_count;
                Some(result)
            })
            .collect::<Vec<_>>();

        prefix_sums.push(*prefix_sums.last().unwrap() + row_counts.last().unwrap());

        let log_m = log2_ceil_usize(*prefix_sums.last().unwrap());

        let log_max_row_count = 7;

        let prover_params =
            JaggedLittlePolynomialProverParams::new(row_counts.to_vec(), log_max_row_count);

        let verifier_params: JaggedLittlePolynomialVerifierParams<F> =
            prover_params.clone().into_verifier_params();

        for index in 0..row_counts.iter().sum() {
            let col = prefix_sums.iter().rposition(|&x| index >= x).unwrap();
            let row = index - prefix_sums[col];
            let z_row = Point::<F>::from_usize(row, log_max_row_count);
            let z_col = Point::from_usize(col, log2_ceil_usize(row_counts.len()));

            for new_row in 0..(1 << log_max_row_count) {
                for new_col in 0..row_counts.len() {
                    if !(new_col == col && new_row == row) {
                        let z_index = Point::<F>::from_usize(index, log_m);

                        let new_z_row = Point::from_usize(new_row, log_max_row_count);
                        let new_z_col =
                            Point::from_usize(new_col, log2_ceil_usize(row_counts.len()));

                        let result = verifier_params.full_jagged_little_polynomial_evaluation(
                            &new_z_row, &new_z_col, &z_index,
                        );
                        assert_eq!(result, F::zero());

                        assert_eq!(
                            prover_params
                                .partial_jagged_little_polynomial_evaluation(&new_z_row, &new_z_col)
                                .blocking_eval_at(&z_index)
                                .to_vec()[0],
                            F::zero()
                        );
                    }
                }
            }

            let z_index = Point::from_usize(index, log_m + 1);
            let result =
                verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index);
            assert_eq!(result, F::one());

            for other_index in 0..*prefix_sums.last().unwrap() {
                if other_index != index {
                    assert!(
                        verifier_params.full_jagged_little_polynomial_evaluation(
                            &z_row,
                            &z_col,
                            &Point::from_usize(other_index, log_m)
                        ) == F::zero()
                    );

                    assert_eq!(
                        prover_params
                            .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                            .blocking_eval_at(&Point::<F>::from_usize(other_index, log_m))
                            .to_vec()[0],
                        F::zero()
                    );
                }
            }
        }

        let mut rng = rand::thread_rng();

        let params =
            super::JaggedLittlePolynomialProverParams::new(row_counts.to_vec(), log_max_row_count);

        let z_row = (0..log_max_row_count).map(|_| rng.gen::<F>()).collect();
        let z_col = (0..log2_ceil_usize(row_counts.len())).map(|_| rng.gen::<F>()).collect();

        let verifier_params = params.clone().into_verifier_params();

        for _ in 0..100 {
            let z_index: Point<F> = (0..log_m + 1).map(|_| rng.gen::<F>()).collect();
            assert_eq!(
                verifier_params.full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index),
                params
                    .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                    .blocking_eval_at(&z_index)
                    .to_vec()[0]
            );
        }
    }

    #[test]
    fn test_single_table_jagged_eval_off_boolean_hypercube() {
        let mut rng = rand::thread_rng();
        for log_num_rows in 0..5 {
            for log_num_cols in 0..5 {
                let log_m = log_num_cols + log_num_rows;
                let z_row = (0..log_num_rows).map(|_| rng.gen::<F>()).collect();
                let z_col = (0..log_num_cols).map(|_| rng.gen::<F>()).collect();

                for index in 0..(1 << (log_num_cols + log_num_rows)) {
                    let params = super::JaggedLittlePolynomialProverParams::new(
                        (0..(1 << log_num_cols)).map(|_| 1 << log_num_rows).collect(),
                        log_num_rows,
                    );

                    let verifier_params = params.clone().into_verifier_params();

                    let z_index = Point::from_usize(index, log_m);
                    assert_eq!(
                        verifier_params
                            .full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index),
                        params
                            .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                            .blocking_eval_at(&z_index)
                            .to_vec()[0]
                    );

                    let z_index = (0..log_m).map(|_| rng.gen::<F>()).collect();
                    assert_eq!(
                        verifier_params
                            .full_jagged_little_polynomial_evaluation(&z_row, &z_col, &z_index),
                        params
                            .partial_jagged_little_polynomial_evaluation(&z_row, &z_col)
                            .blocking_eval_at(&z_index)
                            .to_vec()[0]
                    );
                }
            }
        }
    }

    #[test]
    fn output_transition_table() {
        let memory_states = all_memory_states();
        let bit_states = all_bit_states();

        for bit_state in bit_states {
            let mut output_state: Vec<StateOrFail> = Vec::new();

            for memory_state in memory_states.clone() {
                output_state.push(transition_function(bit_state, memory_state));
            }

            println!(
                "{}",
                output_state.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" ")
            );
        }
    }
}
