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

/// The number of memory states in the wide (interleaved) branching program.
pub const WIDE_BRANCHING_PROGRAM_WIDTH: usize = 8;

/// A struct recording the state of the memory of the branching program.
/// The program performs a two-way addition and one u32 comparison, with an interleaved
/// bit ordering that separates curr and next prefix sum bits into different layers.
/// The memory stores a carry, the comparison result so far, and a saved index bit
/// that is used in the next layer for comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MemoryState {
    pub carry: bool,
    pub comparison_so_far: bool,
    pub saved_index_bit: bool,
}

impl fmt::Display for MemoryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "COMPARISON_SO_FAR_{}__CARRY_{}__SAVED_INDEX_{}",
            self.comparison_so_far as usize, self.carry as usize, self.saved_index_bit as usize
        )
    }
}

impl MemoryState {
    pub fn get_index(&self) -> usize {
        (self.carry as usize)
            + ((self.comparison_so_far as usize) << 1)
            + ((self.saved_index_bit as usize) << 2)
    }
}

impl MemoryState {
    /// The two memory states which indicate success in the last layer of the branching program.
    /// Both saved_index_bit values are accepted since the last layer (a next layer) clears it.
    fn success_states() -> [Self; 2] {
        [
            MemoryState { carry: false, comparison_so_far: true, saved_index_bit: false },
            MemoryState { carry: false, comparison_so_far: true, saved_index_bit: true },
        ]
    }

    pub fn initial_state() -> Self {
        MemoryState { carry: false, comparison_so_far: false, saved_index_bit: false }
    }

    /// The four memory states used by the width-4 (combined) branching program.
    /// These have `saved_index_bit = false` since the combined transition handles
    /// both addition and comparison in a single step.
    pub fn width4_states() -> [Self; 4] {
        [
            MemoryState { carry: false, comparison_so_far: false, saved_index_bit: false },
            MemoryState { carry: true, comparison_so_far: false, saved_index_bit: false },
            MemoryState { carry: false, comparison_so_far: true, saved_index_bit: false },
            MemoryState { carry: true, comparison_so_far: true, saved_index_bit: false },
        ]
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

/// The bits the branching program reads on each layer.
///
/// - `Curr`: Even layers read 3 bits (row, index, curr_col_prefix_sum).
/// - `Next`: Odd layers read 1 bit (next_col_prefix_sum).
/// - `Combined`: Width-4 evaluation reads all 4 bits per layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BitState {
    Curr {
        row_bit: bool,
        index_bit: bool,
        curr_col_prefix_sum_bit: bool,
    },
    Next {
        next_col_prefix_sum_bit: bool,
    },
    Combined {
        row_bit: bool,
        index_bit: bool,
        curr_col_prefix_sum_bit: bool,
        next_col_prefix_sum_bit: bool,
    },
}

impl BitState {
    fn curr_from_index(i: usize) -> Self {
        BitState::Curr {
            row_bit: (i & 1) != 0,
            index_bit: ((i >> 1) & 1) != 0,
            curr_col_prefix_sum_bit: ((i >> 2) & 1) != 0,
        }
    }

    fn next_from_index(i: usize) -> Self {
        BitState::Next { next_col_prefix_sum_bit: (i & 1) != 0 }
    }

    fn combined_from_index(i: usize) -> Self {
        BitState::Combined {
            row_bit: (i & 1) != 0,
            index_bit: ((i >> 1) & 1) != 0,
            curr_col_prefix_sum_bit: ((i >> 2) & 1) != 0,
            next_col_prefix_sum_bit: ((i >> 3) & 1) != 0,
        }
    }
}

/// Enumerate all the possible memory states.
pub fn all_memory_states() -> Vec<MemoryState> {
    (0..2)
        .flat_map(|saved_index_bit| {
            (0..2).flat_map(move |comparison_so_far| {
                (0..2).map(move |carry| MemoryState {
                    carry: carry != 0,
                    comparison_so_far: comparison_so_far != 0,
                    saved_index_bit: saved_index_bit != 0,
                })
            })
        })
        .collect()
}

/// Unified transition function for the branching program.
///
/// - `BitState::Curr`: Checks addition constraint, updates carry, saves index_bit.
/// - `BitState::Next`: Updates comparison using saved index bit. Always succeeds.
/// - `BitState::Combined`: Addition check + comparison update in one step (width-4).
pub fn transition(bit_state: BitState, memory_state: MemoryState) -> StateOrFail {
    match bit_state {
        BitState::Curr { row_bit, index_bit, curr_col_prefix_sum_bit } => {
            let sum =
                row_bit as usize + memory_state.carry as usize + curr_col_prefix_sum_bit as usize;

            if (index_bit as usize) != (sum & 1) {
                return StateOrFail::Fail;
            }

            StateOrFail::State(MemoryState {
                carry: (sum >> 1) != 0,
                comparison_so_far: memory_state.comparison_so_far,
                saved_index_bit: index_bit,
            })
        }
        BitState::Next { next_col_prefix_sum_bit } => {
            let new_comparison_so_far = if memory_state.saved_index_bit == next_col_prefix_sum_bit {
                memory_state.comparison_so_far
            } else {
                next_col_prefix_sum_bit
            };

            StateOrFail::State(MemoryState {
                carry: memory_state.carry,
                comparison_so_far: new_comparison_so_far,
                saved_index_bit: false,
            })
        }
        BitState::Combined {
            row_bit,
            index_bit,
            curr_col_prefix_sum_bit,
            next_col_prefix_sum_bit,
        } => {
            let sum =
                row_bit as usize + memory_state.carry as usize + curr_col_prefix_sum_bit as usize;

            if (index_bit as usize) != (sum & 1) {
                return StateOrFail::Fail;
            }

            let new_comparison_so_far = if index_bit == next_col_prefix_sum_bit {
                memory_state.comparison_so_far
            } else {
                next_col_prefix_sum_bit
            };

            StateOrFail::State(MemoryState {
                carry: (sum >> 1) != 0,
                comparison_so_far: new_comparison_so_far,
                saved_index_bit: false,
            })
        }
    }
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

/// Interleave two prefix sum points into a single point with big-endian layout:
/// `[next[MSB], curr[MSB], next[MSB-1], curr[MSB-1], ..., next[LSB], curr[LSB]]`
pub fn interleave_prefix_sums<K: Clone>(curr: &Point<K>, next: &Point<K>) -> Point<K> {
    assert_eq!(curr.dimension(), next.dimension());
    next.iter().zip(curr.iter()).flat_map(|(n, c)| [n.clone(), c.clone()]).collect()
}

/// De-interleave an interleaved prefix sum point back into `(curr, next)`.
/// Inverse of [`interleave_prefix_sums`].
pub fn deinterleave_prefix_sums<K: Clone>(interleaved: &Point<K>) -> (Point<K>, Point<K>) {
    assert!(interleaved.dimension().is_multiple_of(2));
    let (next, curr): (Vec<_>, Vec<_>) =
        interleaved.to_vec().chunks(2).map(|pair| (pair[0].clone(), pair[1].clone())).unzip();
    (curr.into(), next.into())
}

#[derive(Debug, Clone, Default)]
pub struct BranchingProgram<K: AbstractField> {
    z_row: Point<K>,
    z_index: Point<K>,
    memory_states: Vec<MemoryState>,
    pub(crate) num_vars: usize,
}

impl<K: AbstractField + 'static> BranchingProgram<K> {
    pub fn new(z_row: Point<K>, z_index: Point<K>) -> Self {
        let log_m = z_index.dimension().max(z_row.dimension());

        Self { z_row, z_index, memory_states: all_memory_states(), num_vars: log_m }
    }

    /// Apply one DP layer. `interleaved_val` is the value at this layer's position.
    ///
    /// - Even layer 2k: factors the 3-var eq into a 2-var eq (K) times base factors (F),
    ///   giving K*F multiplications instead of K*K.
    /// - Odd layer 2k+1: accumulates in F, then dot-products with state (K*F).
    pub fn apply_layer_step<F: AbstractField + 'static>(
        &self,
        layer: usize,
        interleaved_val: F,
        state: &[K],
    ) -> [K; WIDE_BRANCHING_PROGRAM_WIDTH]
    where
        K: AbstractExtensionField<F>,
    {
        let mut new_state: [K; WIDE_BRANCHING_PROGRAM_WIDTH] = array::from_fn(|_| K::zero());
        let k = layer / 2;

        if layer.is_multiple_of(2) {
            let two_var_eq: Mle<K> = Mle::blocking_partial_lagrange(
                &[
                    Self::get_ith_least_significant_val(&self.z_row, k),
                    Self::get_ith_least_significant_val(&self.z_index, k),
                ]
                .into_iter()
                .collect::<Point<K>>(),
            );
            let two_var_eq_slice = two_var_eq.guts().as_slice();
            let base_factors: [F; 2] = [F::one() - interleaved_val.clone(), interleaved_val];

            for memory_state in &self.memory_states {
                let mut accum_elems: [K; WIDE_BRANCHING_PROGRAM_WIDTH] =
                    array::from_fn(|_| K::zero());

                for (half_i, eq_val) in two_var_eq_slice.iter().enumerate() {
                    for (bit, factor) in base_factors.iter().enumerate() {
                        let i = (half_i << 1) | bit;
                        let bit_state = BitState::curr_from_index(i);
                        let state_or_fail = transition(bit_state, *memory_state);

                        if let StateOrFail::State(output_state) = state_or_fail {
                            accum_elems[output_state.get_index()] +=
                                eq_val.clone() * factor.clone();
                        }
                    }
                }

                let accum = accum_elems.iter().zip(state.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_result)| {
                        acc + accum_elem.clone() * state_result.clone()
                    },
                );

                new_state[memory_state.get_index()] = accum;
            }
        } else {
            let base_factors: [F; 2] = [F::one() - interleaved_val.clone(), interleaved_val];

            for memory_state in &self.memory_states {
                let mut accum_elems: [F; WIDE_BRANCHING_PROGRAM_WIDTH] =
                    array::from_fn(|_| F::zero());

                for (bit, factor) in base_factors.iter().enumerate() {
                    let bit_state = BitState::next_from_index(bit);
                    let state_or_fail = transition(bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        accum_elems[output_state.get_index()] += factor.clone();
                    }
                }

                let accum = accum_elems.iter().zip(state.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_result)| {
                        acc + state_result.clone() * accum_elem.clone()
                    },
                );

                new_state[memory_state.get_index()] = accum;
            }
        }

        new_state
    }

    /// Specialized [`apply_layer_step`] for `interleaved_val = 0`.
    ///
    /// - Even layer: only bit=0 entries contribute (base factor is `[1, 0]`), halving the work.
    /// - Odd layer: only `next_col_prefix_sum_bit = false` contributes with weight 1.
    pub fn apply_layer_step_at_zero(
        &self,
        layer: usize,
        state: &[K],
    ) -> [K; WIDE_BRANCHING_PROGRAM_WIDTH] {
        let mut new_state: [K; WIDE_BRANCHING_PROGRAM_WIDTH] = array::from_fn(|_| K::zero());
        let k = layer / 2;

        if layer.is_multiple_of(2) {
            let two_var_eq: Mle<K> = Mle::blocking_partial_lagrange(
                &[
                    Self::get_ith_least_significant_val(&self.z_row, k),
                    Self::get_ith_least_significant_val(&self.z_index, k),
                ]
                .into_iter()
                .collect::<Point<K>>(),
            );
            let two_var_eq_slice = two_var_eq.guts().as_slice();

            for memory_state in &self.memory_states {
                let mut accum_elems: [K; WIDE_BRANCHING_PROGRAM_WIDTH] =
                    array::from_fn(|_| K::zero());

                for (half_i, eq_val) in two_var_eq_slice.iter().enumerate() {
                    let i = half_i << 1; // bit 0 = 0
                    let bit_state = BitState::curr_from_index(i);
                    let state_or_fail = transition(bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        accum_elems[output_state.get_index()] += eq_val.clone();
                    }
                }

                let accum = accum_elems.iter().zip(state.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_result)| {
                        acc + accum_elem.clone() * state_result.clone()
                    },
                );

                new_state[memory_state.get_index()] = accum;
            }
        } else {
            // Only bit=0 contributes with weight 1; transition always succeeds for Next.
            for memory_state in &self.memory_states {
                let state_or_fail = transition(BitState::next_from_index(0), *memory_state);

                if let StateOrFail::State(output_state) = state_or_fail {
                    new_state[memory_state.get_index()] = state[output_state.get_index()].clone();
                }
            }
        }

        new_state
    }

    /// Specialized [`apply_layer_step`] for `interleaved_val = 1/2`.
    ///
    /// Both bit values contribute equally (base factor is `[1/2, 1/2]`), so we
    /// accumulate transitions for both bits and multiply by `half` once at the end.
    pub fn apply_layer_step_at_half<F: AbstractField + 'static>(
        &self,
        layer: usize,
        half: F,
        state: &[K],
    ) -> [K; WIDE_BRANCHING_PROGRAM_WIDTH]
    where
        K: AbstractExtensionField<F>,
    {
        let mut new_state: [K; WIDE_BRANCHING_PROGRAM_WIDTH] = array::from_fn(|_| K::zero());
        let k = layer / 2;

        if layer.is_multiple_of(2) {
            let two_var_eq: Mle<K> = Mle::blocking_partial_lagrange(
                &[
                    Self::get_ith_least_significant_val(&self.z_row, k),
                    Self::get_ith_least_significant_val(&self.z_index, k),
                ]
                .into_iter()
                .collect::<Point<K>>(),
            );
            let two_var_eq_slice = two_var_eq.guts().as_slice();

            for memory_state in &self.memory_states {
                let mut accum_elems: [K; WIDE_BRANCHING_PROGRAM_WIDTH] =
                    array::from_fn(|_| K::zero());

                for (half_i, eq_val) in two_var_eq_slice.iter().enumerate() {
                    for bit in 0..2 {
                        let i = (half_i << 1) | bit;
                        let bit_state = BitState::curr_from_index(i);
                        let state_or_fail = transition(bit_state, *memory_state);

                        if let StateOrFail::State(output_state) = state_or_fail {
                            accum_elems[output_state.get_index()] += eq_val.clone();
                        }
                    }
                }

                let accum = accum_elems.iter().zip(state.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_result)| {
                        acc + accum_elem.clone() * state_result.clone()
                    },
                );

                new_state[memory_state.get_index()] = accum * half.clone();
            }
        } else {
            for memory_state in &self.memory_states {
                let mut accum_elems: [K; WIDE_BRANCHING_PROGRAM_WIDTH] =
                    array::from_fn(|_| K::zero());

                for bit in 0..2 {
                    let bit_state = BitState::next_from_index(bit);
                    let state_or_fail = transition(bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        accum_elems[output_state.get_index()] += K::one();
                    }
                }

                let accum = accum_elems.iter().zip(state.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_result)| {
                        acc + accum_elem.clone() * state_result.clone()
                    },
                );

                new_state[memory_state.get_index()] = accum * half.clone();
            }
        }

        new_state
    }

    /// Evaluate the branching program with separate curr and next prefix sum points (width-4).
    ///
    /// Uses a `[K; 4]` state vector indexed by `carry + 2*comparison_so_far`.
    /// Processes `num_vars + 1` layers, each reading 4 bits (row, index, curr_prefix_sum,
    /// next_prefix_sum) via `Mle::blocking_partial_lagrange`.
    pub fn eval(&self, prefix_sum: &Point<K>, next_prefix_sum: &Point<K>) -> K {
        let mut state: [K; 4] = array::from_fn(|_| K::zero());
        // Success state: carry=false, comparison_so_far=true → index 2
        state[2] = K::one();

        let width4_states = MemoryState::width4_states();

        for layer in (0..self.num_vars + 1).rev() {
            // Note: blocking_partial_lagrange maps bit k of the index to point[d-1-k],
            // so we reverse the order so that bit 0 → row, bit 1 → index, etc.
            let point = [
                Self::get_ith_least_significant_val(next_prefix_sum, layer),
                Self::get_ith_least_significant_val(prefix_sum, layer),
                Self::get_ith_least_significant_val(&self.z_index, layer),
                Self::get_ith_least_significant_val(&self.z_row, layer),
            ]
            .into_iter()
            .collect::<Point<K>>();

            let four_var_eq: Mle<K> = Mle::blocking_partial_lagrange(&point);

            let mut new_state: [K; 4] = array::from_fn(|_| K::zero());

            for (state_idx, memory_state) in width4_states.iter().enumerate() {
                let mut accum_elems: [K; 4] = array::from_fn(|_| K::zero());

                for (i, elem) in four_var_eq.guts().as_slice().iter().enumerate() {
                    let bit_state = BitState::combined_from_index(i);
                    let state_or_fail = transition(bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        let output_idx = (output_state.carry as usize)
                            + 2 * (output_state.comparison_so_far as usize);
                        accum_elems[output_idx] += elem.clone();
                    }
                }

                let accum = accum_elems.iter().zip(state.iter()).fold(
                    K::zero(),
                    |acc, (accum_elem, state_result)| {
                        acc + accum_elem.clone() * state_result.clone()
                    },
                );

                new_state[state_idx] = accum;
            }

            state = new_state;
        }

        // Initial state: carry=false, comparison_so_far=false → index 0
        state[0].clone()
    }

    /// Evaluate the branching program with an interleaved point.
    ///
    /// The interleaved point has big-endian layout:
    /// `[next[MSB], curr[MSB], next[MSB-1], curr[MSB-1], ..., next[LSB], curr[LSB]]`
    ///
    /// The BP processes `2*(num_vars+1)` layers, alternating:
    /// - Even layer 2k: reads z_row[k], z_index[k], curr_prefix_sum[k] (3 bits)
    /// - Odd layer 2k+1: reads next_prefix_sum[k] (1 bit)
    pub fn eval_interleaved(&self, interleaved_point: &Point<K>) -> K {
        let mut state: [K; WIDE_BRANCHING_PROGRAM_WIDTH] = array::from_fn(|_| K::zero());
        for success in MemoryState::success_states() {
            state[success.get_index()] = K::one();
        }

        let num_layers = 2 * (self.num_vars + 1);

        for layer in (0..num_layers).rev() {
            let interleaved_val = Self::get_ith_least_significant_val(interleaved_point, layer);
            state = self.apply_layer_step(layer, interleaved_val, &state);
        }

        state[MemoryState::initial_state().get_index()].clone()
    }

    /// Precompute prefix states for a given interleaved point.
    ///
    /// Returns a flat `Vec<K>` of length `(num_layers + 1) * WIDE_BRANCHING_PROGRAM_WIDTH`.
    /// The state for layer `l` is stored at
    /// `[WIDE_BRANCHING_PROGRAM_WIDTH*l .. WIDE_BRANCHING_PROGRAM_WIDTH*(l+1)]`.
    /// Entry `[num_layers]` is the initial success state.
    ///
    /// Accepts a base-field point to avoid F-to-EF promotion of prefix sums.
    pub fn precompute_prefix_states<F: AbstractField + 'static>(
        &self,
        interleaved_point: &Point<F>,
    ) -> Vec<K>
    where
        K: AbstractExtensionField<F>,
    {
        let num_layers = 2 * (self.num_vars + 1);
        let w = WIDE_BRANCHING_PROGRAM_WIDTH;
        let mut states: Vec<K> = vec![K::zero(); (num_layers + 1) * w];

        let mut current_state: [K; WIDE_BRANCHING_PROGRAM_WIDTH] = array::from_fn(|_| K::zero());
        for success in MemoryState::success_states() {
            current_state[success.get_index()] = K::one();
        }
        states[num_layers * w..(num_layers + 1) * w].clone_from_slice(&current_state);

        for layer in (0..num_layers).rev() {
            let interleaved_val = Self::get_ith_least_significant_val(interleaved_point, layer);
            current_state = self.apply_layer_step(layer, interleaved_val, &current_state);
            states[layer * w..(layer + 1) * w].clone_from_slice(&current_state);
        }

        states
    }

    /// Transposed DP step for suffix update. For each old state `s`, pushes weighted
    /// contributions to output states `t = transition(s, b)`.
    ///
    /// Computes `result[t] = Σ_s suffix[s] * M_layer[s, t](interleaved_val)`.
    pub fn apply_layer_step_transposed(
        &self,
        layer: usize,
        interleaved_val: K,
        suffix: &[K],
    ) -> [K; WIDE_BRANCHING_PROGRAM_WIDTH] {
        let mut result: [K; WIDE_BRANCHING_PROGRAM_WIDTH] = array::from_fn(|_| K::zero());
        let k = layer / 2;

        if layer.is_multiple_of(2) {
            let point = [
                Self::get_ith_least_significant_val(&self.z_row, k),
                Self::get_ith_least_significant_val(&self.z_index, k),
                interleaved_val,
            ]
            .into_iter()
            .collect::<Point<K>>();

            let three_var_eq: Mle<K> = Mle::blocking_partial_lagrange(&point);

            for memory_state in &self.memory_states {
                let s = memory_state.get_index();
                for (i, elem) in three_var_eq.guts().as_slice().iter().enumerate() {
                    let bit_state = BitState::curr_from_index(i);
                    let state_or_fail = transition(bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        result[output_state.get_index()] += suffix[s].clone() * elem.clone();
                    }
                }
            }
        } else {
            let point = [interleaved_val].into_iter().collect::<Point<K>>();

            let one_var_eq: Mle<K> = Mle::blocking_partial_lagrange(&point);

            for memory_state in &self.memory_states {
                let s = memory_state.get_index();
                for (i, elem) in one_var_eq.guts().as_slice().iter().enumerate() {
                    let bit_state = BitState::next_from_index(i);
                    let state_or_fail = transition(bit_state, *memory_state);

                    if let StateOrFail::State(output_state) = state_or_fail {
                        result[output_state.get_index()] += suffix[s].clone() * elem.clone();
                    }
                }
            }
        }

        result
    }

    /// Evaluate BP using precomputed prefix and suffix state.
    ///
    /// Processes only one layer (the lambda layer at `layer`) and combines with the
    /// cached prefix state (from above) and suffix vector (from below).
    pub fn eval_with_cached<F: AbstractField + 'static>(
        &self,
        layer: usize,
        lambda: F,
        prefix_state: &[K],
        suffix_vector: &[K],
    ) -> K
    where
        K: AbstractExtensionField<F>,
    {
        let after_lambda = self.apply_layer_step(layer, lambda, prefix_state);
        suffix_vector
            .iter()
            .zip(after_lambda.iter())
            .fold(K::zero(), |acc, (s, a)| acc + s.clone() * a.clone())
    }

    /// Specialized [`eval_with_cached`] for `lambda = 0`.
    pub fn eval_with_cached_at_zero(
        &self,
        layer: usize,
        prefix_state: &[K],
        suffix_vector: &[K],
    ) -> K {
        let after_lambda = self.apply_layer_step_at_zero(layer, prefix_state);
        suffix_vector
            .iter()
            .zip(after_lambda.iter())
            .fold(K::zero(), |acc, (s, a)| acc + s.clone() * a.clone())
    }

    /// Specialized [`eval_with_cached`] for `lambda = 1/2`.
    pub fn eval_with_cached_at_half<F: AbstractField + 'static>(
        &self,
        layer: usize,
        half: F,
        prefix_state: &[K],
        suffix_vector: &[K],
    ) -> K
    where
        K: AbstractExtensionField<F>,
    {
        let after_lambda = self.apply_layer_step_at_half(layer, half, prefix_state);
        suffix_vector
            .iter()
            .zip(after_lambda.iter())
            .fold(K::zero(), |acc, (s, a)| acc + s.clone() * a.clone())
    }

    /// We assume that the point is in big-endian order.
    fn get_ith_least_significant_val<T: AbstractField + 'static>(point: &Point<T>, i: usize) -> T {
        let dim = point.dimension();
        if dim <= i {
            T::zero()
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

    use super::{
        all_memory_states, transition, BitState, JaggedLittlePolynomialProverParams,
        JaggedLittlePolynomialVerifierParams, StateOrFail,
    };

    #[test]
    fn test_transition_functions() {
        for row in [false, true] {
            for index in [false, true] {
                for curr_ps in [false, true] {
                    let bit_state = BitState::Curr {
                        row_bit: row,
                        index_bit: index,
                        curr_col_prefix_sum_bit: curr_ps,
                    };
                    for memory_state in all_memory_states() {
                        println!(
                            "Curr layer: {bit_state:?}, Memory State {memory_state:?} -> {:?}",
                            transition(bit_state, memory_state)
                        );
                    }
                }
            }
        }

        for next_ps in [false, true] {
            let bit_state = BitState::Next { next_col_prefix_sum_bit: next_ps };
            for memory_state in all_memory_states() {
                println!(
                    "Next layer: {bit_state:?}, Memory State {memory_state:?} -> {:?}",
                    transition(bit_state, memory_state)
                );
            }
        }
    }

    /// Verify the width-8 transition tables (CURR_TRANSITIONS_W8 and NEXT_TRANSITIONS_W8)
    /// against the CPU `transition()` function.
    ///
    /// Width-8 memory state index: carry + (comparison_so_far << 1) + (saved_index_bit << 2).
    /// WIDE_FAIL = 8.
    ///
    /// Even layer (Curr) bit state index: (curr_ps_bit << 2) | (index_bit << 1) | row_bit.
    /// Odd layer (Next) bit state index: next_ps_bit.
    #[test]
    fn test_width8_transition_tables() {
        const WIDE_FAIL: u8 = 8;

        // Expected tables matching GPU's CURR_TRANSITIONS_W8 and NEXT_TRANSITIONS_W8.
        #[rustfmt::skip]
        const CURR_TRANSITIONS_W8: [[u8; 8]; 8] = [
            [0, 8, 2, 8, 0, 8, 2, 8], // bit_state 0: row=0 idx=0 cps=0
            [8, 1, 8, 3, 8, 1, 8, 3], // bit_state 1: row=1 idx=0 cps=0
            [8, 4, 8, 6, 8, 4, 8, 6], // bit_state 2: row=0 idx=1 cps=0
            [4, 8, 6, 8, 4, 8, 6, 8], // bit_state 3: row=1 idx=1 cps=0
            [8, 1, 8, 3, 8, 1, 8, 3], // bit_state 4: row=0 idx=0 cps=1
            [1, 8, 3, 8, 1, 8, 3, 8], // bit_state 5: row=1 idx=0 cps=1
            [4, 8, 6, 8, 4, 8, 6, 8], // bit_state 6: row=0 idx=1 cps=1
            [8, 5, 8, 7, 8, 5, 8, 7], // bit_state 7: row=1 idx=1 cps=1
        ];

        #[rustfmt::skip]
        const NEXT_TRANSITIONS_W8: [[u8; 8]; 2] = [
            [0, 1, 2, 3, 0, 1, 0, 1], // next_ps=0
            [2, 3, 2, 3, 0, 1, 2, 3], // next_ps=1
        ];

        let all_states = all_memory_states();
        assert_eq!(all_states.len(), 8);

        // Test Curr (even layer) transitions: 8 bit states × 8 memory states.
        for row in [false, true] {
            for index in [false, true] {
                for curr_ps in [false, true] {
                    let bit_state_idx =
                        (curr_ps as usize) << 2 | (index as usize) << 1 | row as usize;
                    let bit_state = BitState::Curr {
                        row_bit: row,
                        index_bit: index,
                        curr_col_prefix_sum_bit: curr_ps,
                    };

                    for mem_state in &all_states {
                        let mem_idx = mem_state.get_index();
                        let cpu_result = transition(bit_state, *mem_state);
                        let expected = CURR_TRANSITIONS_W8[bit_state_idx][mem_idx];

                        match cpu_result {
                            StateOrFail::Fail => {
                                assert_eq!(
                                    expected, WIDE_FAIL,
                                    "Curr mismatch at bit_state={bit_state_idx}, mem={mem_idx}: \
                                     CPU=Fail, table={}",
                                    expected
                                );
                            }
                            StateOrFail::State(new_state) => {
                                assert_eq!(
                                    expected,
                                    new_state.get_index() as u8,
                                    "Curr mismatch at bit_state={bit_state_idx}, mem={mem_idx}: \
                                     CPU={}, table={}",
                                    new_state.get_index(),
                                    expected
                                );
                            }
                        }
                    }
                }
            }
        }

        // Test Next (odd layer) transitions: 2 bit states × 8 memory states.
        for next_ps in [false, true] {
            let bit_state_idx = next_ps as usize;
            let bit_state = BitState::Next { next_col_prefix_sum_bit: next_ps };

            for mem_state in &all_states {
                let mem_idx = mem_state.get_index();
                let cpu_result = transition(bit_state, *mem_state);
                let expected = NEXT_TRANSITIONS_W8[bit_state_idx][mem_idx];

                match cpu_result {
                    StateOrFail::Fail => {
                        assert_eq!(
                            expected, WIDE_FAIL,
                            "Next mismatch at bit_state={bit_state_idx}, mem={mem_idx}: \
                             CPU=Fail, table={}",
                            expected
                        );
                    }
                    StateOrFail::State(new_state) => {
                        assert_eq!(
                            expected,
                            new_state.get_index() as u8,
                            "Next mismatch at bit_state={bit_state_idx}, mem={mem_idx}: \
                             CPU={}, table={}",
                            new_state.get_index(),
                            expected
                        );
                    }
                }
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

        println!("=== Curr layer transitions ===");
        for row in [false, true] {
            for index in [false, true] {
                for curr_ps in [false, true] {
                    let bit_state = BitState::Curr {
                        row_bit: row,
                        index_bit: index,
                        curr_col_prefix_sum_bit: curr_ps,
                    };
                    let output_state: Vec<_> =
                        memory_states.iter().map(|ms| transition(bit_state, *ms)).collect();
                    println!(
                        "{}",
                        output_state.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" ")
                    );
                }
            }
        }

        println!("=== Next layer transitions ===");
        for next_ps in [false, true] {
            let bit_state = BitState::Next { next_col_prefix_sum_bit: next_ps };
            let output_state: Vec<_> =
                memory_states.iter().map(|ms| transition(bit_state, *ms)).collect();
            println!(
                "{}",
                output_state.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" ")
            );
        }
    }

    #[test]
    fn test_deinterleave_roundtrip() {
        use super::{deinterleave_prefix_sums, interleave_prefix_sums};

        let mut rng = rand::thread_rng();
        for dim in 1..8 {
            let curr: Point<F> = (0..dim).map(|_| rng.gen::<F>()).collect();
            let next: Point<F> = (0..dim).map(|_| rng.gen::<F>()).collect();
            let interleaved = interleave_prefix_sums(&curr, &next);
            let (curr_out, next_out) = deinterleave_prefix_sums(&interleaved);
            assert_eq!(curr, curr_out);
            assert_eq!(next, next_out);
        }
    }

    #[test]
    fn test_eval_matches_eval_interleaved() {
        use slop_algebra::extension::BinomialExtensionField;

        use super::{interleave_prefix_sums, BranchingProgram};

        type EF = BinomialExtensionField<F, 4>;

        let mut rng = rand::thread_rng();
        for log_m in 1..7 {
            let z_row: Point<EF> = (0..log_m).map(|_| rng.gen::<EF>()).collect();
            let z_index: Point<EF> = (0..log_m).map(|_| rng.gen::<EF>()).collect();
            let bp = BranchingProgram::new(z_row, z_index);

            for _ in 0..5 {
                let prefix_sum: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();
                let next_prefix_sum: Point<EF> = (0..log_m + 1).map(|_| rng.gen::<EF>()).collect();
                let interleaved = interleave_prefix_sums(&prefix_sum, &next_prefix_sum);

                let eval_result = bp.eval(&prefix_sum, &next_prefix_sum);
                let interleaved_result = bp.eval_interleaved(&interleaved);
                assert_eq!(eval_result, interleaved_result);
            }
        }
    }
}
