//! Width-4 branching program for `full_geq(prefix_sum, next_prefix_sum)`.
//!
//! Reads bits in the interleaved layout used by the assist (even layer ⇒
//! `prefix_sum` bit, odd layer ⇒ `next_prefix_sum` bit), so its prefix/suffix
//! machinery composes with the assist BP's on the same pass.
//!
//! State encoding (2 bits): `(cso << 1) | saved`, where `cso` is "geq so far"
//! and `saved` is the prefix_sum bit being held between an even and the
//! following odd layer. Iteration is LSB→MSB; a higher (more-significant)
//! differing bit overrides the lower decision. Initial state at the start of
//! the BP is `(cso=1, saved=0)` (default GEQ for equality); the only
//! reachable state at the end of a Next layer is `(cso=accept, saved=0)`.

use std::array;

use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use slop_multilinear::{full_geq, Mle, Point};

/// Compute `Σ_{c < n} z_col_lagrange[c]` for a column hypercube of dimension
/// `z_col.dimension()`, using the closed-form `1 - full_geq(n_as_point, z_col)`.
///
/// The naive form breaks at the hypercube boundary because `n` doesn't fit in
/// `z_col.dimension()` bits when `n == 2^d`. This helper handles both edges:
///
/// - `n == 0` → 0 (empty prefix sums to nothing).
/// - `n >= 2^d` → 1 (full hypercube sums to one).
/// - otherwise → `1 - full_geq(Point::from_usize(n, d), z_col)`.
///
/// Mathematically equivalent to taking the first `n` entries of the partial
/// Lagrange evaluation of `z_col` and summing them, but avoids materializing
/// the `2^d`-sized Lagrange table.
pub fn sum_z_first_n_via_geq<F: Field, EF: ExtensionField<F>>(n: usize, z_col: &Point<EF>) -> EF {
    let d = z_col.dimension();
    if n == 0 {
        return EF::zero();
    }
    if n >= 1usize << d {
        return EF::one();
    }
    let threshold: Point<F> = Point::from_usize(n, d);
    EF::one() - full_geq(&threshold, z_col)
}

/// Width of the geq BP state vector.
pub const GEQ_BP_WIDTH: usize = 4;

/// Index of the initial state at the start of the prover's BP iteration
/// (`cso=1, saved=0`). Also the only reachable accepting state at the end.
pub const GEQ_INITIAL_STATE_INDEX: usize = 2;

/// `CURR_TRANSITIONS_GEQ[p][s_in] = s_out` for the even layer that saves the
/// prefix_sum bit. The transition keeps `cso` and overwrites `saved` with `p`.
pub const CURR_TRANSITIONS_GEQ: [[u8; 4]; 2] = [
    // p=0: saved becomes 0, cso unchanged
    [0, 0, 2, 2],
    // p=1: saved becomes 1, cso unchanged
    [1, 1, 3, 3],
];

/// `NEXT_TRANSITIONS_GEQ[n][s_in] = s_out` for the odd layer that compares
/// `saved` against `n`. If they agree, `cso` is unchanged; otherwise it
/// becomes `n` (the more-significant differing bit wins). `saved` resets to 0.
pub const NEXT_TRANSITIONS_GEQ: [[u8; 4]; 2] = [
    // n=0
    //   s_in=(cso=0,s=0): equal → cso=0, s=0 → 0
    //   s_in=(cso=0,s=1): differ → cso=n=0, s=0 → 0
    //   s_in=(cso=1,s=0): equal → cso=1, s=0 → 2
    //   s_in=(cso=1,s=1): differ → cso=n=0, s=0 → 0
    [0, 0, 2, 0],
    // n=1
    //   s_in=(cso=0,s=0): differ → cso=n=1, s=0 → 2
    //   s_in=(cso=0,s=1): equal → cso=0, s=0 → 0
    //   s_in=(cso=1,s=0): differ → cso=n=1, s=0 → 2
    //   s_in=(cso=1,s=1): equal → cso=1, s=0 → 2
    [2, 0, 2, 2],
];

/// Combined per-(curr_ps, next_ps) layer transition used by the width-4
/// verifier-side eval: equivalent to `CURR` followed by `NEXT`. Indexing
/// `i = (next_ps << 1) | curr_ps` matches the `Mle::blocking_partial_lagrange`
/// ordering for `point = [next_ps, curr_ps]`. Output saved is always 0.
pub const COMBINED_TRANSITIONS_GEQ: [[u8; 4]; 4] = [
    // (curr=0, next=0): equal → cso unchanged, s=0
    [0, 0, 2, 2],
    // (curr=1, next=0): differ → cso=n=0
    [0, 0, 0, 0],
    // (curr=0, next=1): differ → cso=n=1
    [2, 2, 2, 2],
    // (curr=1, next=1): equal → cso unchanged
    [0, 0, 2, 2],
];

/// Branching-program representation of `full_geq(prefix_sum, next_prefix_sum)`.
///
/// Carries only `num_vars` (the bit-width of each prefix sum) — there is no
/// `z_row`/`z_index` because the BP reads only prefix_sum and next_prefix_sum
/// bits.
#[derive(Debug, Clone)]
pub struct GeqBranchingProgram {
    pub(crate) num_vars: usize,
}

impl GeqBranchingProgram {
    pub fn new(num_vars: usize) -> Self {
        Self { num_vars }
    }

    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Multilinear-extension evaluation at `(prefix_sum, next_prefix_sum)`.
    /// Uses the combined (curr, next) per-layer transition table; iterates
    /// MSB→LSB to fold the layers backward, returning `state[2]`, the value
    /// at the BP's initial state.
    pub fn eval<K: AbstractField + Clone + 'static>(
        &self,
        prefix_sum: &Point<K>,
        next_prefix_sum: &Point<K>,
    ) -> K {
        let mut state: [K; GEQ_BP_WIDTH] = array::from_fn(|_| K::zero());
        // Base case at the end of the BP: only `(cso=1, saved=0) = 2` is
        // reachable and it is accepting; assign it weight 1.
        state[GEQ_INITIAL_STATE_INDEX] = K::one();

        for layer in (0..self.num_vars).rev() {
            let point: Point<K> =
                [Self::get_ith_lsb(next_prefix_sum, layer), Self::get_ith_lsb(prefix_sum, layer)]
                    .into_iter()
                    .collect();

            let two_var_eq: Mle<K> = Mle::blocking_partial_lagrange(&point);
            let eq_slice = two_var_eq.guts().as_slice();

            let mut new_state: [K; GEQ_BP_WIDTH] = array::from_fn(|_| K::zero());
            for s_in in 0..GEQ_BP_WIDTH {
                // accum_elems[t] = sum over (curr,next) of eq * indicator(transition(s_in, (curr,next)) == t)
                let mut accum_elems: [K; GEQ_BP_WIDTH] = array::from_fn(|_| K::zero());
                for (i, eq_val) in eq_slice.iter().enumerate() {
                    let s_out = COMBINED_TRANSITIONS_GEQ[i][s_in] as usize;
                    accum_elems[s_out] += eq_val.clone();
                }
                let accum = accum_elems
                    .iter()
                    .zip(state.iter())
                    .fold(K::zero(), |acc, (e, s)| acc + e.clone() * s.clone());
                new_state[s_in] = accum;
            }
            state = new_state;
        }

        state[GEQ_INITIAL_STATE_INDEX].clone()
    }

    /// Backward DP filling each layer's state vector for a single `(curr, next)` pair.
    ///
    /// Layout matches the assist's `precompute_prefix_states`: a flat
    /// `(num_layers + 1) * GEQ_BP_WIDTH` buffer where entry
    /// `[num_layers]` is the accepting base case and entry `[0]` holds the
    /// final V values at the bottom layer (where the prover starts).
    pub fn precompute_prefix_states<F: Field + 'static, K>(
        &self,
        curr: usize,
        next: usize,
    ) -> Vec<K>
    where
        K: AbstractExtensionField<F> + Clone + 'static,
    {
        let num_layers = 2 * self.num_vars;
        let w = GEQ_BP_WIDTH;
        let mut states: Vec<K> = vec![K::zero(); (num_layers + 1) * w];

        let mut current_state: [K; GEQ_BP_WIDTH] = array::from_fn(|_| K::zero());
        // Base case: only `(cso=1, saved=0) = 2` is reachable at the end.
        current_state[GEQ_INITIAL_STATE_INDEX] = K::one();
        states[num_layers * w..(num_layers + 1) * w].clone_from_slice(&current_state);

        for layer in (0..num_layers).rev() {
            let bit_src = if layer & 1 == 0 { curr } else { next };
            let bit_val = F::from_canonical_usize((bit_src >> (layer >> 1)) & 1);
            current_state = self.apply_layer_step::<F, K>(layer, bit_val, &current_state);
            states[layer * w..(layer + 1) * w].clone_from_slice(&current_state);
        }

        states
    }

    /// One backward DP step at `layer`, parameterized by the per-layer bit
    /// variable `interleaved_val` (boolean for the precompute, the round
    /// challenge for sumcheck round univariates).
    ///
    /// `new_state[s_in] = (1 − v) · state[trans[0][s_in]] + v · state[trans[1][s_in]]`.
    pub fn apply_layer_step<F: Field + 'static, K>(
        &self,
        layer: usize,
        interleaved_val: F,
        state: &[K],
    ) -> [K; GEQ_BP_WIDTH]
    where
        K: AbstractExtensionField<F> + Clone + 'static,
    {
        let transitions =
            if layer & 1 == 0 { &CURR_TRANSITIONS_GEQ } else { &NEXT_TRANSITIONS_GEQ };
        let factor_0 = F::one() - interleaved_val;
        let factor_1 = interleaved_val;

        let mut new_state: [K; GEQ_BP_WIDTH] = array::from_fn(|_| K::zero());
        for s_in in 0..GEQ_BP_WIDTH {
            let t0 = transitions[0][s_in] as usize;
            let t1 = transitions[1][s_in] as usize;
            // K::AbstractExtensionField<F> => `state[t] * F` is base-field scaling.
            new_state[s_in] = state[t0].clone() * factor_0 + state[t1].clone() * factor_1;
        }
        new_state
    }

    /// Transposed step used to extend the suffix vector by one layer after the
    /// round challenge `interleaved_val` (an extension-field scalar) is sampled.
    ///
    /// `result[s_out] = Σ_s suffix[s] · factor(s, s_out)`, pushing contributions
    /// forward through the transition graph.
    pub fn apply_layer_step_transposed<K: AbstractField + Clone>(
        &self,
        layer: usize,
        interleaved_val: K,
        suffix: &[K],
    ) -> [K; GEQ_BP_WIDTH] {
        let transitions =
            if layer & 1 == 0 { &CURR_TRANSITIONS_GEQ } else { &NEXT_TRANSITIONS_GEQ };
        let factor_0 = K::one() - interleaved_val.clone();
        let factor_1 = interleaved_val;

        let mut result: [K; GEQ_BP_WIDTH] = array::from_fn(|_| K::zero());
        for s_in in 0..GEQ_BP_WIDTH {
            let t0 = transitions[0][s_in] as usize;
            let t1 = transitions[1][s_in] as usize;
            result[t0] += suffix[s_in].clone() * factor_0.clone();
            result[t1] += suffix[s_in].clone() * factor_1.clone();
        }
        result
    }

    /// Round univariate evaluator: applies the lambda layer step to the cached
    /// prefix state, then dots with the suffix vector.
    pub fn eval_with_cached<F: Field + 'static, K>(
        &self,
        layer: usize,
        lambda: F,
        prefix_state: &[K],
        suffix_vector: &[K],
    ) -> K
    where
        K: AbstractExtensionField<F> + Clone + 'static,
    {
        let after_lambda = self.apply_layer_step::<F, K>(layer, lambda, prefix_state);
        suffix_vector
            .iter()
            .zip(after_lambda.iter())
            .fold(K::zero(), |acc, (s, a)| acc + s.clone() * a.clone())
    }

    fn get_ith_lsb<T: AbstractField + Clone + 'static>(point: &Point<T>, i: usize) -> T {
        let dim = point.dimension();
        if dim <= i {
            T::zero()
        } else {
            point.get(dim - i - 1).expect("index out of bounds").clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slop_algebra::extension::BinomialExtensionField;
    use slop_baby_bear::BabyBear;

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;

    /// Boolean sanity check: BP evaluated on bit-decomposed integers matches
    /// the integer comparison `next >= curr`.
    #[test]
    fn boolean_eval_matches_integer_geq() {
        let num_vars = 5;
        let bp = GeqBranchingProgram::new(num_vars);

        for curr in 0..(1u64 << num_vars) {
            for next in 0..(1u64 << num_vars) {
                let curr_pt: Point<F> = Point::from_usize(curr as usize, num_vars);
                let next_pt: Point<F> = Point::from_usize(next as usize, num_vars);
                let bp_val = bp.eval::<F>(&curr_pt, &next_pt);
                let expected = if next >= curr { F::one() } else { F::zero() };
                assert_eq!(
                    bp_val, expected,
                    "geq BP mismatch: curr={curr}, next={next}, bp={bp_val}, exp={expected}"
                );
            }
        }
    }

    /// `precompute_prefix_states` followed by no remaining work should produce
    /// the same evaluation as the verifier-side `eval` over EF inputs lifted
    /// from the boolean points.
    #[test]
    fn precompute_then_dot_matches_eval() {
        let num_vars = 4;
        let bp = GeqBranchingProgram::new(num_vars);

        for curr in [0usize, 1, 5, 7, 12, 15] {
            for next in [0usize, 1, 5, 7, 12, 15] {
                let states = bp.precompute_prefix_states::<F, EF>(curr, next);
                // States are EF — state[GEQ_INITIAL_STATE_INDEX] at layer 0 is the BP eval.
                let actual = states[GEQ_INITIAL_STATE_INDEX];
                let expected = if next >= curr { EF::one() } else { EF::zero() };
                assert_eq!(
                    actual, expected,
                    "precompute mismatch: curr={curr}, next={next}, got={actual}, exp={expected}"
                );
            }
        }
    }

    /// Prefix * suffix factorization: at any "split" layer, dotting the
    /// prefix_states[layer+1] (above) with the suffix obtained by propagating
    /// the bit-eq factors through layers 0..layer should recover the same
    /// BP eval as a single-shot eval.
    #[test]
    fn prefix_suffix_factorization() {
        let num_vars = 4;
        let bp = GeqBranchingProgram::new(num_vars);
        let curr = 6usize;
        let next = 11usize;

        let prefix_states = bp.precompute_prefix_states::<F, EF>(curr, next);

        // Build suffix from the BOTTOM up to a chosen split layer by repeatedly
        // applying the transposed step with boolean inputs.
        let mut suffix: [EF; GEQ_BP_WIDTH] = array::from_fn(|_| EF::zero());
        suffix[GEQ_INITIAL_STATE_INDEX] = EF::one();

        let split_layer = 3; // any layer in [0, num_layers]
        for layer in 0..split_layer {
            let bit_src = if layer & 1 == 0 { curr } else { next };
            let bit_val = EF::from(F::from_canonical_usize((bit_src >> (layer >> 1)) & 1));
            suffix = bp.apply_layer_step_transposed(layer, bit_val, &suffix);
        }

        // Dot suffix with prefix_states[split_layer].
        let dotted: EF = (0..GEQ_BP_WIDTH)
            .map(|s| suffix[s] * prefix_states[split_layer * GEQ_BP_WIDTH + s])
            .sum();

        let expected = if next >= curr { EF::one() } else { EF::zero() };
        assert_eq!(dotted, expected);
    }
}
