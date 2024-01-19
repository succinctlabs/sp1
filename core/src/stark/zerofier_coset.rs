use p3_field::{cyclic_subgroup_coset_known_order, Field, PackedField, TwoAdicField};

use super::util::batch_multiplicative_inverse;

/// Precomputations of the evaluation of `Z_H(X) = X^n - 1` on a coset `s K` with `H <= K`.
pub struct ZerofierOnCoset<F: Field> {
    /// `n = |H|`.
    log_n: usize,
    /// `rate = |K|/|H|`.
    rate_bits: usize,
    coset_shift: F,
    /// Holds `g^n * (w^n)^i - 1 = g^n * v^i - 1` for `i in 0..rate`, with `w` a generator of `K` and `v` a
    /// `rate`-primitive root of unity.
    evals: Vec<F>,
    /// Holds the multiplicative inverses of `evals`.
    inverses: Vec<F>,
}

impl<F: TwoAdicField> ZerofierOnCoset<F> {
    pub fn new(log_n: usize, rate_bits: usize, coset_shift: F) -> Self {
        let s_pow_n = coset_shift.exp_power_of_2(log_n);
        let evals = F::two_adic_generator(rate_bits)
            .powers()
            .take(1 << rate_bits)
            .map(|x| s_pow_n * x - F::one())
            .collect::<Vec<_>>();
        let inverses = batch_multiplicative_inverse(evals.clone());
        Self {
            log_n,
            rate_bits,
            coset_shift,
            evals,
            inverses,
        }
    }

    /// Returns `Z_H(g * w^i)`.
    pub fn eval(&self, i: usize) -> F {
        self.evals[i & ((1 << self.rate_bits) - 1)]
    }

    /// Returns `1 / Z_H(g * w^i)`.
    pub fn eval_inverse(&self, i: usize) -> F {
        self.inverses[i & ((1 << self.rate_bits) - 1)]
    }

    /// Like `eval_inverse`, but for a range of indices starting with `i_start`.
    pub fn eval_inverse_packed<P: PackedField<Scalar = F>>(&self, i_start: usize) -> P {
        let mut packed = P::zero();
        packed
            .as_slice_mut()
            .iter_mut()
            .enumerate()
            .for_each(|(j, packed_j)| *packed_j = self.eval_inverse(i_start + j));
        packed
    }

    /// Evaluate the Langrange basis polynomial, `L_i(x) = Z_H(x) / (x - g_H^i)`, on our coset `s K`.
    /// Here `L_i(x)` is unnormalized in the sense that it evaluates to some nonzero value at `g_H^i`,
    /// not necessarily 1.
    pub(crate) fn lagrange_basis_unnormalized(&self, i: usize) -> Vec<F> {
        let log_coset_size = self.log_n + self.rate_bits;
        let coset_size = 1 << log_coset_size;
        let g_h = F::two_adic_generator(self.log_n);
        let g_k = F::two_adic_generator(log_coset_size);

        let target_point = g_h.exp_u64(i as u64);
        let denominators = cyclic_subgroup_coset_known_order(g_k, self.coset_shift, coset_size)
            .map(|x| x - target_point)
            .collect::<Vec<_>>();
        let inverses = batch_multiplicative_inverse(denominators);

        self.evals
            .iter()
            .cycle()
            .zip(inverses)
            .map(|(&z_h, inv)| z_h * inv)
            .collect()
    }
}
