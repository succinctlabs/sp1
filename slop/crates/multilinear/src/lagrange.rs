use slop_algebra::AbstractField;
use slop_alloc::{Backend, CpuBackend};
use slop_tensor::Tensor;

use crate::{Basis, Point};

pub trait PartialLagrangeBackend<F>: Backend {
    fn partial_lagrange(point: &Point<F, Self>) -> Tensor<F, Self>;
}

impl<F: AbstractField> PartialLagrangeBackend<F> for CpuBackend {
    fn partial_lagrange(point: &Point<F, CpuBackend>) -> Tensor<F, CpuBackend> {
        partial_lagrange(point)
    }
}

/// Computes the partial lagrange polynomial eq(z, -) for a fixed z.
pub fn partial_lagrange<F: AbstractField>(point: &Point<F, CpuBackend>) -> Tensor<F, CpuBackend> {
    partial_eq_with_basis(point, Basis::Evaluation)
}

/// Computes the monomial basis partial eq.
pub fn monomial_basis_partial_eq<F: AbstractField>(
    point: &Point<F, CpuBackend>,
) -> Tensor<F, CpuBackend> {
    partial_eq_with_basis(point, Basis::Monomial)
}

pub fn partial_eq_with_basis<F: AbstractField>(
    point: &Point<F, CpuBackend>,
    basis: Basis,
) -> Tensor<F, CpuBackend> {
    let one = F::one();
    let mut evals = Vec::with_capacity(1 << point.dimension());
    evals.push(one);

    // Build evals in num_variables rounds. In each round, we consider one more entry of `point`,
    // hence the zip.
    point.iter().for_each(|coordinate| {
        evals = evals
            .iter()
            // For each value in the previous round, multiply by (1-coordinate) and coordinate,
            // and collect all these values into a new vec.
            // For the monomial basis, do a slightly different computation.
            .flat_map(|val| {
                let prod = val.clone() * coordinate.clone();
                match basis {
                    Basis::Evaluation => [val.clone() - prod.clone(), prod.clone()],
                    Basis::Monomial => [val.clone(), prod],
                }
            })
            .collect();
    });
    Tensor::from(evals).reshape([1 << point.dimension(), 1])
}

/// Given `point = [x_1,...,x_n]`, this function computes the 2^m-length vector `v` such that
/// `v[i] = prod_j ((1-i_j)(1-x_j) + x_j^{i_j})` where `i = (i_1,...,i_n)` is the big-endian binary
/// representation of the index `i`.
///
/// Alias for `partial_lagrange` for backwards compatibility.
pub fn partial_lagrange_blocking<F: AbstractField>(
    point: &Point<F, CpuBackend>,
) -> Tensor<F, CpuBackend> {
    partial_lagrange(point)
}

/// Given `point = [x_1,...,x_n]`, this function computes the 2^m-length vector `v` such that
/// `v[i] = x_1^{i_1} * ... * x_n^{i_n}` where `i = (i_1,...,i_n)` is the big-endian binary
/// representation of the index `i`.
///
/// Alias for `monomial_basis_partial_eq` for backwards compatibility.
pub fn monomial_basis_evals_blocking<F: AbstractField>(
    point: &Point<F, CpuBackend>,
) -> Tensor<F, CpuBackend> {
    monomial_basis_partial_eq(point)
}

/// Alias for `partial_eq_with_basis` for backwards compatibility.
pub fn partial_eq_blocking_with_basis<F: AbstractField>(
    point: &Point<F, CpuBackend>,
    basis: Basis,
) -> Tensor<F, CpuBackend> {
    partial_eq_with_basis(point, basis)
}
