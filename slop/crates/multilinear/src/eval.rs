use rayon::prelude::*;
use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::{buffer, Buffer, CpuBackend};
use slop_tensor::{dot_along_dim, Dimensions, Tensor};

use crate::{partial_eq_with_basis, partial_lagrange, Basis, Point};

/// Evaluates the MLE at a given point.
pub fn eval_mle_at_point<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync + 'static,
    EF: AbstractExtensionField<F> + Send + Sync + 'static,
{
    // Compute the eq(b, point) polynomial.
    let partial_lagrange = partial_lagrange(point);
    // Evaluate the mle via a dot product with the partial lagrange polynomial.
    dot_along_dim(mle, &partial_lagrange, 0)
}

/// Evaluates the MLE at a given eq polynomial.
pub fn eval_mle_at_eq<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    eq: &Tensor<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync + 'static,
    EF: AbstractExtensionField<F> + Send + Sync + 'static,
{
    // Evaluate the mle via a dot product with the eq polynomial.
    dot_along_dim(mle, eq, 0)
}

/// Returns a tensor of zero evaluations.
pub fn zero_evaluations<F: AbstractField>(num_polynomials: usize) -> Tensor<F, CpuBackend> {
    Tensor::zeros_in([num_polynomials], CpuBackend)
}

pub fn eval_mle_at_point_with_basis<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
    basis: Basis,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
{
    let partial_lagrange = partial_eq_with_basis(point, basis);
    let mut sizes = mle.sizes().to_vec();
    sizes.remove(0);
    let dimensions = Dimensions::try_from(sizes).unwrap();
    let mut dst = Tensor { storage: buffer![], dimensions };
    let total_len = dst.total_len();
    let dot_products = if total_len == 1 {
        // A single output does not need a one-element allocation for every input row.
        let sum = mle
            .as_buffer()
            .par_iter()
            .zip(partial_lagrange.as_buffer().par_iter())
            .map(|(value, scalar)| scalar.clone() * value.clone())
            .sum::<EF>();
        vec![sum]
    } else {
        mle.as_buffer()
            .par_chunks_exact(mle.strides()[0])
            .zip(partial_lagrange.as_buffer().par_iter())
            .map(|(chunk, scalar)| chunk.iter().map(|a| scalar.clone() * a.clone()).collect())
            .reduce(
                || vec![EF::zero(); total_len],
                |mut a, b| {
                    a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += b.clone());
                    a
                },
            )
    };

    let dot_products = Buffer::from(dot_products);
    dst.storage = dot_products;
    dst
}

/// Alias for `eval_mle_at_point` for backwards compatibility.
pub fn eval_mle_at_point_blocking<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync + 'static,
    EF: AbstractExtensionField<F> + Send + Sync + 'static,
{
    eval_mle_at_point(mle, point)
}

/// Alias for `eval_mle_at_point_with_basis` for backwards compatibility.
pub fn eval_mle_at_point_blocking_with_basis<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
    basis: Basis,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
{
    eval_mle_at_point_with_basis(mle, point, basis)
}

/// Interpreting the internal vector of `mle` as the monomial-basis coefficients of a multilinear
/// polynomial, evaluate that multilinear at `point`.
pub fn eval_monomial_basis_mle_at_point<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
{
    eval_mle_at_point_with_basis(mle, point, Basis::Monomial)
}

/// Alias for backwards compatibility.
pub fn eval_monomial_basis_mle_at_point_blocking<F, EF>(
    mle: &Tensor<F, CpuBackend>,
    point: &Point<EF, CpuBackend>,
) -> Tensor<EF, CpuBackend>
where
    F: AbstractField + Sync,
    EF: AbstractExtensionField<F> + Send + Sync,
{
    eval_monomial_basis_mle_at_point(mle, point)
}

#[cfg(test)]
mod tests {
    use rayon::ThreadPoolBuilder;
    use slop_algebra::{extension::BinomialExtensionField, ExtensionField, Field};
    use slop_baby_bear::BabyBear;

    use super::*;

    fn assert_eval_matches_reference<F: Field, EF: ExtensionField<F>>(
        mle: &Tensor<F, CpuBackend>,
        point: &Point<EF, CpuBackend>,
        basis: Basis,
    ) {
        let width = mle.strides()[0];
        let mut expected = vec![EF::zero(); width];
        for (row, values) in mle.as_slice().chunks_exact(width).enumerate() {
            // Compute each basis weight independently, using big-endian row-index bits.
            let weight: EF = point
                .iter()
                .enumerate()
                .map(|(i, coordinate)| {
                    if row & (1 << (point.dimension() - i - 1)) != 0 {
                        *coordinate
                    } else {
                        match basis {
                            Basis::Evaluation => EF::one() - *coordinate,
                            Basis::Monomial => EF::one(),
                        }
                    }
                })
                .product();
            for (sum, value) in expected.iter_mut().zip(values) {
                *sum += weight * *value;
            }
        }

        let actual = eval_mle_at_point_with_basis(mle, point, basis);
        assert_eq!(actual.sizes(), &mle.sizes()[1..]);
        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_eval_with_basis_matches_reference() {
        type EF = BinomialExtensionField<BabyBear, 4>;

        for threads in [1, 4] {
            let pool = ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            pool.install(|| {
                for (sizes, dimension) in [
                    (vec![0, 1], 0),
                    (vec![0, 3], 0),
                    (vec![1], 0),
                    (vec![1, 2, 3], 0),
                    (vec![3, 2, 3], 2),
                    (vec![8], 3),
                    (vec![8, 3], 3),
                    (vec![8, 2, 3], 3),
                    (vec![257], 9),
                    (vec![257, 1, 1], 9),
                    (vec![257, 2, 3], 9),
                ] {
                    let values: Vec<_> = (0..sizes.iter().product())
                        .map(|i| BabyBear::from_canonical_usize((7 * i + 3) % 101))
                        .collect();
                    let mle = Tensor::from(values).reshape(&sizes);
                    let extension_mle = Tensor::from(
                        mle.as_slice()
                            .iter()
                            .map(|value| {
                                EF::from_base_fn(|j| *value + BabyBear::from_canonical_usize(j))
                            })
                            .collect::<Vec<_>>(),
                    )
                    .reshape(&sizes);
                    let point = Point::from(
                        (0..dimension).map(BabyBear::from_canonical_usize).collect::<Vec<_>>(),
                    );
                    let extension_point = Point::from(
                        (0..dimension)
                            .map(|i| {
                                EF::from_base_fn(|j| BabyBear::from_canonical_usize(3 * i + j + 2))
                            })
                            .collect::<Vec<_>>(),
                    );

                    assert_eval_matches_reference(&mle, &point, Basis::Evaluation);
                    assert_eval_matches_reference(&mle, &point, Basis::Monomial);
                    assert_eval_matches_reference(&mle, &extension_point, Basis::Evaluation);
                    assert_eval_matches_reference(&mle, &extension_point, Basis::Monomial);
                    assert_eval_matches_reference(
                        &extension_mle,
                        &extension_point,
                        Basis::Evaluation,
                    );
                    assert_eval_matches_reference(
                        &extension_mle,
                        &extension_point,
                        Basis::Monomial,
                    );
                }
            });
        }
    }
}
