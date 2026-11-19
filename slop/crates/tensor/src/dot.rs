use rayon::prelude::*;

use slop_algebra::{AbstractExtensionField, AbstractField};
use slop_alloc::{buffer, Buffer, CpuBackend};

use crate::{Dimensions, Tensor};

/// Compute the dot product of a tensor with a scalar tensor along a given dimension.
///
/// This scalar tensor is assumed to be a `1D` tensor, which is any tensor of a shape
/// `[len, 1, 1, 1,..]`.
pub fn dot_along_dim<T, U>(
    src: &Tensor<T, CpuBackend>,
    scalars: &Tensor<U, CpuBackend>,
    dim: usize,
) -> Tensor<U, CpuBackend>
where
    T: AbstractField + 'static + Sync,
    U: AbstractExtensionField<T> + 'static + Send + Sync,
{
    let mut sizes = src.sizes().to_vec();
    sizes.remove(dim);
    let dimensions = Dimensions::try_from(sizes).unwrap();
    let mut dst = Tensor { storage: buffer![], dimensions };
    let max_scalar_dim = *scalars.sizes().iter().max().unwrap();
    assert_eq!(max_scalar_dim, scalars.total_len(), "The scalar tensor must be a 1D tensor");
    match dim {
        0 => {
            assert!(
                src.sizes().len() <= 2,
                "Only 1D and 2D dimensional tensors are supported for dim 0"
            );
            let total_len = dst.total_len();
            let dot_products = if total_len == 1 {
                // A single output does not need a one-element allocation for every input row.
                let sum = src
                    .as_buffer()
                    .par_iter()
                    .zip(scalars.as_buffer().par_iter())
                    .map(|(value, scalar)| scalar.clone() * value.clone())
                    .sum::<U>();
                vec![sum]
            } else {
                src.as_buffer()
                    .par_chunks_exact(src.strides()[0])
                    .zip(scalars.as_buffer().par_iter())
                    .map(|(chunk, scalar)| {
                        chunk.iter().map(|a| scalar.clone() * a.clone()).collect()
                    })
                    .reduce(
                        || vec![U::zero(); total_len],
                        |mut a, b| {
                            a.iter_mut().zip(b.iter()).for_each(|(a, b)| *a += b.clone());
                            a
                        },
                    )
            };

            let dot_products = Buffer::from(dot_products);
            dst.storage = dot_products;
        }
        dim if dim == src.sizes().len() - 1 => {
            let mut dst_storage = Vec::<U>::with_capacity(dst.total_len());
            src.as_buffer()
                .par_chunks_exact(src.strides()[dim - 1])
                .map(|chunk| {
                    scalars
                        .as_buffer()
                        .iter()
                        .zip(chunk.iter())
                        .map(|(a, b)| a.clone() * b.clone())
                        .sum::<U>()
                })
                .collect_into_vec(&mut dst_storage);
            dst.storage = Buffer::from(dst_storage);
        }
        _ => {
            panic!("Unsupported dot product dimension {} for tensor sizes: {:?}", dim, src.sizes())
        }
    }
    dst
}

#[cfg(test)]
mod tests {
    use rayon::ThreadPoolBuilder;
    use slop_algebra::{extension::BinomialExtensionField, AbstractField, ExtensionField, Field};
    use slop_baby_bear::BabyBear;

    use super::*;

    fn assert_dot_along_dim_0_matches_reference<F: Field, EF: ExtensionField<F>>(
        tensor: &Tensor<F, CpuBackend>,
        scalars: &Tensor<EF, CpuBackend>,
    ) {
        let width = tensor.strides()[0];
        let expected: Vec<EF> = (0..width)
            .map(|column| {
                scalars
                    .as_slice()
                    .iter()
                    .take(tensor.sizes()[0])
                    .enumerate()
                    .map(|(row, scalar)| *scalar * tensor.as_slice()[row * width + column])
                    .sum()
            })
            .collect();
        let actual = dot_along_dim(tensor, scalars, 0);
        assert_eq!(actual.sizes(), &tensor.sizes()[1..]);
        assert_eq!(actual.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_dot_along_dim_0_matches_reference() {
        type EF = BinomialExtensionField<BabyBear, 4>;

        for threads in [1, 4] {
            let pool = ThreadPoolBuilder::new().num_threads(threads).build().unwrap();
            pool.install(|| {
                // Longer scalar tensors model MLEs whose missing rows are implicitly zero.
                for (rows, width, scalar_count) in [
                    (0, 1, 1),
                    (1, 1, 1),
                    (3, 1, 0),
                    (3, 8, 8),
                    (17, 1, 9),
                    (17, 1, 32),
                    (17, 7, 9),
                    (17, 7, 32),
                    (32, 1, 32),
                    (1500, 1, 2048),
                    (1500, 10, 2048),
                ] {
                    let values: Vec<_> = (0..rows * width)
                        .map(|i| BabyBear::from_canonical_usize((7 * i + 3) % 101))
                        .collect();
                    let tensor = Tensor::from(values).reshape([rows, width]);
                    let scalars = Tensor::from(
                        (0..scalar_count)
                            .map(|i| BabyBear::from_canonical_usize((11 * i + 5) % 103))
                            .collect::<Vec<_>>(),
                    );
                    let extension_scalars = Tensor::from(
                        (0..scalar_count)
                            .map(|i| {
                                EF::from_base_fn(|j| {
                                    BabyBear::from_canonical_usize((13 * i + 17 * j + 1) % 107)
                                })
                            })
                            .collect::<Vec<_>>(),
                    );
                    let extension_tensor = Tensor::from(
                        tensor
                            .as_slice()
                            .iter()
                            .map(|value| {
                                EF::from_base_fn(|j| *value + BabyBear::from_canonical_usize(j))
                            })
                            .collect::<Vec<_>>(),
                    )
                    .reshape([rows, width]);

                    assert_dot_along_dim_0_matches_reference(&tensor, &scalars);
                    assert_dot_along_dim_0_matches_reference(&tensor, &extension_scalars);
                    assert_dot_along_dim_0_matches_reference(&extension_tensor, &extension_scalars);

                    if width == 1 {
                        assert_dot_along_dim_0_matches_reference(
                            &tensor.reshape([rows]),
                            &extension_scalars,
                        );
                    }
                }

                // Repeated rows cancel exactly, including a value close to the field modulus.
                let repeated = Tensor::from(vec![-BabyBear::from_canonical_u32(7); 32]);
                let signs = Tensor::from(
                    (0..32)
                        .map(|i| if i % 2 == 0 { BabyBear::one() } else { -BabyBear::one() })
                        .collect::<Vec<_>>(),
                );
                assert_dot_along_dim_0_matches_reference(&repeated, &signs);
                assert_eq!(dot_along_dim(&repeated, &signs, 0).as_slice(), &[BabyBear::zero()]);

                let extension = EF::from_base_fn(|j| BabyBear::from_canonical_usize(j + 1));
                let extension_signs = Tensor::from(
                    (0..32)
                        .map(|i| if i % 2 == 0 { extension } else { -extension })
                        .collect::<Vec<_>>(),
                );
                assert_dot_along_dim_0_matches_reference(&repeated, &extension_signs);
                assert_eq!(
                    dot_along_dim(&repeated, &extension_signs, 0).as_slice(),
                    &[EF::zero()],
                );
            });
        }
    }

    #[test]
    fn test_dot_along_dim_0() {
        let mut rng = rand::thread_rng();
        let tensor = Tensor::<BabyBear, CpuBackend>::rand(&mut rng, [1500, 10]);
        let scalars = Tensor::<BabyBear, CpuBackend>::rand(&mut rng, [1500]);
        let dot = dot_along_dim(&tensor, &scalars, 0);
        for j in 0..10 {
            let mut dot_product = BabyBear::zero();
            for i in 0..1500 {
                dot_product += *scalars[[i]] * *tensor[[i, j]];
            }
            assert_eq!(*dot[[j]], dot_product);
        }
    }

    #[test]
    fn test_dot_along_dim_last() {
        let mut rng = rand::thread_rng();
        let tensor = Tensor::<BabyBear, CpuBackend>::rand(&mut rng, [10, 1500, 10]);
        let scalars = Tensor::<BabyBear, CpuBackend>::rand(&mut rng, [10]);
        let dot = dot_along_dim(&tensor, &scalars, 2);
        for k in 0..10 {
            for i in 0..1500 {
                let mut dot_product = BabyBear::zero();
                for j in 0..10 {
                    dot_product += *scalars[[j]] * *tensor[[k, i, j]];
                }
                assert_eq!(*dot[[k, i]], dot_product);
            }
        }
    }
}
