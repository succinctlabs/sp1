use std::{mem::ManuallyDrop, sync::Arc};

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use slop_alloc::{Backend, CpuBackend, HasBackend, GLOBAL_CPU_BACKEND};
use slop_tensor::Tensor;

use crate::{
    eval_mle_at_eq, full_geq, mle_fix_last_variable, mle_fix_last_variable_constant_padding,
    partial_lagrange, zero_evaluations, Mle, MleBaseBackend, MleEval, Point,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "MleEval<F, A>: Serialize, F: Serialize, A: Serialize",
    deserialize = "MleEval<F, A>: Deserialize<'de>, F: Deserialize<'de>, A: Deserialize<'de>"
))]
pub enum Padding<F, A: Backend> {
    Constant((F, usize, A)),
    Generic(Arc<MleEval<F, A>>),
}

impl<F, A: Backend> HasBackend for Padding<F, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        match self {
            Padding::Constant((_, _, backend)) => backend,
            Padding::Generic(eval) => eval.backend(),
        }
    }
}

impl<F: Clone, A: Backend> Padding<F, A> {
    pub fn num_polynomials(&self) -> usize {
        match self {
            Padding::Constant((_, num_polynomials, _)) => *num_polynomials,
            Padding::Generic(ref eval) => eval.num_polynomials(),
        }
    }
}

impl<F: AbstractField> From<Padding<F, CpuBackend>> for Vec<F> {
    fn from(padding: Padding<F, CpuBackend>) -> Self {
        match padding {
            Padding::Constant((value, num_polynomials, _)) => vec![value; num_polynomials],
            Padding::Generic(eval) => eval.evaluations().as_buffer().to_vec(),
        }
    }
}

impl<F, A: Backend> From<MleEval<F, A>> for Padding<F, A> {
    fn from(eval: MleEval<F, A>) -> Self {
        Padding::Generic(Arc::new(eval))
    }
}

/// A bacth of multi-linear polynomials, potentially padded with additional variables.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "Tensor<T, A>: Serialize, T: Serialize, A: Serialize",
    deserialize = "Tensor<T, A>: Deserialize<'de>, T: Deserialize<'de>, A: Deserialize<'de>"
))]
pub struct PaddedMle<T, A: Backend = CpuBackend> {
    inner: Option<Arc<Mle<T, A>>>,
    padding_values: Padding<T, A>,
    num_variables: u32,
}

// Generic backend implementation for basic PaddedMle operations
impl<T: Field, A: MleBaseBackend<T>> PaddedMle<T, A> {
    #[inline]
    pub const fn new(
        inner: Option<Arc<Mle<T, A>>>,
        num_variables: u32,
        padding_values: Padding<T, A>,
    ) -> Self {
        Self { inner, num_variables, padding_values }
    }

    pub fn padded(
        inner: Arc<Mle<T, A>>,
        num_variables: u32,
        padding_values: Padding<T, A>,
    ) -> Self {
        assert!(inner.num_non_zero_entries() <= 1 << num_variables);
        assert_eq!(padding_values.num_polynomials(), inner.num_polynomials());
        Self { inner: Some(inner), num_variables, padding_values }
    }

    pub fn dummy(num_variables: u32, padding_values: Padding<T, A>) -> Self {
        Self { inner: None, num_variables, padding_values }
    }

    pub fn with_minimal_padding(inner: Arc<Mle<T, A>>, padding_values: Padding<T, A>) -> Self {
        let num_padded_variables = inner.num_variables();
        Self::padded(inner, num_padded_variables, padding_values)
    }

    pub fn padded_with_zeros(inner: Arc<Mle<T, A>>, num_variables: u32) -> Self {
        let num_polys = inner.num_polynomials();
        let backend = inner.backend().clone();
        Self::padded(inner, num_variables, Padding::Constant((T::zero(), num_polys, backend)))
    }

    pub fn zeros_in(num_polynomials: usize, num_variables: u32, backend: A) -> Self {
        Self::dummy(num_variables, Padding::Constant((T::zero(), num_polynomials, backend)))
    }

    /// Returns the number of variables in the multi-linear polynomial.
    pub fn num_variables(&self) -> u32 {
        self.num_variables
    }

    pub fn into_inner(self) -> Option<Arc<Mle<T, A>>> {
        self.inner
    }

    pub fn into_padding_values(self) -> Padding<T, A> {
        self.padding_values
    }

    pub fn num_real_entries(&self) -> usize {
        self.inner.as_ref().map(|mle| mle.num_non_zero_entries()).unwrap_or(0)
    }
}

impl<T: Field> PaddedMle<T, CpuBackend> {
    /// Returns the underlying tensor.
    pub fn inner(&self) -> &Option<Arc<Mle<T, CpuBackend>>> {
        &self.inner
    }

    pub fn zeros(num_polynomials: usize, num_variables: u32) -> Self {
        Self::zeros_in(num_polynomials, num_variables, GLOBAL_CPU_BACKEND)
    }

    #[inline]
    pub fn num_polynomials(&self) -> usize {
        self.padding_values.num_polynomials()
    }

    #[inline]
    pub fn fix_last_variable<EF>(&self, alpha: EF) -> PaddedMle<EF, CpuBackend>
    where
        EF: ExtensionField<T>,
    {
        assert!(self.num_variables > 0);
        match &self.padding_values {
            Padding::Generic(orig_padding_values) => {
                let new_padding_values: MleEval<EF> = orig_padding_values
                    .to_vec()
                    .iter()
                    .cloned()
                    .map(EF::from_base)
                    .collect::<Vec<_>>()
                    .into();

                let inner = self.inner.as_ref().map(|mle| {
                    let guts =
                        mle_fix_last_variable(mle.guts(), alpha, orig_padding_values.clone());
                    Arc::new(Mle::<EF, CpuBackend>::new(guts))
                });
                PaddedMle {
                    inner,
                    padding_values: Padding::Generic(Arc::new(new_padding_values)),
                    num_variables: self.num_variables - 1,
                }
            }

            Padding::Constant((padding_value, _, backend)) => {
                let inner = self.inner.as_ref().map(|mle| {
                    let guts =
                        mle_fix_last_variable_constant_padding(mle.guts(), alpha, *padding_value);
                    Arc::new(Mle::<EF, CpuBackend>::new(guts))
                });
                PaddedMle {
                    inner,
                    padding_values: Padding::Constant((
                        EF::from_base(*padding_value),
                        self.num_polynomials(),
                        *backend,
                    )),
                    num_variables: self.num_variables - 1,
                }
            }
        }
    }

    pub fn eval_at_eq<ET: AbstractExtensionField<T> + Send + Sync + Eq + 'static>(
        &self,
        point: &Point<ET>,
        eq: &Mle<ET, CpuBackend>,
    ) -> MleEval<ET, CpuBackend>
    where
        T: Sync + 'static,
    {
        let num_real_entries =
            self.inner.as_ref().map(|mle| mle.num_non_zero_entries()).unwrap_or(0);
        match &self.padding_values {
            Padding::Generic(orig_padding_values) => {
                let geq_adjustments: MleEval<ET> = if num_real_entries < 1 << self.num_variables {
                    orig_padding_values
                        .to_vec()
                        .into_iter()
                        .map(|x| {
                            full_geq(
                                &Point::from_usize(num_real_entries, self.num_variables as usize),
                                point,
                            ) * x
                        })
                        .collect::<Vec<_>>()
                        .into()
                } else {
                    assert_eq!(num_real_entries, 1 << self.num_variables);
                    vec![ET::zero(); self.num_polynomials()].into()
                };

                let final_evals = if let Some(inner) = self.inner.as_ref() {
                    let evals = inner.eval_at(point);
                    evals.add_evals(geq_adjustments)
                } else {
                    geq_adjustments
                };

                final_evals
            }
            Padding::Constant((padding_value, _, _)) => {
                let geq_adjustment = if *padding_value != T::zero() {
                    if num_real_entries < 1 << self.num_variables {
                        full_geq(
                            &Point::from_usize(num_real_entries, self.num_variables as usize),
                            point,
                        ) * *padding_value
                    } else {
                        assert_eq!(num_real_entries, 1 << self.num_variables);
                        ET::zero()
                    }
                } else {
                    ET::zero()
                };

                let mut evals = if let Some(inner) = self.inner.as_ref() {
                    MleEval::new(eval_mle_at_eq(inner.guts(), eq.guts()))
                } else {
                    MleEval::new(zero_evaluations(self.num_polynomials()))
                };

                if *padding_value == T::zero() {
                    return evals;
                }

                // Add geq_adjustment to all evaluations
                for eval in evals.iter_mut() {
                    *eval += geq_adjustment.clone();
                }
                evals
            }
        }
    }

    pub fn eval_at<ET: AbstractExtensionField<T> + Send + Sync + Eq + 'static>(
        &self,
        point: &Point<ET>,
    ) -> MleEval<ET, CpuBackend>
    where
        T: Sync + 'static,
    {
        let eq_tensor = partial_lagrange(point);
        let eq = Mle::new(eq_tensor);
        self.eval_at_eq(point, &eq)
    }

    /// # Safety
    ///
    /// The caller must ensure that the lifetime bounds are being respected, as this function
    /// completely breaks the lifetime bound of the padded mle.
    #[inline]
    pub unsafe fn owned_unchecked(&self) -> ManuallyDrop<Self> {
        let inner = self.inner.as_ref().map(|mle| {
            let mle = mle.owned_unchecked_in(CpuBackend);
            let mle = ManuallyDrop::into_inner(mle);
            Arc::new(mle)
        });

        let padding_values = match &self.padding_values {
            Padding::Constant((value, num_polynomials, _)) => {
                Padding::Constant((*value, *num_polynomials, CpuBackend))
            }

            Padding::Generic(eval) => {
                let evaluations = eval.owned_unchecked_in(CpuBackend);
                let evaluations = ManuallyDrop::into_inner(evaluations);
                Padding::Generic(Arc::new(evaluations))
            }
        };

        let padded_mle = PaddedMle { inner, padding_values, num_variables: self.num_variables };
        ManuallyDrop::new(padded_mle)
    }
}

impl<T, A: Backend> HasBackend for PaddedMle<T, A> {
    type Backend = A;

    fn backend(&self) -> &Self::Backend {
        match &self.padding_values {
            Padding::Generic(eval) => eval.backend(),
            Padding::Constant((_, _, backend)) => backend,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use slop_baby_bear::BabyBear;

    use crate::Mle;

    use super::*;

    #[test]
    fn test_padded_eval_at() {
        let padded_guts = vec![1, 2, 3, 1, 1, 1, 1, 1]
            .into_iter()
            .map(BabyBear::from_canonical_usize)
            .collect::<Vec<_>>();

        let point = (0..3).map(|_| rand::thread_rng().gen::<BabyBear>()).collect::<Point<_>>();
        for i in 3..8 {
            let virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                3,
                Padding::Constant((BabyBear::one(), 1, CpuBackend)),
            );

            let other_virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                3,
                Padding::Generic(Arc::new(vec![BabyBear::one()].into())),
            );
            assert_eq!(
                Into::<Mle<_>>::into(padded_guts.clone()).eval_at(&point).to_vec()[0],
                virtually_padded_mle.eval_at(&point).to_vec()[0]
            );
            assert_eq!(
                Into::<Mle<_>>::into(padded_guts.clone()).eval_at(&point).to_vec()[0],
                other_virtually_padded_mle.eval_at(&point).to_vec()[0]
            );
        }
    }

    #[test]
    fn test_pure_padded_mle() {
        let mut rng = rand::thread_rng();
        let padded_values = (0..1000).map(|_| rng.gen::<BabyBear>()).collect::<Vec<_>>();
        let padded_values = Arc::new(MleEval::<BabyBear, CpuBackend>::from(padded_values));
        let num_variables = 16;
        let padded_mle = PaddedMle::dummy(num_variables, Padding::Generic(padded_values.clone()));
        let point =
            (0..num_variables).map(|_| rand::thread_rng().gen::<BabyBear>()).collect::<Point<_>>();
        let evals = padded_mle.eval_at(&point);
        assert_eq!(evals.to_vec(), padded_values.to_vec());
    }

    #[test]
    fn test_padded_fix_last_variable() {
        let padded_guts = vec![1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
            .into_iter()
            .map(BabyBear::from_canonical_usize)
            .collect::<Vec<_>>();

        for i in 3..16 {
            let virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                4,
                Padding::Constant((BabyBear::one(), 1, CpuBackend)),
            );
            let other_virtually_padded_mle = PaddedMle::padded(
                Arc::new(padded_guts[..i].to_vec().into()),
                4,
                Padding::Generic(Arc::new(vec![BabyBear::one()].into())),
            );
            let mut virtual_cursor = virtually_padded_mle.clone();
            let mut other_virtual_cursor = other_virtually_padded_mle.clone();
            let mut cursor: Mle<_> = padded_guts.clone().into();

            for j in 0..4 {
                let alpha = rand::thread_rng().gen::<BabyBear>();
                virtual_cursor = virtual_cursor.fix_last_variable(alpha);
                other_virtual_cursor = other_virtual_cursor.fix_last_variable(alpha);
                cursor = cursor.fix_last_variable(alpha);
                let beta = (0..(3 - j)).map(|_| rand::thread_rng().gen::<BabyBear>()).collect();
                assert_eq!(
                    virtual_cursor.eval_at(&beta).to_vec()[0],
                    cursor.eval_at(&beta).to_vec()[0]
                );
                assert_eq!(
                    other_virtual_cursor.eval_at(&beta).to_vec()[0],
                    cursor.eval_at(&beta).to_vec()[0]
                );
            }
        }
    }
}
