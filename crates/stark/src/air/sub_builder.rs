use std::{
    iter::{Skip, Take},
    ops::{Deref, Range},
};

use p3_air::{AirBuilder, BaseAir};
use p3_matrix::Matrix;

/// A submatrix of a matrix.  The matrix will contain a subset of the columns of `self.inner`.
pub struct SubMatrixRowSlices<M: Matrix<T>, T: Send + Sync> {
    inner: M,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<T>,
}

impl<M: Matrix<T>, T: Send + Sync> SubMatrixRowSlices<M, T> {
    /// Creates a new [`SubMatrixRowSlices`].
    #[must_use]
    pub const fn new(inner: M, column_range: Range<usize>) -> Self {
        Self { inner, column_range, _phantom: std::marker::PhantomData }
    }
}

/// Implement `Matrix` for `SubMatrixRowSlices`.
impl<M: Matrix<T>, T: Send + Sync> Matrix<T> for SubMatrixRowSlices<M, T> {
    type Row<'a>
        = Skip<Take<M::Row<'a>>>
    where
        Self: 'a;

    #[inline]
    fn row(&self, r: usize) -> Self::Row<'_> {
        self.inner.row(r).take(self.column_range.end).skip(self.column_range.start)
    }

    #[inline]
    fn row_slice(&self, r: usize) -> impl Deref<Target = [T]> {
        self.row(r).collect::<Vec<_>>()
    }

    #[inline]
    fn width(&self) -> usize {
        self.column_range.len()
    }

    #[inline]
    fn height(&self) -> usize {
        self.inner.height()
    }
}

/// A builder used to eval a sub-air.  This will handle enforcing constraints for a subset of a
/// trace matrix.  E.g. if a particular air needs to be enforced for a subset of the columns of
/// the trace, then the [`SubAirBuilder`] can be used.
pub struct SubAirBuilder<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> {
    inner: &'a mut AB,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<(SubAir, T)>,
}

impl<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> SubAirBuilder<'a, AB, SubAir, T> {
    /// Creates a new [`SubAirBuilder`].
    #[must_use]
    pub fn new(inner: &'a mut AB, column_range: Range<usize>) -> Self {
        Self { inner, column_range, _phantom: std::marker::PhantomData }
    }
}

/// Implement `AirBuilder` for `SubAirBuilder`.
impl<'a, AB: AirBuilder, SubAir: BaseAir<F>, F> AirBuilder for SubAirBuilder<'a, AB, SubAir, F> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = SubMatrixRowSlices<AB::M, Self::Var>;

    fn main(&self) -> Self::M {
        let matrix = self.inner.main();

        SubMatrixRowSlices::new(matrix, self.column_range.clone())
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }
}
