use std::ops::Range;

use p3_air::{AirBuilder, BaseAir};
use p3_matrix::{Matrix, MatrixRowSlices, MatrixRows};

/// A submatrix of a matrix.  The matrix will contain a subset of the columns of `self.inner`.
pub struct SubMatrixRowSlices<M: MatrixRowSlices<T>, T> {
    inner: M,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<T>,
}

impl<M: MatrixRowSlices<T>, T> SubMatrixRowSlices<M, T> {
    pub fn new(inner: M, column_range: Range<usize>) -> Self {
        Self {
            inner,
            column_range,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Implement `Matrix` for `SubMatrixRowSlices`.
impl<M: MatrixRowSlices<T>, T> Matrix<T> for SubMatrixRowSlices<M, T> {
    fn width(&self) -> usize {
        self.column_range.end - self.column_range.start
    }

    fn height(&self) -> usize {
        self.inner.height()
    }
}

/// Implement `MatrixRows` for `SubMatrixRowSlices`.
impl<M: MatrixRowSlices<T>, T> MatrixRows<T> for SubMatrixRowSlices<M, T> {
    type Row<'a> = M::Row<'a> where Self: 'a;

    fn row(&self, r: usize) -> Self::Row<'_> {
        self.inner.row(r)
    }

    fn row_vec(&self, r: usize) -> Vec<T> {
        self.inner.row_vec(r)
    }

    fn first_row(&self) -> Self::Row<'_> {
        self.inner.first_row()
    }

    fn last_row(&self) -> Self::Row<'_> {
        self.inner.last_row()
    }

    fn to_row_major_matrix(self) -> p3_matrix::dense::RowMajorMatrix<T>
    where
        Self: Sized,
        T: Clone,
    {
        self.inner.to_row_major_matrix()
    }
}

/// Implement `MatrixRowSlices` for `SubMatrixRowSlices`.
impl<M: MatrixRowSlices<T>, T> MatrixRowSlices<T> for SubMatrixRowSlices<M, T> {
    fn row_slice(&self, r: usize) -> &[T] {
        let entry = self.inner.row_slice(r);
        &entry[self.column_range.start..self.column_range.end]
    }
}

/// A builder used to eval a sub-air.  This will handle enforcing constraints for a subset of a
/// trace matrix.  E.g. if a particular air needs to be enforced for a subset of the columns of
/// the trace, then the SubAirBuilder can be used.
pub struct SubAirBuilder<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> {
    inner: &'a mut AB,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<(SubAir, T)>,
}

impl<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> SubAirBuilder<'a, AB, SubAir, T> {
    pub fn new(inner: &'a mut AB, column_range: Range<usize>) -> Self {
        Self {
            inner,
            column_range,
            _phantom: std::marker::PhantomData,
        }
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
