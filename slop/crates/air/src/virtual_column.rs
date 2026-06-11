use core::ops::Mul;
use serde::{Deserialize, Serialize};

use slop_algebra::{AbstractField, Field};

/// An affine function over columns in a PAIR.
#[derive(Clone, Debug)]
pub struct VirtualPairCol<F: Field> {
    pub column_weights: Vec<(PairCol, F)>,
    pub constant: F,
}

/// A column in a PAIR: a preprocessed, global, or main trace column.
///
/// The derived ordering follows the round order: preprocessed, then global,
/// then main.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PairCol {
    Preprocessed(usize),
    Global(usize),
    Main(usize),
}

impl PairCol {
    pub const fn get<T: Copy>(&self, preprocessed: &[T], global: &[T], main: &[T]) -> T {
        match self {
            PairCol::Preprocessed(i) => preprocessed[*i],
            PairCol::Global(i) => global[*i],
            PairCol::Main(i) => main[*i],
        }
    }
}

impl<F: Field> VirtualPairCol<F> {
    pub const fn new(column_weights: Vec<(PairCol, F)>, constant: F) -> Self {
        Self { column_weights, constant }
    }

    pub fn new_preprocessed(column_weights: Vec<(usize, F)>, constant: F) -> Self {
        Self::new(
            column_weights.into_iter().map(|(i, w)| (PairCol::Preprocessed(i), w)).collect(),
            constant,
        )
    }

    pub fn new_main(column_weights: Vec<(usize, F)>, constant: F) -> Self {
        Self::new(
            column_weights.into_iter().map(|(i, w)| (PairCol::Main(i), w)).collect(),
            constant,
        )
    }

    #[must_use]
    pub fn one() -> Self {
        Self::constant(F::one())
    }

    #[must_use]
    pub const fn constant(x: F) -> Self {
        Self { column_weights: vec![], constant: x }
    }

    #[must_use]
    pub fn single(column: PairCol) -> Self {
        Self { column_weights: vec![(column, F::one())], constant: F::zero() }
    }

    #[must_use]
    pub fn single_preprocessed(column: usize) -> Self {
        Self::single(PairCol::Preprocessed(column))
    }

    #[must_use]
    pub fn single_main(column: usize) -> Self {
        Self::single(PairCol::Main(column))
    }

    #[must_use]
    pub fn sum_main(columns: Vec<usize>) -> Self {
        let column_weights = columns.into_iter().map(|col| (col, F::one())).collect();
        Self::new_main(column_weights, F::zero())
    }

    #[must_use]
    pub fn sum_preprocessed(columns: Vec<usize>) -> Self {
        let column_weights = columns.into_iter().map(|col| (col, F::one())).collect();
        Self::new_preprocessed(column_weights, F::zero())
    }

    /// `a - b`, where `a` and `b` are columns in the preprocessed trace.
    #[must_use]
    pub fn diff_preprocessed(a_col: usize, b_col: usize) -> Self {
        Self::new_preprocessed(vec![(a_col, F::one()), (b_col, F::neg_one())], F::zero())
    }

    /// `a - b`, where `a` and `b` are columns in the main trace.
    #[must_use]
    pub fn diff_main(a_col: usize, b_col: usize) -> Self {
        Self::new_main(vec![(a_col, F::one()), (b_col, F::neg_one())], F::zero())
    }

    pub fn apply<Expr, Var>(&self, preprocessed: &[Var], global: &[Var], main: &[Var]) -> Expr
    where
        F: Into<Expr>,
        Expr: AbstractField + Mul<F, Output = Expr>,
        Var: Into<Expr> + Copy,
    {
        let mut result = self.constant.into();
        for (column, weight) in self.column_weights.iter() {
            if *weight != F::one() {
                result += column.get(preprocessed, global, main).into() * *weight;
            } else {
                result += column.get(preprocessed, global, main).into();
            }
        }
        result
    }
}
