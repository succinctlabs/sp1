use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::AirBuilder;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use super::expression::SymbolicExpression;
use super::variable::SymbolicVariable;

/// An `AirBuilder` for evaluating constraints symbolically, and recording them for later use.
pub struct SymbolicAirBuilder<F: Field> {
    main: RowMajorMatrix<SymbolicVariable<F>>,
    constraints: Vec<SymbolicExpression<F>>,
}

impl<F: Field> SymbolicAirBuilder<F> {
    pub(crate) fn new(width: usize) -> Self {
        let values = [false, true]
            .into_iter()
            .flat_map(|is_next| {
                (0..width).map(move |column| SymbolicVariable {
                    is_next,
                    column,
                    _phantom: PhantomData,
                })
            })
            .collect();
        Self {
            main: RowMajorMatrix::new(values, width),
            constraints: vec![],
        }
    }

    pub(crate) fn max_degree_multiple(&self) -> usize {
        self.constraints
            .iter()
            .map(|c| c.degree_multiple())
            .max()
            .unwrap_or(0)
    }
}

impl<F: Field> AirBuilder for SymbolicAirBuilder<F> {
    type F = F;
    type Expr = SymbolicExpression<F>;
    type Var = SymbolicVariable<F>;
    type M = RowMajorMatrix<Self::Var>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        SymbolicExpression::IsFirstRow
    }

    fn is_last_row(&self) -> Self::Expr {
        SymbolicExpression::IsLastRow
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            SymbolicExpression::IsTransition
        } else {
            panic!("uni-stark only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraints.push(x.into());
    }
}
