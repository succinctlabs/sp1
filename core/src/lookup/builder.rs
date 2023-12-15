use std::{ops::Add, os::unix::process, rc::Rc};

use p3_air::{AirBuilder, PairCol, VirtualPairCol};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    air::CurtaBuilder,
    symbolic::{expression::SymbolicExpression, variable::SymbolicVariable},
};

use super::{Interaction, InteractionKind};

/// A column in a PAIR, i.e. either a preprocessed column or a main trace column.
#[derive(Copy, Clone, Debug)]
pub enum MyPairCol {
    Preprocessed(usize),
    Main(usize),
}

pub struct InteractionBuilder<F: Field> {
    main: RowMajorMatrix<SymbolicVariable<F>>,
    constraints: Vec<SymbolicExpression<F>>,
    sends: Vec<Interaction<F>>,
    receives: Vec<Interaction<F>>,
}

impl<F: Field> AirBuilder for InteractionBuilder<F> {
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

    fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
}

impl<F: Field> CurtaBuilder for InteractionBuilder<F> {
    fn send(&mut self, values: &[Self::Expr], multiplicity: Self::Expr, kind: InteractionKind) {
        let values = values
            .iter()
            .map(|v| symbolic_to_virtual_pair(v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&multiplicity);

        self.sends
            .push(Interaction::new(values, multiplicity, kind));
    }

    fn receive(&mut self, values: &[Self::Expr], multiplicity: Self::Expr, kind: InteractionKind) {
        let values = values
            .iter()
            .map(|v| symbolic_to_virtual_pair(v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&multiplicity);

        self.receives
            .push(Interaction::new(values, multiplicity, kind));
    }
}

fn symbolic_to_virtual_pair<F: Field>(expression: &SymbolicExpression<F>) -> VirtualPairCol<F> {
    if expression.degree_multiple() > 1 {
        panic!("degree multiple is too high");
    }

    let (column_weights, constant) = eval_symbolic_to_virtual_pair(expression);

    let column_weights = column_weights
        .into_iter()
        .map(|(c, w)| (c.into(), w))
        .collect();

    VirtualPairCol::new(column_weights, constant)
}

fn eval_symbolic_to_virtual_pair<F: Field>(
    expression: &SymbolicExpression<F>,
) -> (Vec<(MyPairCol, F)>, F) {
    match expression {
        SymbolicExpression::Constant(c) => (vec![], *c),
        SymbolicExpression::Variable(v) if !v.is_next => {
            (vec![(MyPairCol::Main(v.column), F::one())], F::zero())
        }
        SymbolicExpression::Add(left, right) => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(left);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(right);
            ([v_l, v_r].concat(), c_l + c_r)
        }
        SymbolicExpression::Sub(left, right) => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(left);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(right);
            let neg_v_r = v_r.iter().map(|(c, w)| (*c, -*w)).collect();
            ([v_l, neg_v_r].concat(), c_l - c_r)
        }
        SymbolicExpression::Neg(x) => {
            let (v, c) = eval_symbolic_to_virtual_pair(x);
            (v.iter().map(|(c, w)| (*c, -*w)).collect(), -c)
        }
        SymbolicExpression::Mul(left, right) => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(left);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(right);

            let mut v = vec![];
            v.extend(v_l.iter().map(|(c, w)| (*c, *w * c_r)));
            v.extend(v_r.iter().map(|(c, w)| (*c, *w * c_l)));

            if !v_l.is_empty() && !v_r.is_empty() {
                panic!("Not an affine expression")
            }

            (v, c_l * c_r)
        }
        SymbolicExpression::IsFirstRow => {
            panic!("Not an affine expression in current row elements")
        }

        SymbolicExpression::IsLastRow => {
            panic!("Not an affine expression in current row elements")
        }
        SymbolicExpression::IsTransition => {
            panic!("Not an affine expression in current row elements")
        }
        SymbolicExpression::Variable(_) => {
            panic!("Not an affine expression in current row elements")
        }
    }
}

impl Into<PairCol> for MyPairCol {
    fn into(self) -> PairCol {
        match self {
            MyPairCol::Preprocessed(i) => PairCol::Preprocessed(i),
            MyPairCol::Main(i) => PairCol::Main(i),
        }
    }
}
