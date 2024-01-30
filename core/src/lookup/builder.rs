use crate::air::{AirInteraction, MessageBuilder};
use p3_air::{AirBuilder, PairCol, VirtualPairCol};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicExpression, SymbolicVariable};

use super::Interaction;

/// A builder for the lookup table interactions.
pub struct InteractionBuilder<F: Field> {
    main: RowMajorMatrix<SymbolicVariable<F>>,
    sends: Vec<Interaction<F>>,
    receives: Vec<Interaction<F>>,
}

impl<F: Field> InteractionBuilder<F> {
    /// Creates a new `InteractionBuilder` with the given width.
    pub fn new(width: usize) -> Self {
        let values = [false, true]
            .into_iter()
            .flat_map(|is_next| {
                (0..width).map(move |column| SymbolicVariable::new(is_next, column))
            })
            .collect();
        Self {
            main: RowMajorMatrix::new(values, width),
            sends: vec![],
            receives: vec![],
        }
    }

    /// Returns the sends and receives.
    pub fn interactions(self) -> (Vec<Interaction<F>>, Vec<Interaction<F>>) {
        (self.sends, self.receives)
    }
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

impl<F: Field> MessageBuilder<AirInteraction<SymbolicExpression<F>>> for InteractionBuilder<F> {
    fn send(&mut self, message: AirInteraction<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.sends
            .push(Interaction::new(values, multiplicity, message.kind));
    }

    fn receive(&mut self, message: AirInteraction<SymbolicExpression<F>>) {
        let values = message
            .values
            .into_iter()
            .map(|v| symbolic_to_virtual_pair(&v))
            .collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.receives
            .push(Interaction::new(values, multiplicity, message.kind));
    }
}

fn symbolic_to_virtual_pair<F: Field>(expression: &SymbolicExpression<F>) -> VirtualPairCol<F> {
    if expression.degree_multiple() > 1 {
        panic!("degree multiple is too high");
    }

    let (column_weights, constant) = eval_symbolic_to_virtual_pair(expression);

    let column_weights = column_weights.into_iter().collect();

    VirtualPairCol::new(column_weights, constant)
}

fn eval_symbolic_to_virtual_pair<F: Field>(
    expression: &SymbolicExpression<F>,
) -> (Vec<(PairCol, F)>, F) {
    match expression {
        SymbolicExpression::Constant(c) => (vec![], *c),
        SymbolicExpression::Variable(v) if !v.is_next => {
            (vec![(PairCol::Main(v.column), F::one())], F::zero())
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

#[cfg(test)]
mod tests {
    use p3_air::{Air, BaseAir, VirtualPairCol};
    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, Field};
    use p3_matrix::MatrixRowSlices;

    use super::*;
    use crate::{
        air::CurtaAirBuilder,
        lookup::{InteractionBuilder, InteractionKind},
    };

    #[test]
    fn test_symbolic_to_virtual_pair_col() {
        type F = BabyBear;

        let x = SymbolicVariable::<F>::new(false, 0);

        let y = SymbolicVariable::<F>::new(false, 1);

        let z = x + y;

        let (column_weights, constant) = super::eval_symbolic_to_virtual_pair(&z);
        println!("column_weights: {:?}", column_weights);
        println!("constant: {:?}", constant);

        let column_weights = column_weights.into_iter().collect::<Vec<_>>();

        let z = VirtualPairCol::new(column_weights, constant);

        let expr: F = z.apply(&[], &[F::one(), F::one()]);

        println!("expr: {}", expr);
    }

    pub struct LookupTestAir;

    const NUM_COLS: usize = 3;

    impl<F: Field> BaseAir<F> for LookupTestAir {
        fn width(&self) -> usize {
            NUM_COLS
        }
    }

    impl<AB: CurtaAirBuilder> Air<AB> for LookupTestAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);

            let x = local[0];
            let y = local[1];
            let z = local[2];

            builder.send(AirInteraction::new(
                vec![x.into(), y.into()],
                AB::F::from_canonical_u32(3).into(),
                InteractionKind::Alu,
            ));
            builder.send(AirInteraction::new(
                vec![x + y, z.into()],
                AB::F::from_canonical_u32(5).into(),
                InteractionKind::Alu,
            ));

            builder.receive(AirInteraction::new(
                vec![x.into()],
                y.into(),
                InteractionKind::Byte,
            ));
        }
    }

    #[test]
    fn test_lookup_interactions() {
        let air = LookupTestAir {};

        let mut builder = InteractionBuilder::<BabyBear>::new(NUM_COLS);

        air.eval(&mut builder);

        let mut main = builder.main();
        let (sends, receives) = builder.interactions();

        for interaction in receives {
            print!("Receive values: ");
            for value in interaction.values {
                let expr = value.apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );
                print!("{}, ", expr);
            }

            let multiplicity = interaction
                .multiplicity
                .apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );

            println!(", multiplicity: {}", multiplicity);
        }

        for interaction in sends {
            print!("Send values: ");
            for value in interaction.values {
                let expr = value.apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );
                print!("{}, ", expr);
            }

            let multiplicity = interaction
                .multiplicity
                .apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );

            println!(", multiplicity: {}", multiplicity);
        }
    }
}
