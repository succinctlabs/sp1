use p3_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder, PairCol, VirtualPairCol};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};

use crate::{
    air::{AirInteraction, InteractionScope, MessageBuilder},
    PROOF_MAX_NUM_PVS,
};

use super::Interaction;

/// A builder for the lookup table interactions.
pub struct InteractionBuilder<F: Field> {
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    main: RowMajorMatrix<SymbolicVariable<F>>,
    sends: Vec<Interaction<F>>,
    receives: Vec<Interaction<F>>,
    public_values: Vec<F>,
}

impl<F: Field> InteractionBuilder<F> {
    /// Creates a new [`InteractionBuilder`] with the given width.
    #[must_use]
    pub fn new(preprocessed_width: usize, main_width: usize) -> Self {
        let preprocessed_width = preprocessed_width.max(1);
        let prep_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..preprocessed_width).map(move |column| {
                    SymbolicVariable::new(Entry::Preprocessed { offset }, column)
                })
            })
            .collect();

        let main_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..main_width)
                    .map(move |column| SymbolicVariable::new(Entry::Main { offset }, column))
            })
            .collect();

        Self {
            preprocessed: RowMajorMatrix::new(prep_values, preprocessed_width),
            main: RowMajorMatrix::new(main_values, main_width),
            sends: vec![],
            receives: vec![],
            public_values: vec![F::zero(); PROOF_MAX_NUM_PVS],
        }
    }

    /// Returns the sends and receives.
    #[must_use]
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

impl<F: Field> PairBuilder for InteractionBuilder<F> {
    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }
}

impl<F: Field> MessageBuilder<AirInteraction<SymbolicExpression<F>>> for InteractionBuilder<F> {
    fn send(&mut self, message: AirInteraction<SymbolicExpression<F>>, scope: InteractionScope) {
        let values =
            message.values.into_iter().map(|v| symbolic_to_virtual_pair(&v)).collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.sends.push(Interaction::new(values, multiplicity, message.kind, scope));
    }

    fn receive(&mut self, message: AirInteraction<SymbolicExpression<F>>, scope: InteractionScope) {
        let values =
            message.values.into_iter().map(|v| symbolic_to_virtual_pair(&v)).collect::<Vec<_>>();

        let multiplicity = symbolic_to_virtual_pair(&message.multiplicity);

        self.receives.push(Interaction::new(values, multiplicity, message.kind, scope));
    }
}

impl<F: Field> AirBuilderWithPublicValues for InteractionBuilder<F> {
    type PublicVar = F;

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
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
        SymbolicExpression::Variable(v) => match v.entry {
            Entry::Preprocessed { offset: 0 } => {
                (vec![(PairCol::Preprocessed(v.index), F::one())], F::zero())
            }
            Entry::Main { offset: 0 } => (vec![(PairCol::Main(v.index), F::one())], F::zero()),
            _ => panic!("not an affine expression in current row elements {:?}", v.entry),
        },
        SymbolicExpression::Add { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);
            ([v_l, v_r].concat(), c_l + c_r)
        }
        SymbolicExpression::Sub { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);
            let neg_v_r = v_r.iter().map(|(c, w)| (*c, -*w)).collect();
            ([v_l, neg_v_r].concat(), c_l - c_r)
        }
        SymbolicExpression::Neg { x, .. } => {
            let (v, c) = eval_symbolic_to_virtual_pair(x);
            (v.iter().map(|(c, w)| (*c, -*w)).collect(), -c)
        }
        SymbolicExpression::Mul { x, y, .. } => {
            let (v_l, c_l) = eval_symbolic_to_virtual_pair(x);
            let (v_r, c_r) = eval_symbolic_to_virtual_pair(y);

            let mut v = vec![];
            v.extend(v_l.iter().map(|(c, w)| (*c, *w * c_r)));
            v.extend(v_r.iter().map(|(c, w)| (*c, *w * c_l)));

            if !v_l.is_empty() && !v_r.is_empty() {
                panic!("Not an affine expression")
            }

            (v, c_l * c_r)
        }
        SymbolicExpression::IsFirstRow => {
            panic!("not an affine expression in current row elements for first row")
        }
        SymbolicExpression::IsLastRow => {
            panic!("not an affine expression in current row elements for last row")
        }
        SymbolicExpression::IsTransition => {
            panic!("not an affine expression in current row elements for transition row")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use p3_air::{Air, BaseAir};
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use p3_matrix::Matrix;

    use super::*;
    use crate::{air::SP1AirBuilder, lookup::InteractionKind};

    #[test]
    fn test_symbolic_to_virtual_pair_col() {
        type F = BabyBear;

        let x = SymbolicVariable::<F>::new(Entry::Main { offset: 0 }, 0);

        let y = SymbolicVariable::<F>::new(Entry::Main { offset: 0 }, 1);

        let z = x + y;

        let (column_weights, constant) = super::eval_symbolic_to_virtual_pair(&z);
        println!("column_weights: {column_weights:?}");
        println!("constant: {constant:?}");

        let column_weights = column_weights.into_iter().collect::<Vec<_>>();

        let z = VirtualPairCol::new(column_weights, constant);

        let expr: F = z.apply(&[], &[F::one(), F::one()]);

        println!("expr: {expr}");
    }

    pub struct LookupTestAir;

    const NUM_COLS: usize = 3;

    impl<F: Field> BaseAir<F> for LookupTestAir {
        fn width(&self) -> usize {
            NUM_COLS
        }
    }

    impl<AB: SP1AirBuilder> Air<AB> for LookupTestAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0);
            let local: &[AB::Var] = (*local).borrow();

            let x = local[0];
            let y = local[1];
            let z = local[2];

            builder.send(
                AirInteraction::new(
                    vec![x.into(), y.into()],
                    AB::F::from_canonical_u32(3).into(),
                    InteractionKind::Alu,
                ),
                InteractionScope::Local,
            );
            builder.send(
                AirInteraction::new(
                    vec![x + y, z.into()],
                    AB::F::from_canonical_u32(5).into(),
                    InteractionKind::Alu,
                ),
                InteractionScope::Local,
            );

            builder.receive(
                AirInteraction::new(vec![x.into()], y.into(), InteractionKind::Byte),
                InteractionScope::Local,
            );
        }
    }

    #[test]
    fn test_lookup_interactions() {
        let air = LookupTestAir {};

        let mut builder = InteractionBuilder::<BabyBear>::new(0, NUM_COLS);

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
                print!("{expr:?}, ");
            }

            let multiplicity = interaction
                .multiplicity
                .apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );

            println!(", multiplicity: {multiplicity:?}");
        }

        for interaction in sends {
            print!("Send values: ");
            for value in interaction.values {
                let expr = value.apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );
                print!("{expr:?}, ");
            }

            let multiplicity = interaction
                .multiplicity
                .apply::<SymbolicExpression<BabyBear>, SymbolicVariable<BabyBear>>(
                    &[],
                    main.row_mut(0),
                );

            println!(", multiplicity: {multiplicity:?}");
        }
    }
}
