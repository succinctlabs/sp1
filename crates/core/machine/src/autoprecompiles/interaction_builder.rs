use slop_air::{AirBuilder, AirBuilderWithPublicValues, PairBuilder};
use slop_algebra::Field;
use slop_matrix::dense::RowMajorMatrix;
use slop_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
use sp1_hypercube::{
    air::{AirInteraction, InteractionScope, MessageBuilder},
    PROOF_MAX_NUM_PVS,
};

use crate::air::TrivialOperationBuilder;

/// An interaction for a lookup or a permutation argument.
#[derive(Clone)]
pub struct Interaction<F: Field> {
    /// The message sent to the bus. Receives have a negative multiplicity.
    pub message: AirInteraction<SymbolicExpression<F>>,
    pub scope: InteractionScope,
}

/// An alternative to [sp1_stark::lookup::builder::InteractionBuilder] that uses
/// [SymbolicExpression] and maintains the order of interactions.
pub struct InteractionBuilder<F: Field> {
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    main: RowMajorMatrix<SymbolicVariable<F>>,
    interactions: Vec<Interaction<F>>,
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
            interactions: vec![],
            public_values: vec![F::zero(); PROOF_MAX_NUM_PVS],
        }
    }

    /// Returns the interactions.
    #[must_use]
    pub fn interactions(self) -> Vec<Interaction<F>> {
        self.interactions
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
        self.interactions.push(Interaction { message, scope });
    }

    fn receive(
        &mut self,
        mut message: AirInteraction<SymbolicExpression<F>>,
        scope: InteractionScope,
    ) {
        // Negate the multiplicity for receives.
        message.multiplicity = -message.multiplicity;
        self.interactions.push(Interaction { message, scope });
    }
}

impl<F: Field> AirBuilderWithPublicValues for InteractionBuilder<F> {
    type PublicVar = F;

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl<F: Field> TrivialOperationBuilder for InteractionBuilder<F> {}
