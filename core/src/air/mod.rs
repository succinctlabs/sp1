mod bool;
mod word;

pub use bool::Bool;
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_field::{AbstractField, Field, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
pub use word::Word;

use crate::{
    lookup::{Interaction, InteractionKind},
    utils::Chip,
};

pub fn reduce<AB: AirBuilder>(input: Word<AB::Var>) -> AB::Expr {
    let base = [1, 1 << 8, 1 << 16, 1 << 24].map(AB::Expr::from_canonical_u32);

    input
        .0
        .into_iter()
        .enumerate()
        .map(|(i, x)| base[i].clone() * x)
        .sum()
}

/// An extension of the `AirBuilder` trait with additional methods for Curta types.
///
/// All `AirBuilder` implementations automatically implement this trait.
pub trait CurtaTypesBuilder: AirBuilder {
    fn assert_word_eq<I: Into<Self::Expr>>(&mut self, left: Word<I>, right: Word<I>) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    fn assert_is_bool<I: Into<Self::Expr>>(&mut self, value: Bool<I>) {
        self.assert_bool(value.0);
    }
}

impl<AB: AirBuilder> CurtaTypesBuilder for AB {}

pub trait CurtaAirBuilder: AirBuilder {
    fn send<I, T, J>(&mut self, values: I, multiplicity: J, kind: InteractionKind)
    where
        I: IntoIterator<Item = T>,
        T: Into<Self::Expr>,
        J: Into<Self::Expr>;

    fn receive<I, T, J>(&mut self, values: I, multiplicity: J, kind: InteractionKind)
    where
        I: IntoIterator<Item = T>,
        T: Into<Self::Expr>,
        J: Into<Self::Expr>;
}

pub struct DefaultCurta<'a, T>(pub &'a mut T);

impl<'a, AB: AirBuilder> AirBuilder for DefaultCurta<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = AB::M;

    fn main(&self) -> Self::M {
        self.0.main()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.0.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.0.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.0.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.0.assert_zero(x.into());
    }
}

impl<'a, AB: PermutationAirBuilder> PermutationAirBuilder for DefaultCurta<'a, AB> {
    type EF = AB::EF;
    type VarEF = AB::VarEF;
    type ExprEF = AB::ExprEF;
    type MP = AB::MP;

    fn permutation(&self) -> Self::MP {
        self.0.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::EF] {
        self.0.permutation_randomness()
    }
}

impl<'a, AB: AirBuilder> CurtaAirBuilder for DefaultCurta<'a, AB> {
    fn send<I, T, J>(&mut self, _values: I, _mult: J, _kind: InteractionKind)
    where
        I: IntoIterator<Item = T>,
        T: Into<Self::Expr>,
        J: Into<Self::Expr>,
    {
    }

    fn receive<I, T, J>(&mut self, _values: I, _mult: J, _kind: InteractionKind)
    where
        I: IntoIterator<Item = T>,
        T: Into<Self::Expr>,
        J: Into<Self::Expr>,
    {
    }
}

pub struct AirAdapter<T>(T);

impl<T> AirAdapter<T> {
    pub fn new(curta_air: T) -> Self {
        AirAdapter(curta_air)
    }
}

impl<F: PrimeField, T: Chip<F>> Chip<F> for AirAdapter<T> {
    fn generate_trace(&self, runtime: &mut crate::runtime::Runtime) -> RowMajorMatrix<F> {
        self.0.generate_trace(runtime)
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        self.0.sends()
    }

    fn receives(&self) -> Vec<Interaction<F>> {
        self.0.receives()
    }
}

pub trait CurtaAir<AB: CurtaAirBuilder>: BaseAir<AB::F> {
    fn eval(&self, builder: &mut AB);
}

impl<'a, F: Field, T: BaseAir<F>> BaseAir<F> for AirAdapter<T> {
    fn width(&self) -> usize {
        self.0.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.0.preprocessed_trace()
    }
}

impl<AB: AirBuilder, T: for<'a> CurtaAir<DefaultCurta<'a, AB>>> Air<AB> for AirAdapter<T> {
    fn eval(&self, builder: &mut AB) {
        let mut curta_builder = DefaultCurta(builder);
        self.0.eval(&mut curta_builder);
    }
}
