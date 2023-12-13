use super::Runtime;
use crate::lookup::Interaction;
use p3_field::PrimeField;
use p3_matrix::dense::RowMajorMatrix;

pub trait Chip<F: PrimeField> {
    fn generate_trace(&self, runtime: &mut Runtime) -> RowMajorMatrix<F>;
    fn sends(&self) -> Vec<Interaction<F>>;
    fn receives(&self) -> Vec<Interaction<F>>;
}
