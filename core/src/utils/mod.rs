pub mod ec;
mod logger;
mod programs;
mod prove;
mod tracer;

pub use logger::*;
pub use prove::*;
pub use tracer::*;

#[cfg(test)]
pub use programs::*;

use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    lookup::{Interaction, InteractionBuilder},
    memory::MemoryCols,
    operations::field::params::Limbs,
    runtime::Segment,
    stark::{
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        DebugConstraintBuilder, StarkConfig,
    },
};

pub trait Chip<F: Field>: Air<InteractionBuilder<F>> {
    fn name(&self) -> String;

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F>;

    fn receives(&self) -> Vec<Interaction<F>> {
        let mut builder = InteractionBuilder::new(self.width());
        self.eval(&mut builder);
        let (_, receives) = builder.interactions();
        receives
    }

    fn sends(&self) -> Vec<Interaction<F>> {
        let mut builder = InteractionBuilder::new(self.width());
        self.eval(&mut builder);
        let (sends, _) = builder.interactions();
        sends
    }

    fn all_interactions(&self) -> Vec<Interaction<F>> {
        let mut builder = InteractionBuilder::new(self.width());
        self.eval(&mut builder);
        let (mut sends, receives) = builder.interactions();
        sends.extend(receives);
        sends
    }
}

pub trait AirChip<SC: StarkConfig>:
    Chip<SC::Val>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<VerifierConstraintFolder<'a, SC::Val, SC::Challenge, SC::ChallengeAlgebra>>
    + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
    fn air_width(&self) -> usize {
        <Self as BaseAir<SC::Val>>::width(self)
    }

    fn as_chip(&self) -> &dyn Chip<SC::Val>;
}

impl<SC: StarkConfig, T> AirChip<SC> for T
where
    T: Chip<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC::Val, SC::Challenge, SC::ChallengeAlgebra>>
        + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>,
{
    fn as_chip(&self) -> &dyn Chip<SC::Val> {
        self
    }
}

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub fn pad_to_power_of_two<const N: usize, T: Clone + Default>(values: &mut Vec<T>) {
    debug_assert!(values.len() % N == 0);
    let mut n_real_rows = values.len() / N;
    if n_real_rows == 0 || n_real_rows == 1 {
        n_real_rows = 8;
    }
    values.resize(n_real_rows.next_power_of_two() * N, T::default());
}

pub fn limbs_from_prev_access<T: Copy, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T> {
    let vec = cols
        .iter()
        .flat_map(|access| access.prev_value().0)
        .collect::<Vec<T>>();

    let sized = vec
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn limbs_from_access<T: Copy, M: MemoryCols<T>>(cols: &[M]) -> Limbs<T> {
    let vec = cols
        .iter()
        .flat_map(|access| access.value().0)
        .collect::<Vec<T>>();

    let sized = vec
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}

pub fn pad_rows<T: Clone, const N: usize>(rows: &mut Vec<[T; N]>, row_fn: impl Fn() -> [T; N]) {
    let nb_rows = rows.len();
    let mut padded_nb_rows = nb_rows.next_power_of_two();
    if padded_nb_rows == 2 || padded_nb_rows == 1 {
        padded_nb_rows = 4;
    }
    if padded_nb_rows == nb_rows {
        return;
    }
    let dummy_row = row_fn();
    rows.resize(padded_nb_rows, dummy_row);
}

/// Converts a slice of words to a byte array in little endian.
pub fn words_to_bytes_le<const B: usize>(words: &[u32]) -> [u8; B] {
    debug_assert_eq!(words.len() * 4, B);
    words
        .iter()
        .flat_map(|word| word.to_le_bytes().to_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Converts a byte array in little endian to a slice of words.
pub fn bytes_to_words_le<const W: usize>(bytes: &[u8]) -> [u32; W] {
    debug_assert_eq!(bytes.len(), W * 4);
    bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
