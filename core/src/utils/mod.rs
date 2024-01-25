pub mod ec;
mod logger;
mod prove;
mod tracer;

pub use logger::*;
use p3_uni_stark::StarkConfig;
pub use prove::*;
pub use tracer::*;

use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    cpu::cols::cpu_cols::MemoryAccessCols,
    lookup::{Interaction, InteractionBuilder},
    operations::field::params::{Limbs, NUM_LIMBS},
    runtime::Segment,
    stark::{
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        DebugConstraintBuilder,
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
    + for<'a> Air<VerifierConstraintFolder<'a, SC::Challenge>>
    + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
    fn air_width(&self) -> usize {
        <Self as BaseAir<SC::Val>>::width(self)
    }
}

impl<SC: StarkConfig, T> AirChip<SC> for T where
    T: Chip<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC::Challenge>>
        + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
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

pub fn limbs_from_access<T: Copy>(cols: &[MemoryAccessCols<T>]) -> Limbs<T> {
    let vec = cols
        .iter()
        .flat_map(|access| access.prev_value.0)
        .collect::<Vec<T>>();
    assert_eq!(vec.len(), NUM_LIMBS);

    let sized = vec
        .try_into()
        .unwrap_or_else(|_| panic!("failed to convert to limbs"));
    Limbs(sized)
}
