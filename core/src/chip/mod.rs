use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    lookup::{Interaction, InteractionBuilder},
    memory::MemoryCols,
    operations::field::params::Limbs,
    runtime::Segment,
    stark::{
        DebugConstraintBuilder, ProverConstraintFolder, StarkConfig, VerifierConstraintFolder,
    },
};

pub trait Chip<F: Field>: Air<InteractionBuilder<F>> {
    fn name(&self) -> String;

    fn generate_trace(&self, segment: &mut Segment) -> RowMajorMatrix<F>;

    fn shard(&self, input: &Segment, outputs: &mut Vec<Segment>);

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
    + for<'a> Air<VerifierConstraintFolder<'a, SC>>
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
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>,
{
    fn as_chip(&self) -> &dyn Chip<SC::Val> {
        self
    }
}
