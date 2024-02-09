use p3_air::{Air, BaseAir};
use p3_field::Field;

use crate::lookup::{Interaction, InteractionBuilder};

use super::{
    DebugConstraintBuilder, ProverConstraintFolder, StarkConfig, VerifierConstraintFolder,
};

pub struct Chip<F: Field, A> {
    air: A,
    sends: Vec<Interaction<F>>,
    receives: Vec<Interaction<F>>,
}

pub trait StarkAir<SC: StarkConfig>:
    Air<InteractionBuilder<SC::Val>>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<VerifierConstraintFolder<'a, SC>>
    + for<'a> Air<DebugConstraintBuilder<'a, SC::Val, SC::Challenge>>
{
}

pub struct ChipRef<'a, SC: StarkConfig> {
    air: &'a dyn StarkAir<SC>,
    sends: &'a [Interaction<SC::Val>],
    receives: &'a [Interaction<SC::Val>],
}

impl<F, A> Chip<F, A>
where
    F: Field,
    A: Air<InteractionBuilder<F>>,
{
    pub fn new(air: A) -> Self {
        let mut builder = InteractionBuilder::new(air.width());
        air.eval(&mut builder);
        let (sends, receives) = builder.interactions();

        Self {
            air,
            sends,
            receives,
        }
    }

    pub fn num_interactions(&self) -> usize {
        self.sends.len() + self.receives.len()
    }

    pub fn as_ref<SC: StarkConfig<Val = F>>(&self) -> ChipRef<SC>
    where
        A: StarkAir<SC>,
    {
        ChipRef {
            air: &self.air,
            sends: &self.sends,
            receives: &self.receives,
        }
    }
}

impl<'a, SC: StarkConfig> BaseAir<SC::Val> for ChipRef<'a, SC> {
    fn width(&self) -> usize {
        <dyn StarkAir<SC> as BaseAir<SC::Val>>::width(self.air)
    }
}

impl<'a, SC: StarkConfig> Air<InteractionBuilder<SC::Val>> for ChipRef<'a, SC> {
    fn eval(&self, builder: &mut InteractionBuilder<SC::Val>) {
        self.air.eval(builder);
    }
}

impl<'a, 'b, SC: StarkConfig> Air<ProverConstraintFolder<'b, SC>> for ChipRef<'a, SC> {
    fn eval(&self, builder: &mut ProverConstraintFolder<'b, SC>) {
        <dyn StarkAir<SC> as Air<ProverConstraintFolder<'b, SC>>>::eval(self.air, builder);
    }
}

impl<'a, 'b, SC: StarkConfig> Air<VerifierConstraintFolder<'b, SC>> for ChipRef<'a, SC> {
    fn eval(&self, builder: &mut VerifierConstraintFolder<'b, SC>) {
        <dyn StarkAir<SC> as Air<VerifierConstraintFolder<'b, SC>>>::eval(self.air, builder);
    }
}
