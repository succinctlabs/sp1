use sp1_core::utils::{InnerChallenge, InnerVal};
use sp1_recursion_compiler::circuit::CircuitV2Builder;
use sp1_recursion_compiler::ir::*;

pub trait Witnessable<C: Config> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut Witness<C>);
}

// TODO Bn254Fr

impl<C: Config<F = Self>> Witnessable<C> for InnerVal {
    type WitnessVariable = Felt<Self>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.hint_felt_v2()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.felts.push(*self);
    }
}

impl<C: Config<EF = Self>> Witnessable<C> for InnerChallenge {
    type WitnessVariable = Ext<C::F, Self>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.hint_ext_v2()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.exts.push(*self);
    }
}

impl<C: Config, T: Witnessable<C>> Witnessable<C> for Vec<T> {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.iter().for_each(|x| x.write(witness));
    }
}

impl<C: Config, T: Witnessable<C>, const N: usize> Witnessable<C> for [T; N] {
    type WitnessVariable = [T::WitnessVariable; N];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        core::array::from_fn(|i| self[i].read(builder))
    }

    fn write(&self, witness: &mut Witness<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}
