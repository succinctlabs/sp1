use std::collections::BTreeMap;

use crate::{
    basefold::{stacked::RecursiveStackedPcsProof, RecursiveBasefoldProof},
    hash::FieldHasherVariable,
    shard::{MachineVerifyingKeyVariable, ShardProofVariable},
    CircuitConfig, SP1FieldConfigVariable,
};
use slop_algebra::{extension::BinomialExtensionField, AbstractExtensionField, AbstractField};
use slop_bn254::Bn254Fr;
use slop_challenger::{GrindingChallenger, IopCtx};
use slop_commit::Rounds;
use sp1_hypercube::{
    septic_curve::SepticCurve, septic_digest::SepticDigest, septic_extension::SepticExtension,
    AirOpenedValues, ChipOpenedValues, MachineVerifyingKey, ShardOpenedValues, ShardProof,
};
use sp1_primitives::{SP1ExtensionField, SP1Field};
pub use sp1_recursion_compiler::ir::Witness as OuterWitness;
use sp1_recursion_compiler::{
    config::OuterConfig,
    ir::{Builder, Ext, Felt, Var},
};
use sp1_recursion_executor::Block;

pub trait WitnessWriter<C: CircuitConfig>: Sized {
    fn write_bit(&mut self, value: bool);

    fn write_var(&mut self, value: C::N);

    fn write_felt(&mut self, value: SP1Field);

    fn write_ext(&mut self, value: SP1ExtensionField);
}

impl WitnessWriter<OuterConfig> for OuterWitness<OuterConfig> {
    fn write_bit(&mut self, value: bool) {
        self.vars.push(Bn254Fr::from_bool(value));
    }

    fn write_var(&mut self, value: Bn254Fr) {
        self.vars.push(value);
    }

    fn write_felt(&mut self, value: SP1Field) {
        self.felts.push(value);
    }

    fn write_ext(&mut self, value: BinomialExtensionField<SP1Field, 4>) {
        self.exts.push(value);
    }
}

pub type WitnessBlock = Block<SP1Field>;

impl<C: CircuitConfig<Bit = Felt<SP1Field>>> WitnessWriter<C> for Vec<WitnessBlock> {
    fn write_bit(&mut self, value: bool) {
        self.push(Block::from(SP1Field::from_bool(value)))
    }

    fn write_var(&mut self, _value: <C>::N) {
        unimplemented!("Cannot write Var<N> in this configuration")
    }

    fn write_felt(&mut self, value: SP1Field) {
        self.push(Block::from(value))
    }

    fn write_ext(&mut self, value: SP1ExtensionField) {
        self.push(Block::from(value.as_base_slice()))
    }
}

pub trait Witnessable<C: CircuitConfig> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut impl WitnessWriter<C>);
}

impl<C: CircuitConfig> Witnessable<C> for () {
    type WitnessVariable = ();

    fn read(&self, _builder: &mut Builder<C>) -> Self::WitnessVariable {}

    fn write(&self, _witness: &mut impl WitnessWriter<C>) {}
}

impl<C: CircuitConfig> Witnessable<C> for bool {
    type WitnessVariable = C::Bit;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        C::read_bit(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_bit(*self);
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for &T {
    type WitnessVariable = T::WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        (*self).read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        (*self).write(witness)
    }
}

impl<C: CircuitConfig, T: Witnessable<C>, U: Witnessable<C>> Witnessable<C> for (T, U) {
    type WitnessVariable = (T::WitnessVariable, U::WitnessVariable);

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        (self.0.read(builder), self.1.read(builder))
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.0.write(witness);
        self.1.write(witness);
    }
}

impl<C: CircuitConfig> Witnessable<C> for SP1Field {
    type WitnessVariable = Felt<SP1Field>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        C::read_felt(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_felt(*self);
    }
}

impl<C: CircuitConfig> Witnessable<C> for BinomialExtensionField<SP1Field, 4> {
    type WitnessVariable = Ext<SP1Field, BinomialExtensionField<SP1Field, 4>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        C::read_ext(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_ext(*self);
    }
}

impl<C: CircuitConfig<N = Bn254Fr>> Witnessable<C> for Bn254Fr {
    type WitnessVariable = Var<Bn254Fr>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_var()
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_var(*self)
    }
}

impl<C: CircuitConfig, T: Witnessable<C>, const N: usize> Witnessable<C> for [T; N] {
    type WitnessVariable = [T::WitnessVariable; N];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect::<Vec<_>>().try_into().unwrap_or_else(
            |x: Vec<_>| {
                // Cannot just `.unwrap()` without requiring Debug bounds.
                panic!("could not coerce vec of len {} into array of len {N}", x.len())
            },
        )
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Vec<T> {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<C: CircuitConfig, K: Clone + Ord, V: Witnessable<C>> Witnessable<C> for BTreeMap<K, V> {
    type WitnessVariable = BTreeMap<K, V::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|(k, v)| (k.clone(), v.read(builder))).collect()
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for v in self.values() {
            v.write(witness);
        }
    }
}

impl<C: CircuitConfig, T: Witnessable<C>> Witnessable<C> for Rounds<T> {
    type WitnessVariable = Rounds<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<C: CircuitConfig> Witnessable<C> for SepticDigest<SP1Field> {
    type WitnessVariable = SepticDigest<Felt<SP1Field>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let x = self.0.x.0.read(builder);
        let y = self.0.y.0.read(builder);
        SepticDigest(SepticCurve { x: SepticExtension(x), y: SepticExtension(y) })
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.0.x.0.write(witness);
        self.0.y.0.write(witness);
    }
}

impl<C: CircuitConfig> Witnessable<C> for ShardOpenedValues<SP1Field, SP1ExtensionField> {
    type WitnessVariable = ShardOpenedValues<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let chips = self.chips.read(builder);
        Self::WitnessVariable { chips }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.chips.write(witness);
    }
}

impl<C: CircuitConfig> Witnessable<C> for ChipOpenedValues<SP1Field, SP1ExtensionField> {
    type WitnessVariable = ChipOpenedValues<Felt<SP1Field>, Ext<SP1Field, SP1ExtensionField>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let degree = self.degree.read(builder);
        Self::WitnessVariable { preprocessed, main, degree }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.preprocessed.write(witness);
        self.main.write(witness);
        self.degree.write(witness);
    }
}

impl<C: CircuitConfig> Witnessable<C> for AirOpenedValues<SP1ExtensionField> {
    type WitnessVariable = AirOpenedValues<Ext<SP1Field, SP1ExtensionField>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        Self::WitnessVariable { local }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.local.write(witness);
    }
}

impl<C, GC, Proof> Witnessable<C> for ShardProof<GC, Proof>
where
    C: CircuitConfig,
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    <GC as IopCtx>::Digest:
        Witnessable<C, WitnessVariable = <GC as FieldHasherVariable<C>>::DigestVariable>,
    <GC::Challenger as GrindingChallenger>::Witness:
        Witnessable<C, WitnessVariable = Felt<SP1Field>>,
    Proof: Witnessable<
        C,
        WitnessVariable = RecursiveStackedPcsProof<
            RecursiveBasefoldProof<C, GC>,
            SP1Field,
            SP1ExtensionField,
        >,
    >,
{
    type WitnessVariable = ShardProofVariable<C, GC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let public_values = self.public_values.read(builder);
        let main_commitment = self.main_commitment.read(builder);
        let logup_gkr_proof = self.logup_gkr_proof.read(builder);
        let zerocheck_proof = self.zerocheck_proof.read(builder);
        let opened_values = self.opened_values.read(builder);
        let evaluation_proof = self.evaluation_proof.read(builder);
        Self::WitnessVariable {
            main_commitment,
            zerocheck_proof,
            opened_values,
            public_values,
            logup_gkr_proof,
            evaluation_proof,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.public_values.write(witness);
        self.main_commitment.write(witness);
        self.logup_gkr_proof.write(witness);
        self.zerocheck_proof.write(witness);
        self.opened_values.write(witness);
        self.evaluation_proof.write(witness);
    }
}

impl<C, GC> Witnessable<C> for MachineVerifyingKey<GC>
where
    C: CircuitConfig,
    GC: IopCtx<F = SP1Field, EF = SP1ExtensionField> + SP1FieldConfigVariable<C>,
    <GC as IopCtx>::Digest:
        Witnessable<C, WitnessVariable = <GC as FieldHasherVariable<C>>::DigestVariable>,
{
    type WitnessVariable = MachineVerifyingKeyVariable<C, GC>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let pc_start = self.pc_start.read(builder);
        let initial_global_cumulative_sum = self.initial_global_cumulative_sum.read(builder);
        let preprocessed_commit = self.preprocessed_commit.read(builder);
        let enable_untrusted_programs = self.enable_untrusted_programs.read(builder);
        Self::WitnessVariable {
            pc_start,
            initial_global_cumulative_sum,
            preprocessed_commit,
            enable_untrusted_programs,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.pc_start.write(witness);
        self.initial_global_cumulative_sum.write(witness);
        self.preprocessed_commit.write(witness);
        self.enable_untrusted_programs.write(witness);
    }
}
