use p3_bn254_fr::Bn254Fr;
use sp1_core::stark::{AirOpenedValues, ChipOpenedValues, ShardCommitment, ShardOpenedValues};
use sp1_recursion_compiler::{
    config::OuterConfig,
    ir::{Builder, Config, Ext, Felt, Var},
};
use sp1_recursion_core::stark::config::{OuterBatchOpening, OuterChallenge, OuterDigest, OuterVal};

use crate::types::{
    AirOpenedValuesVariable, BatchOpeningVariable, ChipOpenedValuesVariable, OuterDigestVariable,
    RecursionShardOpenedValuesVariable,
};

pub struct Witness<C: Config> {
    vars: Vec<C::N>,
    felts: Vec<C::F>,
    exts: Vec<C::EF>,
}

pub trait Witnessable<C: Config> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut Witness<C>);
}

type C = OuterConfig;

impl Witnessable<C> for Bn254Fr {
    type WitnessVariable = Var<Bn254Fr>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_var()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.vars.push(*self);
    }
}

impl Witnessable<C> for OuterVal {
    type WitnessVariable = Felt<OuterVal>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_felt()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.felts.push(*self);
    }
}

impl Witnessable<C> for OuterChallenge {
    type WitnessVariable = Ext<OuterVal, OuterChallenge>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_ext()
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.exts.push(*self);
    }
}

trait VectorWitnessable<C: Config>: Witnessable<C> {}
impl VectorWitnessable<C> for Bn254Fr {}
impl VectorWitnessable<C> for OuterVal {}
impl VectorWitnessable<C> for OuterChallenge {}
impl VectorWitnessable<C> for Vec<OuterVal> {}
impl VectorWitnessable<C> for Vec<OuterChallenge> {}
impl VectorWitnessable<C> for Vec<Vec<OuterVal>> {}

impl<I: VectorWitnessable<C>> Witnessable<C> for Vec<I> {
    type WitnessVariable = Vec<I::WitnessVariable>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.iter().for_each(|x| x.write(witness));
    }
}

impl Witnessable<C> for OuterDigest {
    type WitnessVariable = OuterDigestVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        [builder.witness_var()]
    }

    fn write(&self, witness: &mut Witness<C>) {
        witness.vars.push(self[0]);
    }
}
impl VectorWitnessable<C> for OuterDigest {}

impl Witnessable<C> for ShardCommitment<OuterDigest> {
    type WitnessVariable = ShardCommitment<OuterDigestVariable<C>>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let main_commit = self.main_commit.read(builder);
        let permutation_commit = self.permutation_commit.read(builder);
        let quotient_commit = self.quotient_commit.read(builder);
        ShardCommitment {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.main_commit.write(witness);
        self.permutation_commit.write(witness);
        self.quotient_commit.write(witness);
    }
}

impl Witnessable<C> for AirOpenedValues<OuterChallenge> {
    type WitnessVariable = AirOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let local = self.local.read(builder);
        let next = self.next.read(builder);
        AirOpenedValuesVariable { local, next }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.local.write(witness);
        self.next.write(witness);
    }
}

impl Witnessable<C> for ChipOpenedValues<OuterChallenge> {
    type WitnessVariable = ChipOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let preprocessed = self.preprocessed.read(builder);
        let main = self.main.read(builder);
        let permutation = self.permutation.read(builder);
        let quotient = self.quotient.read(builder);
        let cumulative_sum = self.cumulative_sum.read(builder);
        let log_degree = self.log_degree;
        ChipOpenedValuesVariable {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum,
            log_degree,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.preprocessed.write(witness);
        self.main.write(witness);
        self.permutation.write(witness);
        self.quotient.write(witness);
        self.cumulative_sum.write(witness);
    }
}
impl VectorWitnessable<C> for ChipOpenedValues<OuterChallenge> {}

impl Witnessable<C> for ShardOpenedValues<OuterChallenge> {
    type WitnessVariable = RecursionShardOpenedValuesVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let chips = self.chips.read(builder);
        RecursionShardOpenedValuesVariable { chips }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.chips.write(witness);
    }
}

impl Witnessable<C> for OuterBatchOpening {
    type WitnessVariable = BatchOpeningVariable<C>;

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let opened_values = self
            .opened_values
            .read(builder)
            .into_iter()
            .map(|a| a.into_iter().map(|b| vec![b]).collect())
            .collect();
        let opening_proof = self.opening_proof.read(builder);
        BatchOpeningVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self, witness: &mut Witness<C>) {
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
    }
}
