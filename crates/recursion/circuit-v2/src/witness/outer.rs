use p3_bn254_fr::Bn254Fr;
use p3_field::AbstractField;

pub use sp1_recursion_compiler::ir::Witness as OuterWitness;
use sp1_recursion_compiler::{
    config::OuterConfig,
    ir::{Builder, Var},
};
use sp1_recursion_core_v2::stark::config::{
    BabyBearPoseidon2Outer, OuterBatchOpening, OuterChallenge, OuterVal,
};

use crate::BatchOpeningVariable;

use super::{WitnessWriter, Witnessable};

impl WitnessWriter<OuterConfig> for OuterWitness<OuterConfig> {
    fn write_bit(&mut self, value: bool) {
        self.vars.push(Bn254Fr::from_bool(value));
    }

    fn write_var(&mut self, value: Bn254Fr) {
        self.vars.push(value);
    }

    fn write_felt(&mut self, value: OuterVal) {
        self.felts.push(value);
    }

    fn write_ext(&mut self, value: OuterChallenge) {
        self.exts.push(value);
    }
}

impl Witnessable<OuterConfig> for Bn254Fr {
    type WitnessVariable = Var<Bn254Fr>;

    fn read(&self, builder: &mut Builder<OuterConfig>) -> Self::WitnessVariable {
        builder.witness_var()
    }
    fn write(&self, witness: &mut impl WitnessWriter<OuterConfig>) {
        witness.write_var(*self)
    }
}

impl Witnessable<OuterConfig> for OuterBatchOpening {
    type WitnessVariable = BatchOpeningVariable<OuterConfig, BabyBearPoseidon2Outer>;

    fn read(&self, builder: &mut Builder<OuterConfig>) -> Self::WitnessVariable {
        let opened_values = self
            .opened_values
            .read(builder)
            .into_iter()
            .map(|a| a.into_iter().map(|b| vec![b]).collect())
            .collect();
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable { opened_values, opening_proof }
    }

    fn write(&self, witness: &mut impl WitnessWriter<OuterConfig>) {
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
    }
}
