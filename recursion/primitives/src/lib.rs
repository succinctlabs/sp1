use core::marker::PhantomData;

mod constants;

use constants::*;

use sp1_core::air::MachineAir;
use sp1_core::stark::{RiscvStark, ShardProof, StarkGenericConfig, Verifier};

pub use sp1_core::*;

pub struct RecursiveVerifier<SC: StarkGenericConfig>(PhantomData<SC>);

impl<SC: StarkGenericConfig> RecursiveVerifier<SC> {
    pub fn new() -> Self {
        RecursiveVerifier(PhantomData)
    }

    pub fn verify_shard<'a, 'b: 'a>(
        machine: &'b RiscvStark<'a, SC>,
        challenger: &mut SC::Challenger,
        proof: &ShardProof<SC>,
    ) {
        let shard_chips = machine
            .chips()
            .iter()
            .filter(|chip| proof.chip_ids.contains(&chip.name()))
            .collect::<Vec<_>>();

        Verifier::verify_shard(machine.config(), &shard_chips, challenger, proof)
            .expect("verification failed")
    }
}

impl<SC: StarkGenericConfig> Default for RecursiveVerifier<SC> {
    fn default() -> Self {
        RecursiveVerifier::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use p3_air::{PairCol, VirtualPairCol};
    use p3_baby_bear::BabyBear;
    use p3_field::{AbstractField, Field};
    use sp1_core::{
        alu::AddChip,
        stark::{Chip, RiscvAir},
    };

    fn assert_pair_col_eq(left: &PairCol, right: &PairCol) {
        match (left, right) {
            (PairCol::Main(l), PairCol::Main(r)) => assert_eq!(l, r),
            (PairCol::Preprocessed(l), PairCol::Preprocessed(r)) => assert_eq!(l, r),
            _ => panic!("Unequal column types"),
        }
    }

    fn assert_virtual_pair_col_eq<F: Field>(left: &VirtualPairCol<F>, right: &VirtualPairCol<F>) {
        assert_eq!(left.get_constant(), right.get_constant());
        for (l, r) in left
            .get_column_weights()
            .iter()
            .zip(right.get_column_weights())
        {
            assert_pair_col_eq(&l.0, &r.0);
            assert_eq!(l.1, r.1);
        }
    }

    #[test]
    fn test_constant_gen() {
        let expected_values = [1, 2, 4, 5, 6].map(BabyBear::from_canonical_u32);
        assert_eq!(VALUES, &expected_values);

        assert_pair_col_eq(&PAIR_COL, &PairCol::Main(3));

        let chip = Chip::<BabyBear, _>::new(RiscvAir::Add(AddChip));

        let sends = chip.sends();

        let interaction = &sends[0];
        let mult = &interaction.multiplicity;
        assert_virtual_pair_col_eq(mult, &VIRTUAL_COL_MULT);
    }
}
