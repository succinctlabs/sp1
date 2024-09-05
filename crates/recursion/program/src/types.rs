use p3_air::BaseAir;
use p3_field::{AbstractExtensionField, AbstractField};
use sp1_primitives::consts::WORD_SIZE;
use sp1_recursion_compiler::prelude::*;
use sp1_stark::{
    air::{MachineAir, PV_DIGEST_NUM_WORDS},
    AirOpenedValues, Chip, ChipOpenedValues, Word,
};

use crate::fri::{
    types::{DigestVariable, FriConfigVariable, TwoAdicPcsProofVariable},
    TwoAdicMultiplicativeCosetVariable,
};

/// Reference: [sp1_core_machine::stark::ShardProof]
#[derive(DslVariable, Clone)]
pub struct ShardProofVariable<C: Config> {
    pub commitment: ShardCommitmentVariable<C>,
    pub opened_values: ShardOpenedValuesVariable<C>,
    pub opening_proof: TwoAdicPcsProofVariable<C>,
    pub public_values: Array<C, Felt<C::F>>,
    pub quotient_data: Array<C, QuotientData<C>>,
    pub sorted_idxs: Array<C, Var<C::N>>,
}

#[derive(DslVariable, Clone, Copy)]
pub struct QuotientData<C: Config> {
    pub log_quotient_degree: Var<C::N>,
    pub quotient_size: Var<C::N>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotientDataValues {
    pub log_quotient_degree: usize,
    pub quotient_size: usize,
}

/// Reference: [sp1_core_machine::stark::VerifyingKey]
#[derive(DslVariable, Clone)]
pub struct VerifyingKeyVariable<C: Config> {
    pub commitment: DigestVariable<C>,
    pub pc_start: Felt<C::F>,
    pub preprocessed_sorted_idxs: Array<C, Var<C::N>>,
    pub prep_domains: Array<C, TwoAdicMultiplicativeCosetVariable<C>>,
}

/// Reference: [sp1_core_machine::stark::ShardCommitment]
#[derive(DslVariable, Clone)]
pub struct ShardCommitmentVariable<C: Config> {
    pub main_commit: DigestVariable<C>,
    pub permutation_commit: DigestVariable<C>,
    pub quotient_commit: DigestVariable<C>,
}

/// Reference: [sp1_core_machine::stark::ShardOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct ShardOpenedValuesVariable<C: Config> {
    pub chips: Array<C, ChipOpenedValuesVariable<C>>,
}

/// Reference: [sp1_core_machine::stark::ChipOpenedValues]
#[derive(Debug, Clone)]
pub struct ChipOpening<C: Config> {
    pub preprocessed: AirOpenedValues<Ext<C::F, C::EF>>,
    pub main: AirOpenedValues<Ext<C::F, C::EF>>,
    pub permutation: AirOpenedValues<Ext<C::F, C::EF>>,
    pub quotient: Vec<Vec<Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: Var<C::N>,
}

/// Reference: [sp1_core_machine::stark::ChipOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct ChipOpenedValuesVariable<C: Config> {
    pub preprocessed: AirOpenedValuesVariable<C>,
    pub main: AirOpenedValuesVariable<C>,
    pub permutation: AirOpenedValuesVariable<C>,
    pub quotient: Array<C, Array<C, Ext<C::F, C::EF>>>,
    pub cumulative_sum: Ext<C::F, C::EF>,
    pub log_degree: Var<C::N>,
}

/// Reference: [sp1_core_machine::stark::AirOpenedValues]
#[derive(DslVariable, Debug, Clone)]
pub struct AirOpenedValuesVariable<C: Config> {
    pub local: Array<C, Ext<C::F, C::EF>>,
    pub next: Array<C, Ext<C::F, C::EF>>,
}

#[derive(DslVariable, Debug, Clone)]
pub struct Sha256DigestVariable<C: Config> {
    pub bytes: Array<C, Felt<C::F>>,
}

impl<C: Config> Sha256DigestVariable<C> {
    pub fn from_words(builder: &mut Builder<C>, words: &[Word<Felt<C::F>>]) -> Self {
        let mut bytes = builder.array(PV_DIGEST_NUM_WORDS * WORD_SIZE);
        for (i, word) in words.iter().enumerate() {
            for j in 0..WORD_SIZE {
                let byte = word[j];
                builder.set(&mut bytes, i * WORD_SIZE + j, byte);
            }
        }
        Sha256DigestVariable { bytes }
    }
}

impl<C: Config> ChipOpening<C> {
    /// Collect opening values from a dynamic array into vectors.
    ///
    /// This method is used to convert a `ChipOpenedValuesVariable` into a `ChipOpenedValues`, which
    /// are the same values but with each opening converted from a dynamic array into a Rust vector.
    ///
    /// *Safety*: This method also verifies that the legnth of the dynamic arrays match the expected
    /// length of the vectors.
    pub fn from_variable<A>(
        builder: &mut Builder<C>,
        chip: &Chip<C::F, A>,
        opening: &ChipOpenedValuesVariable<C>,
    ) -> Self
    where
        A: MachineAir<C::F>,
    {
        let mut preprocessed = AirOpenedValues { local: vec![], next: vec![] };
        let preprocessed_width = chip.preprocessed_width();
        // Assert that the length of the dynamic arrays match the expected length of the vectors.
        builder.assert_usize_eq(preprocessed_width, opening.preprocessed.local.len());
        builder.assert_usize_eq(preprocessed_width, opening.preprocessed.next.len());
        // Collect the preprocessed values into vectors.
        for i in 0..preprocessed_width {
            preprocessed.local.push(builder.get(&opening.preprocessed.local, i));
            preprocessed.next.push(builder.get(&opening.preprocessed.next, i));
        }

        let mut main = AirOpenedValues { local: vec![], next: vec![] };
        let main_width = chip.width();
        // Assert that the length of the dynamic arrays match the expected length of the vectors.
        builder.assert_usize_eq(main_width, opening.main.local.len());
        builder.assert_usize_eq(main_width, opening.main.next.len());
        // Collect the main values into vectors.
        for i in 0..main_width {
            main.local.push(builder.get(&opening.main.local, i));
            main.next.push(builder.get(&opening.main.next, i));
        }

        let mut permutation = AirOpenedValues { local: vec![], next: vec![] };
        let permutation_width = C::EF::D * chip.permutation_width();
        // Assert that the length of the dynamic arrays match the expected length of the vectors.
        builder.assert_usize_eq(permutation_width, opening.permutation.local.len());
        builder.assert_usize_eq(permutation_width, opening.permutation.next.len());
        // Collect the permutation values into vectors.
        for i in 0..permutation_width {
            permutation.local.push(builder.get(&opening.permutation.local, i));
            permutation.next.push(builder.get(&opening.permutation.next, i));
        }

        let num_quotient_chunks = 1 << chip.log_quotient_degree();
        let mut quotient = vec![];
        // Assert that the length of the quotient chunk arrays match the expected length.
        builder.assert_usize_eq(num_quotient_chunks, opening.quotient.len());
        // Collect the quotient values into vectors.
        for i in 0..num_quotient_chunks {
            let chunk = builder.get(&opening.quotient, i);
            // Assert that the chunk length matches the expected length.
            builder.assert_usize_eq(C::EF::D, chunk.len());
            // Collect the quotient values into vectors.
            let mut quotient_vals = vec![];
            for j in 0..C::EF::D {
                let value = builder.get(&chunk, j);
                quotient_vals.push(value);
            }
            quotient.push(quotient_vals);
        }

        ChipOpening {
            preprocessed,
            main,
            permutation,
            quotient,
            cumulative_sum: opening.cumulative_sum,
            log_degree: opening.log_degree,
        }
    }
}

impl<C: Config> FromConstant<C> for AirOpenedValuesVariable<C> {
    type Constant = AirOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        AirOpenedValuesVariable {
            local: builder.constant(value.local),
            next: builder.constant(value.next),
        }
    }
}

impl<C: Config> FromConstant<C> for ChipOpenedValuesVariable<C> {
    type Constant = ChipOpenedValues<C::EF>;

    fn constant(value: Self::Constant, builder: &mut Builder<C>) -> Self {
        ChipOpenedValuesVariable {
            preprocessed: builder.constant(value.preprocessed),
            main: builder.constant(value.main),
            permutation: builder.constant(value.permutation),
            quotient: builder.constant(value.quotient),
            cumulative_sum: builder.eval(value.cumulative_sum.cons()),
            log_degree: builder.eval(C::N::from_canonical_usize(value.log_degree)),
        }
    }
}

impl<C: Config> FriConfigVariable<C> {
    pub fn get_subgroup(
        &self,
        builder: &mut Builder<C>,
        log_degree: impl Into<Usize<C::N>>,
    ) -> TwoAdicMultiplicativeCosetVariable<C> {
        builder.get(&self.subgroups, log_degree)
    }

    pub fn get_two_adic_generator(
        &self,
        builder: &mut Builder<C>,
        bits: impl Into<Usize<C::N>>,
    ) -> Felt<C::F> {
        builder.get(&self.generators, bits)
    }
}
