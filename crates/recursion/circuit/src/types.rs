use hashbrown::HashMap;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, TwoAdicField};
use p3_matrix::Dimensions;

use sp1_recursion_compiler::ir::{Builder, Ext, Felt};

use sp1_recursion_core::DIGEST_SIZE;

use crate::{
    challenger::CanObserveVariable, hash::FieldHasherVariable, BabyBearFriConfigVariable,
    CircuitConfig,
};

/// Reference: [sp1_core::stark::StarkVerifyingKey]
#[derive(Clone)]
pub struct VerifyingKeyVariable<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>> {
    pub commitment: SC::DigestVariable,
    pub pc_start: Felt<C::F>,
    pub chip_information: Vec<(String, TwoAdicMultiplicativeCoset<C::F>, Dimensions)>,
    pub chip_ordering: HashMap<String, usize>,
}

#[derive(Clone)]
pub struct FriProofVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub commit_phase_commits: Vec<H::DigestVariable>,
    pub query_proofs: Vec<FriQueryProofVariable<C, H>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<H::DigestVariable>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProofVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C, H>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallenges<C: CircuitConfig> {
    pub query_indices: Vec<Vec<C::Bit>>,
    pub betas: Vec<Ext<C::F, C::EF>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsProofVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub fri_proof: FriProofVariable<C, H>,
    pub query_openings: Vec<Vec<BatchOpeningVariable<C, H>>>,
}

#[derive(Clone)]
pub struct BatchOpeningVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    pub opening_proof: Vec<H::DigestVariable>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<C: CircuitConfig, H: FieldHasherVariable<C>> {
    pub batch_commit: H::DigestVariable,
    pub domains_points_and_opens: Vec<TwoAdicPcsMatsVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<C: CircuitConfig> {
    pub domain: TwoAdicMultiplicativeCoset<C::F>,
    pub points: Vec<Ext<C::F, C::EF>>,
    pub values: Vec<Vec<Ext<C::F, C::EF>>>,
}

impl<C: CircuitConfig<F = SC::Val>, SC: BabyBearFriConfigVariable<C>> VerifyingKeyVariable<C, SC> {
    pub fn observe_into<Challenger>(&self, builder: &mut Builder<C>, challenger: &mut Challenger)
    where
        Challenger: CanObserveVariable<C, Felt<C::F>> + CanObserveVariable<C, SC::DigestVariable>,
    {
        // Observe the commitment.
        challenger.observe(builder, self.commitment);
        // Observe the pc_start.
        challenger.observe(builder, self.pc_start);
        // Observe the padding.
        let zero: Felt<_> = builder.eval(C::F::zero());
        for _ in 0..7 {
            challenger.observe(builder, zero);
        }
    }

    /// Hash the verifying key + prep domains into a single digest.
    /// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
    pub fn hash(&self, builder: &mut Builder<C>) -> SC::DigestVariable
    where
        C::F: TwoAdicField,
        SC::DigestVariable: IntoIterator<Item = Felt<C::F>>,
    {
        let prep_domains = self.chip_information.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commitment);
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(builder.eval(C::F::from_canonical_usize(domain.log_n)));
            let size = 1 << domain.log_n;
            inputs.push(builder.eval(C::F::from_canonical_usize(size)));
            let g = C::F::two_adic_generator(domain.log_n);
            inputs.push(builder.eval(domain.shift));
            inputs.push(builder.eval(g));
        }

        SC::hash(builder, &inputs)
    }
}
