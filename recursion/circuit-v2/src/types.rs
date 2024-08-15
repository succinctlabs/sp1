use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, TwoAdicField};
use p3_matrix::Dimensions;

use sp1_core::{stark::StarkVerifyingKey, utils::BabyBearPoseidon2};
use sp1_recursion_compiler::{
    circuit::CircuitV2Builder,
    ir::{Builder, Config, Ext, Felt},
};

use sp1_recursion_core_v2::DIGEST_SIZE;

use crate::challenger::CanObserveVariable;

pub type DigestVariable<C> = [Felt<<C as Config>::F>; DIGEST_SIZE];

/// Reference: [sp1_core::stark::StarkVerifyingKey]
#[derive(Clone)]
pub struct VerifyingKeyVariable<C: Config> {
    pub commitment: DigestVariable<C>,
    pub pc_start: Felt<C::F>,
    pub chip_information: Vec<(String, TwoAdicMultiplicativeCoset<C::F>, Dimensions)>,
    pub chip_ordering: HashMap<String, usize>,
}

#[derive(Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Vec<DigestVariable<C>>,
    pub query_proofs: Vec<FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Vec<DigestVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<C>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallenges<C: Config> {
    pub query_indices: Vec<Vec<Felt<C::F>>>,
    pub betas: Vec<Ext<C::F, C::EF>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsProofVariable<C: Config> {
    pub fri_proof: FriProofVariable<C>,
    pub query_openings: Vec<Vec<BatchOpeningVariable<C>>>,
}

#[derive(Clone)]
pub struct BatchOpeningVariable<C: Config> {
    pub opened_values: Vec<Vec<Vec<Felt<C::F>>>>,
    pub opening_proof: Vec<DigestVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<C: Config> {
    pub batch_commit: DigestVariable<C>,
    pub domains_points_and_opens: Vec<TwoAdicPcsMatsVariable<C>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<C: Config> {
    pub domain: TwoAdicMultiplicativeCoset<C::F>,
    pub points: Vec<Ext<C::F, C::EF>>,
    pub values: Vec<Vec<Ext<C::F, C::EF>>>,
}

impl<C: Config> VerifyingKeyVariable<C> {
    pub fn from_constant_key_babybear(
        builder: &mut Builder<C>,
        vk: &StarkVerifyingKey<BabyBearPoseidon2>,
    ) -> Self
    where
        C: Config<F = BabyBear>,
    {
        let commitment_array: [_; DIGEST_SIZE] = vk.commit.into();
        let commitment = commitment_array.map(|x| builder.eval(x));
        let pc_start = builder.eval(vk.pc_start);

        Self {
            commitment,
            pc_start,
            chip_information: vk.chip_information.clone(),
            chip_ordering: vk.chip_ordering.clone(),
        }
    }

    pub fn observe_into<Challenger>(&self, builder: &mut Builder<C>, challenger: &mut Challenger)
    where
        Challenger: CanObserveVariable<C, Felt<C::F>> + CanObserveVariable<C, DigestVariable<C>>,
    {
        // Observe the commitment.
        challenger.observe(builder, self.commitment);
        // Observe the pc_start.
        challenger.observe(builder, self.pc_start);
    }

    /// Hash the verifying key + prep domains into a single digest.
    /// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
    pub fn hash(&self, builder: &mut Builder<C>) -> DigestVariable<C>
    where
        C::F: TwoAdicField,
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

        builder.poseidon2_hash_v2(&inputs)
    }
}
