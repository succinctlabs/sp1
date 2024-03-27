use p3_fri::{verifier::FriChallenges, FriConfig};
use sp1_recursion_compiler::{
    ir::{Builder, Config, Felt},
    verifier::fri::types::FriProofVariable,
};
use sp1_recursion_core::stark::bn254::ChallengeMmcs;

use crate::{challenger::MultiFieldChallengerVariable, DIGEST_SIZE};

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<ChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut MultiFieldChallengerVariable<C>,
) -> FriChallenges<C> {
    let mut betas = vec![];

    for i in 0..proof.commit_phase_commits.vec().len() {
        let commitment: [Felt<C::F>; DIGEST_SIZE] = proof.commit_phase_commits.vec()[i]
            .vec()
            .try_into()
            .unwrap();
        challenger.observe_commitment(builder, commitment);
        let sample = challenger.sample(builder);
        betas.push(sample);
    }

    let num_query_proofs = proof.query_proofs.vec().len();
    assert_eq!(num_query_proofs, config.num_queries);

    todo!()
}
