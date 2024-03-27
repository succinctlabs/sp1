use p3_fri::FriConfig;
use sp1_recursion_compiler::{
    ir::{Builder, Config, Felt},
    verifier::fri::types::FriProofVariable,
};
use sp1_recursion_core::stark::config::OuterChallengeMmcs;

use crate::{challenger::MultiFieldChallengerVariable, DIGEST_SIZE};

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    config: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut MultiFieldChallengerVariable<C>,
) {
    let mut betas = vec![];

    for i in 0..proof.commit_phase_commits.vec().len() {
        let commitment: [Felt<C::F>; DIGEST_SIZE] = proof.commit_phase_commits.vec()[i]
            .vec()
            .try_into()
            .unwrap();
        challenger.observe_commitment(builder, commitment);
        let sample = challenger.sample_ext(builder);
        betas.push(sample);
    }

    for beta in betas.iter() {
        builder.print_e(*beta);
    }
}

#[cfg(test)]
mod tests {
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use sp1_recursion_core::stark::config::{
        outer_fri_config, outer_perm, OuterChallenge, OuterChallenger, OuterCompress, OuterDft,
        OuterHash, OuterPcs, OuterVal, OuterValMmcs,
    };

    #[test]
    fn test_fri_verify_shape_and_sample_challenges() {
        let mut rng = &mut OsRng;
        let log_degrees = &[16, 9, 7, 4, 2];
        let perm = outer_perm();
        let fri_config = outer_fri_config();
        let hash = OuterHash::new(perm.clone()).unwrap();
        let compress = OuterCompress::new(perm.clone());
        let val_mmcs = OuterValMmcs::new(hash, compress);
        let dft = OuterDft {};
        let pcs: OuterPcs = OuterPcs::new(
            log_degrees.iter().copied().max().unwrap(),
            dft,
            val_mmcs,
            fri_config,
        );

        // Generate proof.
        let domains_and_polys = log_degrees
            .iter()
            .map(|&d| {
                (
                    <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::natural_domain_for_degree(
                        &pcs,
                        1 << d,
                    ),
                    RowMajorMatrix::<OuterVal>::rand(&mut rng, 1 << d, 10),
                )
            })
            .collect::<Vec<_>>();
        let (commit, data) = <OuterPcs as Pcs<OuterChallenge, OuterChallenger>>::commit(
            &pcs,
            domains_and_polys.clone(),
        );
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        let zeta = challenger.sample_ext_element::<OuterChallenge>();
        let points = domains_and_polys
            .iter()
            .map(|_| vec![zeta])
            .collect::<Vec<_>>();
        let (opening, proof) = pcs.open(vec![(&data, points)], &mut challenger);

        // Verify proof.
        let mut challenger = OuterChallenger::new(perm.clone()).unwrap();
        challenger.observe(commit);
        challenger.sample_ext_element::<OuterChallenge>();
        let os: Vec<(
            TwoAdicMultiplicativeCoset<OuterVal>,
            Vec<(OuterChallenge, Vec<OuterChallenge>)>,
        )> = domains_and_polys
            .iter()
            .zip(&opening[0])
            .map(|((domain, _), mat_openings)| (*domain, vec![(zeta, mat_openings[0].clone())]))
            .collect();
        pcs.verify(vec![(commit, os.clone())], &proof, &mut challenger)
            .unwrap();
    }
}
