use p3_fri::FriConfig;
use sp1_recursion_compiler::ir::{Builder, Config, Felt};
use sp1_recursion_compiler::prelude::Array;
use sp1_recursion_compiler::prelude::MemVariable;
use sp1_recursion_compiler::prelude::*;
use sp1_recursion_core::stark::config::OuterChallengeMmcs;
use sp1_recursion_derive::DslVariable;

use crate::{challenger::MultiFieldChallengerVariable, DIGEST_SIZE};

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L27
pub fn verify_shape_and_sample_challenges<C: Config>(
    builder: &mut Builder<C>,
    _: &FriConfig<OuterChallengeMmcs>,
    proof: &FriProofVariable<C>,
    challenger: &mut MultiFieldChallengerVariable<C>,
) {
    let mut betas = vec![];

    #[allow(clippy::never_loop)]
    for i in 0..proof.commit_phase_commits.vec().len() {
        let commitment: [Var<C::N>; DIGEST_SIZE] = proof.commit_phase_commits.vec()[i]
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

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L12
#[derive(DslVariable, Clone)]
pub struct FriProofVariable<C: Config> {
    pub commit_phase_commits: Array<C, Array<C, Var<C::N>>>,
    pub query_proofs: Array<C, FriQueryProofVariable<C>>,
    pub final_poly: Ext<C::F, C::EF>,
    pub pow_witness: Felt<C::F>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(DslVariable, Clone)]
pub struct FriCommitPhaseProofStepVariable<C: Config> {
    pub sibling_value: Ext<C::F, C::EF>,
    pub opening_proof: Array<C, Array<C, Var<C::N>>>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L23
#[derive(DslVariable, Clone)]
pub struct FriQueryProofVariable<C: Config> {
    pub commit_phase_openings: Array<C, FriCommitPhaseProofStepVariable<C>>,
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use p3_baby_bear::BabyBear;
    use p3_bn254_fr::Bn254Fr;
    use p3_challenger::{CanObserve, CanSample, FieldChallenger};
    use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
    use p3_matrix::dense::RowMajorMatrix;
    use rand::rngs::OsRng;
    use sp1_recursion_compiler::{
        gnark::GnarkBackend,
        ir::{Builder, SymbolicExt, Var},
    };
    use sp1_recursion_core::stark::config::{
        outer_fri_config, outer_perm, OuterChallenge, OuterChallenger, OuterCompress, OuterDft,
        OuterFriProof, OuterHash, OuterPcs, OuterVal, OuterValMmcs,
    };

    use super::{
        verify_shape_and_sample_challenges, FriCommitPhaseProofStepVariable, FriProofVariable,
    };
    use crate::{
        challenger::MultiFieldChallengerVariable, fri::FriQueryProofVariable, GnarkConfig,
        DIGEST_SIZE,
    };

    pub fn const_fri_proof(
        builder: &mut Builder<GnarkConfig>,
        fri_proof: OuterFriProof,
    ) -> FriProofVariable<GnarkConfig> {
        // Set the commit phase commits.
        let commit_phase_commits = fri_proof
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: [Bn254Fr; DIGEST_SIZE] = (*commit).into();
                let commit: Var<_> = builder.eval(commit[0]);
                builder.vec(vec![commit])
            })
            .collect::<Vec<_>>();
        let commit_phase_commits = builder.vec(commit_phase_commits);

        // Set the query proofs.
        let query_proofs = fri_proof
            .query_proofs
            .iter()
            .map(|query_proof| {
                let commit_phase_openings = query_proof
                    .commit_phase_openings
                    .iter()
                    .map(|commit_phase_opening| {
                        let sibling_value =
                            builder.eval(SymbolicExt::Const(commit_phase_opening.sibling_value));
                        let opening_proof = commit_phase_opening
                            .opening_proof
                            .iter()
                            .map(|sibling| {
                                let commit: Var<_> = builder.eval(sibling[0]);
                                builder.vec(vec![commit])
                            })
                            .collect::<Vec<_>>();
                        let opening_proof = builder.vec(opening_proof);
                        FriCommitPhaseProofStepVariable {
                            sibling_value,
                            opening_proof,
                        }
                    })
                    .collect::<Vec<_>>();
                let commit_phase_openings = builder.vec(commit_phase_openings);
                FriQueryProofVariable {
                    commit_phase_openings,
                }
            })
            .collect::<Vec<_>>();
        let query_proofs = builder.vec(query_proofs);

        // Initialize the FRI proof variable.
        FriProofVariable {
            commit_phase_commits,
            query_proofs,
            final_poly: builder.eval(SymbolicExt::Const(fri_proof.final_poly)),
            pow_witness: builder.eval(fri_proof.pow_witness),
        }
    }

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

        // Define circuit.
        let mut builder = Builder::<GnarkConfig>::default();
        let config = outer_fri_config();
        let fri_proof = const_fri_proof(&mut builder, proof.fri_proof);

        let mut challenger = MultiFieldChallengerVariable::new(&mut builder);
        let commit: [Bn254Fr; DIGEST_SIZE] = commit.into();
        let commit: Var<_> = builder.eval(commit[0]);
        challenger.observe_commitment(&mut builder, [commit]);
        let s = challenger.sample_ext(&mut builder);
        builder.print_e(s);
        verify_shape_and_sample_challenges(&mut builder, &config, &fri_proof, &mut challenger);

        let mut backend = GnarkBackend::<GnarkConfig>::default();
        let result = backend.compile(builder.operations);
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let path = format!("{}/build/verifier.go", manifest_dir);
        let mut file = File::create(path).unwrap();
        file.write_all(result.as_bytes()).unwrap();
    }
}
