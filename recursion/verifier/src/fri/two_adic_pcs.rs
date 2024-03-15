use p3_field::Field;
use sp1_recursion_compiler::{
    asm::VmBuilder,
    ir::{Ext, Felt, Var},
};

use crate::symmetric::hash::Hash;

use super::proof::FriProof;

pub type OpenedValues<F> = Vec<OpenedValuesForRound<F>>;
pub type OpenedValuesForRound<F> = Vec<OpenedValuesForMatrix<F>>;
pub type OpenedValuesForMatrix<F> = Vec<OpenedValuesForPoint<F>>;
pub type OpenedValuesForPoint<F> = Vec<Felt<F>>;

pub struct Dimensions<F> {
    pub width: Var<F>,
    pub height: Var<F>,
}

fn verify_multi_batches<F: Field, EF, const DIGEST_ELEMS: usize>(
    builder: &mut VmBuilder<F>,
    commits_and_points: &[(Hash<F, DIGEST_ELEMS>, &[Vec<Ext<F, EF>>])],
    dims: &[Vec<Dimensions<F>>],
    values: OpenedValues<F>,
    proof: FriProof<F, DIGEST_ELEMS>,
    alpha: Ext<F, EF>,
    query_indices: Vec<Var<F>>,
    betas: Vec<Ext<F, EF>>,
) {
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_challenger::DuplexChallenger;
    use p3_commit::{ExtensionMmcs, OpenedValues, Pcs, UnivariatePcs};
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::Field;
    use p3_fri::{verifier::FriChallenges, FriConfig, TwoAdicFriPcs, TwoAdicFriPcsConfig};
    use p3_matrix::{dense::RowMajorMatrix, Dimensions};
    use p3_merkle_tree::FieldMerkleTreeMmcs;
    use p3_poseidon2::{DiffusionMatrixBabybear, Poseidon2};
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::StarkConfig;
    use rand::thread_rng;

    #[test]
    fn test_verify_multibatch() {
        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type Perm = Poseidon2<Val, DiffusionMatrixBabybear, 16, 7>;
        let mut perm = Perm::new_from_rng(8, 22, DiffusionMatrixBabybear, &mut thread_rng(), false);

        type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        let hash = MyHash::new(perm.clone());

        type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
        let compress = MyCompress::new(perm.clone());

        type ValMmcs = FieldMerkleTreeMmcs<
            <Val as Field>::Packing,
            <Val as Field>::Packing,
            MyHash,
            MyCompress,
            8,
        >;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel;
        let dft = Dft {};

        type Challenger = DuplexChallenger<Val, Perm, 16>;

        let fri_config = FriConfig {
            log_blowup: 1,
            num_queries: 100,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        type PCSType = TwoAdicFriPcs<
            TwoAdicFriPcsConfig<Val, Challenge, Challenger, Dft, ValMmcs, ChallengeMmcs>,
        >;

        type MyConfig = StarkConfig<Val, Challenge, PCSType, Challenger>;

        let commits_and_points: [(
            <PCSType as Pcs<Val, RowMajorMatrix<Val>>>::Commitment,
            [Vec<Challenge>; 1],
        ); 2] = serde_json::from_slice(
            &std::fs::read("fixtures/verify_multi_batch/commit_and_points").unwrap(),
        )
        .unwrap();
        let dims: [Vec<Dimensions>; 2] =
            serde_json::from_slice(&std::fs::read("fixtures/verify_multi_batch/dims").unwrap())
                .unwrap();
        let values: OpenedValues<Challenge> =
            serde_json::from_slice(&std::fs::read("fixtures/verify_multi_batch/values").unwrap())
                .unwrap();
        let proof: <PCSType as Pcs<Val, RowMajorMatrix<Val>>>::Proof = serde_json::from_slice(
            &std::fs::read("fixtures/verify_multi_batch/opening_proof").unwrap(),
        )
        .unwrap();
        let fri_challenges: FriChallenges<Challenge> = serde_json::from_slice(
            &std::fs::read("fixtures/verify_multi_batch/fri_challenges").unwrap(),
        )
        .unwrap();
        let alpha: Challenge =
            serde_json::from_slice(&std::fs::read("fixtures/verify_multi_batch/alpha").unwrap())
                .unwrap();

        let mut challenger = Challenger::new(perm.clone());
        let pcs = PCSType::new(fri_config, dft, val_mmcs);
        let res = <PCSType as UnivariatePcs<Val, Challenge, RowMajorMatrix<Val>, Challenger>>::verify_multi_batches(
            &pcs,
            &[
                (commits_and_points[0].0, &commits_and_points[0].1),
                (commits_and_points[1].0, &commits_and_points[1].1),
            ],
            &dims,
            values,
            &proof,
            &mut challenger,
            alpha,
            fri_challenges.query_indices,
            fri_challenges.betas,
        );
        println!("res is {:?}", res);
    }
}
