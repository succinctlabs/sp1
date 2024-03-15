use sp1_recursion_compiler::ir::{Builder, Config, Ext, Felt, Slice, Var, Vector};

use p3_field::AbstractField;

use crate::symmetric::hash::Hash;

use super::proof::FriProof;

pub type OpenedValues<C> = Vector<C, OpenedValuesForRound<C>>;
pub type OpenedValuesForRound<C> = Vector<C, OpenedValuesForMatrix<C>>;
pub type OpenedValuesForMatrix<C> = Vector<C, OpenedValuesForPoint<C>>;
pub type OpenedValuesForPoint<C: Config> = Vector<C, Felt<C::F>>;

pub struct Dimensions<F> {
    pub width: Var<F>,
    pub height: Var<F>,
}

pub struct BatchOpening<C: Config> {
    opened_values: Vector<C, Vector<C, C::F>>,
    // pub(crate) opening_proof: <C::InputMmcs as Mmcs<C::Val>>::Proof,
}

pub struct TwoAdicFriPcsProof<C: Config, const DIGEST_ELEMS: usize> {
    fri_proof: FriProof<C, DIGEST_ELEMS>,
    /// For each query, for each committed batch, query openings for that batch
    query_openings: Vec<Vec<BatchOpening<C>>>,
}

pub struct FriConfig<C: Config> {
    pub log_blowup: Var<C::N>,
    pub num_queries: Var<C::N>,
    pub proof_of_work_bits: Var<C::N>,
    pub num_batches: Var<C::N>,
    pub num_tables_in_batches: Vector<C, Var<C::N>>,
    pub num_openings_in_batch: Vector<C, Var<C::N>>,
}

#[allow(clippy::too_many_arguments)]
fn verify_multi_batches<C: Config, const DIGEST_ELEMS: usize>(
    builder: &mut Builder<C>,
    fri_config: FriConfig<C>,
    commits_and_points: [(Hash<C::N, DIGEST_ELEMS>, [Vector<C, Ext<C::F, C::EF>>; 1]); 2],
    dims: &[Vector<C, Dimensions<C::N>>],
    values: OpenedValues<C>,
    proof: FriProof<C, DIGEST_ELEMS>,
    alpha: Ext<C::F, C::EF>,
    query_indices: Vector<C, Var<C::N>>,
    betas: Vector<C, Ext<C::F, C::EF>>,
) {
    let zero: Var<C::N> = builder.eval(C::N::zero());

    // Iterate over the query openings and query_indices (len == num_queries)
    // builder
    //     .range(zero, fri_config.num_queries)
    //     .for_each(|idx, builder| {
    //         let index = builder.get(&Slice::Vec(query_indices), idx);
    //         let temp: Felt<_> = builder.uninit();
    //         builder.assign(temp, b);
    //         builder.assign(b, a + b);
    //         builder.assign(a, temp);
    //     });
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
    use sp1_recursion_compiler::ir::Config;

    #[derive(Clone)]
    struct BabyBearConfig;

    impl Config for BabyBearConfig {
        type N = BabyBear;
        type F = BabyBear;
        type EF = BinomialExtensionField<BabyBear, 4>;
    }

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
