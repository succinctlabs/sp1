#![allow(clippy::disallowed_types, clippy::disallowed_methods)]
use crate::zk::error_correcting_code::*;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;

use super::verifier::ZkDotProductError;
use super::{
    dot_product, verify_zk_dot_product, verify_zk_dot_products, zk_dot_product_commitment,
    zk_dot_product_proof, zk_dot_products_proof,
};

#[tokio::test]
async fn test_zk_dot_product() {
    const LENGTH: usize = 3000;
    type GC = KoalaBearDegree4Duplex;
    type Code = RsFromCoefficients<<GC as IopCtx>::EF>;

    let mut rng = ChaCha20Rng::from_entropy();
    let in_vec: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();
    let dot_vec: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();
    let expected = dot_product(&in_vec, &dot_vec);

    // Prover
    let (commitment, total_proof) = {
        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let (commitment, prover_secret_data) =
            zk_dot_product_commitment::<GC, _, _, Code>(&[in_vec], &mut rng, &merkleizer);
        let mut challenger = GC::default_challenger();
        let total_proof = zk_dot_product_proof::<GC, _, Code>(
            &dot_vec,
            &commitment,
            prover_secret_data,
            &mut challenger,
            &merkleizer,
        );
        (commitment, total_proof)
    };

    assert_eq!(total_proof.proof.claimed_dot_products[0], expected);

    // Verifier
    let mut challenger = GC::default_challenger();
    verify_zk_dot_product::<GC, Code>(&commitment, &dot_vec, &total_proof, &mut challenger)
        .unwrap();
}

#[tokio::test]
async fn test_zk_dot_products_100() {
    const LENGTH: usize = 3000;
    const NUM_DOT_VECS: usize = 100;
    type GC = KoalaBearDegree4Duplex;
    type Code = RsFromCoefficients<<GC as IopCtx>::EF>;

    let mut rng = ChaCha20Rng::from_entropy();
    let in_vec: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();
    let dot_vecs: Vec<Vec<<GC as IopCtx>::EF>> =
        std::iter::repeat_with(|| std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect())
            .take(NUM_DOT_VECS)
            .collect();

    // Prover
    let (commitment, total_proof) = {
        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let (commitment, prover_secret_data) =
            zk_dot_product_commitment::<GC, _, _, Code>(&[in_vec], &mut rng, &merkleizer);
        let mut challenger = GC::default_challenger();
        let total_proof = zk_dot_products_proof::<GC, _, Code>(
            &dot_vecs,
            commitment,
            prover_secret_data,
            &mut challenger,
            &merkleizer,
        );
        (commitment, total_proof)
    };

    // Verifier
    let mut challenger = GC::default_challenger();
    verify_zk_dot_products::<GC, RsFromCoefficients<_>>(
        &commitment,
        &dot_vecs,
        &total_proof,
        &mut challenger,
    )
    .unwrap();
}

#[tokio::test]
async fn test_zk_dot_products_100_corrupted() {
    const LENGTH: usize = 3000;
    const NUM_DOT_VECS: usize = 100;
    type GC = KoalaBearDegree4Duplex;

    let mut rng = ChaCha20Rng::from_entropy();
    let in_vec: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();
    let dot_vecs: Vec<Vec<<GC as IopCtx>::EF>> =
        std::iter::repeat_with(|| std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect())
            .take(NUM_DOT_VECS)
            .collect();

    // Prover
    let (commitment, total_proof) = {
        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let (commitment, prover_secret_data) = zk_dot_product_commitment::<
            GC,
            _,
            _,
            RsFromCoefficients<_>,
        >(&[in_vec], &mut rng, &merkleizer);
        let mut challenger = GC::default_challenger();
        let total_proof = zk_dot_products_proof::<GC, _, RsFromCoefficients<_>>(
            &dot_vecs,
            commitment,
            prover_secret_data,
            &mut challenger,
            &merkleizer,
        );
        (commitment, total_proof)
    };

    // Corrupt one random dot_vec entry
    let mut corrupted_dot_vecs = dot_vecs.clone();
    corrupted_dot_vecs[rng.gen_range(0..NUM_DOT_VECS)][rng.gen_range(0..LENGTH)] = rng.gen();

    // Verifier (should fail)
    let mut challenger = GC::default_challenger();
    let result = verify_zk_dot_products::<GC, RsFromCoefficients<_>>(
        &commitment,
        &corrupted_dot_vecs,
        &total_proof,
        &mut challenger,
    );
    match result {
        Err(ZkDotProductError::RLCDotInconsistency) => {}
        other => panic!("Expected RLCDotInconsistency error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_zk_dot_product_batched() {
    const LENGTH: usize = 3000;
    const NUM_INPUT_VECS: usize = 100;
    type GC = KoalaBearDegree4Duplex;
    type Code = RsFromCoefficients<<GC as IopCtx>::EF>;

    let mut rng = ChaCha20Rng::from_entropy();
    let in_vecs: Vec<Vec<<GC as IopCtx>::EF>> =
        std::iter::repeat_with(|| std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect())
            .take(NUM_INPUT_VECS)
            .collect();
    let dot_vec: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();

    let expected: Vec<_> = in_vecs.iter().map(|v| dot_product(v, &dot_vec)).collect();

    // Prover
    let (commitment, total_proof) = {
        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let (commitment, prover_secret_data) =
            zk_dot_product_commitment::<GC, _, _, Code>(&in_vecs, &mut rng, &merkleizer);
        let mut challenger = GC::default_challenger();
        let total_proof = zk_dot_product_proof::<GC, _, Code>(
            &dot_vec,
            &commitment,
            prover_secret_data,
            &mut challenger,
            &merkleizer,
        );
        (commitment, total_proof)
    };

    assert_eq!(total_proof.proof.claimed_dot_products, expected);

    // Verifier
    let mut challenger = GC::default_challenger();
    verify_zk_dot_product::<GC, Code>(&commitment, &dot_vec, &total_proof, &mut challenger)
        .unwrap();
}

#[tokio::test]
async fn test_zk_dot_product_batched_corrupted() {
    const LENGTH: usize = 3000;
    const NUM_INPUT_VECS: usize = 5;
    type GC = KoalaBearDegree4Duplex;
    type Code = RsFromCoefficients<<GC as IopCtx>::EF>;

    let mut rng = ChaCha20Rng::from_entropy();
    let in_vecs: Vec<Vec<<GC as IopCtx>::EF>> =
        std::iter::repeat_with(|| std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect())
            .take(NUM_INPUT_VECS)
            .collect();
    let dot_vec: Vec<<GC as IopCtx>::EF> =
        std::iter::repeat_with(|| rng.gen()).take(LENGTH).collect();

    // Prover
    let (commitment, mut total_proof) = {
        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let (commitment, prover_secret_data) =
            zk_dot_product_commitment::<GC, _, _, Code>(&in_vecs, &mut rng, &merkleizer);
        let mut challenger = GC::default_challenger();
        let total_proof = zk_dot_product_proof::<GC, _, Code>(
            &dot_vec,
            &commitment,
            prover_secret_data,
            &mut challenger,
            &merkleizer,
        );
        (commitment, total_proof)
    };

    // Corrupt a random claimed dot product
    total_proof.proof.claimed_dot_products[rng.gen_range(0..NUM_INPUT_VECS)] +=
        rng.gen::<<GC as IopCtx>::EF>();

    // Verifier (should fail with RLCDotInconsistency)
    let mut challenger = GC::default_challenger();
    let result =
        verify_zk_dot_product::<GC, Code>(&commitment, &dot_vec, &total_proof, &mut challenger);
    match result {
        Err(ZkDotProductError::RLCDotInconsistency) => {}
        other => panic!("Expected RLCDotInconsistency, got: {:?}", other),
    }
}
