#![allow(clippy::disallowed_types, clippy::disallowed_methods)]
use crate::zk::dot_product::dot_product;
use crate::zk::error_correcting_code::RsInterpolation;
use itertools::Itertools;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_algebra::AbstractField;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;

use super::{
    verify_zk_hadamard_and_dots, zk_hadamard_and_dots_proof, zk_hadamard_product_commitment,
};

type GC = KoalaBearDegree4Duplex;
type Code = RsInterpolation<<GC as IopCtx>::EF>;
type EF = <GC as IopCtx>::EF;

/// Computes the Hadamard (elementwise) product of two vectors.
pub fn hadamard_product<K>(a_vec: &[K], b_vec: &[K]) -> Vec<K>
where
    K: AbstractField + Copy,
{
    a_vec.iter().zip_eq(b_vec.iter()).map(|(a, b)| *a * *b).collect()
}

/// Runs the full combined Hadamard + dot product pipeline for honest inputs of the
/// given length, asserting the claimed dot products match directly-recomputed values.
fn run_hadamard_and_dots(length: usize) {
    let mut rng = ChaCha20Rng::from_entropy();
    let a_vec: Vec<EF> = (0..length).map(|_| rng.gen()).collect();
    let b_vec: Vec<EF> = (0..length).map(|_| rng.gen()).collect();
    let c_vec = hadamard_product(&a_vec, &b_vec);
    let dot_vec: Vec<EF> = (0..length).map(|_| rng.gen()).collect();

    let merkleizer = Poseidon2KoalaBear16Prover::default();

    // Prover: commit to [a, b, c] then generate the combined proof.
    let mut challenger = GC::default_challenger();
    let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<GC, _, _, Code>(
        &a_vec,
        &b_vec,
        &c_vec,
        &mut rng,
        &merkleizer,
    )
    .unwrap();
    let total_proof = zk_hadamard_and_dots_proof::<GC, _, Code>(
        commitment,
        &dot_vec,
        prover_secret_data,
        &mut challenger,
        &merkleizer,
    )
    .unwrap();

    // The committed vectors are [a, b, c]; check claimed dot products against direct computation.
    let expected = [
        dot_product(&a_vec, &dot_vec),
        dot_product(&b_vec, &dot_vec),
        dot_product(&c_vec, &dot_vec),
    ];
    assert_eq!(total_proof.dot_claimed_dot_products(), expected.as_slice());

    // Verifier.
    let mut challenger = GC::default_challenger();
    verify_zk_hadamard_and_dots::<GC, Code>(&commitment, &dot_vec, &total_proof, &mut challenger)
        .unwrap();
}

#[tokio::test]
async fn test_zk_hadamard_and_dots_honest() {
    run_hadamard_and_dots(100);
}

#[tokio::test]
async fn test_zk_hadamard_and_dots_large() {
    run_hadamard_and_dots(3000);
}

#[tokio::test]
async fn test_zk_hadamard_and_dots_different_sizes() {
    for length in [10, 50, 100, 500, 1000] {
        run_hadamard_and_dots(length);
    }
}

#[tokio::test]
#[should_panic(expected = "FDotZInconsistency")]
async fn test_zk_hadamard_and_dots_invalid() {
    use slop_algebra::AbstractField;

    const LENGTH: usize = 100;

    let mut rng = ChaCha20Rng::from_entropy();
    let a_vec: Vec<EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let b_vec: Vec<EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let mut c_vec = hadamard_product(&a_vec, &b_vec);
    // Corrupt one element so c != a ∘ b.
    c_vec[50] += EF::one();
    let dot_vec: Vec<EF> = (0..LENGTH).map(|_| rng.gen()).collect();

    let merkleizer = Poseidon2KoalaBear16Prover::default();
    let mut challenger = GC::default_challenger();
    let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<GC, _, _, Code>(
        &a_vec,
        &b_vec,
        &c_vec,
        &mut rng,
        &merkleizer,
    )
    .unwrap();
    let total_proof = zk_hadamard_and_dots_proof::<GC, _, Code>(
        commitment,
        &dot_vec,
        prover_secret_data,
        &mut challenger,
        &merkleizer,
    )
    .unwrap();

    // Verification must reject the corrupted Hadamard relation with
    // ZkHadamardAndDotsError::Hadamard(ZkHadamardProductError::FDotZInconsistency).
    let mut challenger = GC::default_challenger();
    verify_zk_hadamard_and_dots::<GC, Code>(&commitment, &dot_vec, &total_proof, &mut challenger)
        .unwrap();
}
