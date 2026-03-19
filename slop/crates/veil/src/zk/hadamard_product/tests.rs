#![allow(clippy::disallowed_types, clippy::disallowed_methods, dead_code)]
use crate::zk::error_correcting_code::RsInterpolation;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;

use std::time::Instant;

use super::{
    hadamard_product, verify_zk_hadamard_product, zk_hadamard_product_commitment,
    zk_hadamard_product_proof,
};

#[tokio::test]
async fn test_zk_hadamard_product_honest() {
    const LENGTH: usize = 3000;
    type GC = KoalaBearDegree4Duplex;

    // Generate three random vectors where c = a * b (Hadamard product)
    let mut rng = ChaCha20Rng::from_entropy();
    let a_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let b_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let c_vec = hadamard_product(&a_vec, &b_vec);

    // Compute and time commitment + proof generation
    let start = Instant::now();
    let merkleizer = Poseidon2KoalaBear16Prover::default();
    let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<
        GC,
        _,
        _,
        RsInterpolation<_>,
    >(&a_vec, &b_vec, &c_vec, &mut rng, &merkleizer);

    let mut challenger_prove = GC::default_challenger();
    let total_proof = zk_hadamard_product_proof::<GC, _, RsInterpolation<_>>(
        commitment,
        prover_secret_data,
        &mut challenger_prove,
        &merkleizer,
    );
    let duration = start.elapsed();
    eprintln!("Commitment + proof generation time: {:?}", duration);
    eprintln!("Proof gamma: {:?}", total_proof.proof.gamma);

    // Compute and time verification
    let start = Instant::now();
    let mut challenger_ver = GC::default_challenger();
    verify_zk_hadamard_product::<GC, RsInterpolation<_>>(
        &commitment,
        &total_proof,
        &mut challenger_ver,
    )
    .unwrap();
    let duration = start.elapsed();
    eprintln!("Verification time: {:?}", duration);
}

#[tokio::test]
async fn test_zk_hadamard_product_small() {
    const LENGTH: usize = 100;
    type GC = KoalaBearDegree4Duplex;

    // Generate three small random vectors
    let mut rng = ChaCha20Rng::from_entropy();
    let a_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let b_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let c_vec = hadamard_product(&a_vec, &b_vec);

    eprintln!("Testing with LENGTH={}", LENGTH);

    let merkleizer = Poseidon2KoalaBear16Prover::default();
    let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<
        GC,
        _,
        _,
        RsInterpolation<_>,
    >(&a_vec, &b_vec, &c_vec, &mut rng, &merkleizer);

    let mut challenger_prove = GC::default_challenger();
    let total_proof = zk_hadamard_product_proof::<GC, _, RsInterpolation<_>>(
        commitment,
        prover_secret_data,
        &mut challenger_prove,
        &merkleizer,
    );

    let mut challenger_ver = GC::default_challenger();
    verify_zk_hadamard_product::<GC, RsInterpolation<_>>(
        &commitment,
        &total_proof,
        &mut challenger_ver,
    )
    .unwrap();

    eprintln!("Small test passed!");
}

#[tokio::test]
#[should_panic(expected = "FDotZInconsistency")]
async fn test_zk_hadamard_product_invalid() {
    const LENGTH: usize = 100;
    type GC = KoalaBearDegree4Duplex;

    // Generate vectors where c != a * b (invalid Hadamard product)
    let mut rng = ChaCha20Rng::from_entropy();
    let a_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let b_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let mut c_vec = hadamard_product(&a_vec, &b_vec);

    // Corrupt one element of c
    use slop_algebra::AbstractField;
    c_vec[50] += <GC as IopCtx>::EF::one();

    let merkleizer = Poseidon2KoalaBear16Prover::default();
    let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<
        GC,
        _,
        _,
        RsInterpolation<_>,
    >(&a_vec, &b_vec, &c_vec, &mut rng, &merkleizer);

    let mut challenger_prove = GC::default_challenger();
    let total_proof = zk_hadamard_product_proof::<GC, _, RsInterpolation<_>>(
        commitment,
        prover_secret_data,
        &mut challenger_prove,
        &merkleizer,
    );

    let mut challenger_ver = GC::default_challenger();
    verify_zk_hadamard_product::<GC, RsInterpolation<_>>(
        &commitment,
        &total_proof,
        &mut challenger_ver,
    )
    .unwrap();
    // This should panic
}

#[tokio::test]
async fn test_zk_hadamard_product_different_sizes() {
    type GC = KoalaBearDegree4Duplex;

    for length in [10, 50, 100, 500, 1000] {
        eprintln!("\nTesting with LENGTH={}", length);

        let mut rng = ChaCha20Rng::from_entropy();
        let a_vec: Vec<<GC as IopCtx>::EF> = (0..length).map(|_| rng.gen()).collect();
        let b_vec: Vec<<GC as IopCtx>::EF> = (0..length).map(|_| rng.gen()).collect();
        let c_vec = hadamard_product(&a_vec, &b_vec);

        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<
            GC,
            _,
            _,
            RsInterpolation<_>,
        >(
            &a_vec, &b_vec, &c_vec, &mut rng, &merkleizer
        );

        let mut challenger_prove = GC::default_challenger();
        let total_proof = zk_hadamard_product_proof::<GC, _, RsInterpolation<_>>(
            commitment,
            prover_secret_data,
            &mut challenger_prove,
            &merkleizer,
        );

        let mut challenger_ver = GC::default_challenger();
        verify_zk_hadamard_product::<GC, RsInterpolation<_>>(
            &commitment,
            &total_proof,
            &mut challenger_ver,
        )
        .unwrap();

        eprintln!("Test passed for LENGTH={}", length);
    }
}

#[tokio::test]
async fn test_zk_hadamard_and_dots() {
    use super::{verify_zk_hadamard_and_dots, zk_hadamard_and_dots_proof};

    const LENGTH: usize = 100;
    type GC = KoalaBearDegree4Duplex;
    type Code = RsInterpolation<<GC as IopCtx>::EF>;

    eprintln!("Testing combined Hadamard + dot product proofs with LENGTH={}", LENGTH);

    // Generate three random vectors where c = a * b (Hadamard product)
    let mut rng = ChaCha20Rng::from_entropy();
    let a_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let b_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();
    let c_vec = hadamard_product(&a_vec, &b_vec);

    // Create a random vector to dot product with
    let dot_vec: Vec<<GC as IopCtx>::EF> = (0..LENGTH).map(|_| rng.gen()).collect();

    // ==================== PROVER ====================
    let (commitment, total_proof) = {
        let merkleizer = Poseidon2KoalaBear16Prover::default();
        let mut challenger = GC::default_challenger();

        // Commit to the three vectors for Hadamard product
        eprintln!("\n=== Committing vectors ===");
        let (commitment, prover_secret_data) = zk_hadamard_product_commitment::<GC, _, _, Code>(
            &a_vec,
            &b_vec,
            &c_vec,
            &mut rng,
            &merkleizer,
        );

        // Generate combined proofs with shared indices
        eprintln!("\n=== Generating combined Hadamard + dot product proofs ===");
        let total_proof = zk_hadamard_and_dots_proof::<GC, _, Code>(
            commitment,
            &dot_vec,
            prover_secret_data,
            &mut challenger,
            &merkleizer,
        );

        (commitment, total_proof)
    };

    // ==================== VERIFIER ====================
    {
        let mut challenger = GC::default_challenger();

        // Verify combined proofs
        eprintln!("\n=== Verifying combined proofs ===");
        verify_zk_hadamard_and_dots::<GC, Code>(
            &commitment,
            &dot_vec,
            &total_proof,
            &mut challenger,
        )
        .unwrap();
        eprintln!("All proofs verified successfully!");
    }

    eprintln!("\n=== Test passed! ===");
}
