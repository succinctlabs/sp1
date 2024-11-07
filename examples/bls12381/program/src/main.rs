#![no_main]

use bls12_381::{
    fp::Fp, fp2::Fp2, multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared,
    G2Projective, Scalar,
};
use ff::Field;
use group::Group;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Fp operations
    {
        let lhs = Fp::one();
        let rhs = Fp::one();

        println!("cycle-tracker-start: bls12_381-add-fp");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-fp");
        println!("cycle-tracker-start: bls12_381-sub-fp");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bls12_381-sub-fp");
        println!("cycle-tracker-start: bls12_381-mul-fp");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bls12_381-mul-fp");
    }

    // Scalar operations
    {
        let lhs = Scalar::random(&mut rand::thread_rng());
        let rhs = Scalar::random(&mut rand::thread_rng());
        println!("cycle-tracker-start: bls12_381-add-scalar");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-scalar");
        println!("cycle-tracker-start: bls12_381-sub-scalar");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bls12_381-sub-scalar");
        println!("cycle-tracker-start: bls12_381-mul-scalar");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bls12_381-mul-scalar");
    }

    // Fp2 operations
    {
        let lhs = Fp2::random(&mut rand::thread_rng());
        let rhs = Fp2::random(&mut rand::thread_rng());
        println!("cycle-tracker-start: bls12_381-add-fp2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-fp2");
        println!("cycle-tracker-start: bls12_381-sub-fp2");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bls12_381-sub-fp2");
        println!("cycle-tracker-start: bls12_381-mul-fp2");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bls12_381-mul-fp2");
    }

    // G1 operations
    {
        let lhs = G1Projective::random(&mut rand::thread_rng());
        let rhs = G1Projective::random(&mut rand::thread_rng());
        println!("cycle-tracker-start: bls12_381-add-g1");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-g1");
        println!("cycle-tracker-start: bls12_381-mul-g1");
        let _ = lhs * Scalar::random(&mut rand::thread_rng());
        println!("cycle-tracker-end: bls12_381-mul-g1");
    }

    // G2 operations
    {
        let lhs = G2Projective::random(&mut rand::thread_rng());
        let rhs = G2Projective::random(&mut rand::thread_rng());
        println!("cycle-tracker-start: bls12_381-add-g2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bls12_381-add-g2");
        println!("cycle-tracker-start: bls12_381-mul-g2");
        let _ = lhs * Scalar::random(&mut rand::thread_rng());
        println!("cycle-tracker-end: bls12_381-mul-g2");
    }

    // Pairing
    {
        let p1 = G1Affine::from(G1Projective::random(&mut rand::thread_rng()));
        let p2 = G2Affine::from(G2Projective::random(&mut rand::thread_rng()));
        println!("cycle-tracker-start: bls12_381-pairing");
        let _ = pairing(&p1, &p2);
        println!("cycle-tracker-end: bls12_381-pairing");
    }

    // Pairing Check
    {
        let p1 = G1Affine::from(G1Projective::random(&mut rand::thread_rng()));
        let q1 = G2Affine::from(G2Projective::random(&mut rand::thread_rng()));
        let p2 = G1Affine::from(G1Projective::random(&mut rand::thread_rng()));
        let q2 = G2Affine::from(G2Projective::random(&mut rand::thread_rng()));
        println!("cycle-tracker-start: bls12_381-pairing-check");
        multi_miller_loop(&[(&p1, &G2Prepared::from(q1)), (&p2, &G2Prepared::from(q2))])
            .final_exponentiation();
        println!("cycle-tracker-end: bls12_381-pairing-check");
    }
}
