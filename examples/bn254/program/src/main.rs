#![no_main]

use substrate_bn::{pairing, pairing_batch, Fq, Fq2, Fr, Group, G1, G2};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    {
        let lhs = Fq::random(&mut rand::thread_rng());
        let rhs = Fq::random(&mut rand::thread_rng());

        println!("cycle-tracker-start: bn254-add-fp");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-fp");

        println!("cycle-tracker-start: bn254-sub-fp");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bn254-sub-fp");

        println!("cycle-tracker-start: bn254-mul-fp");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bn254-mul-fp");
    }

    {
        let lhs = Fr::random(&mut rand::thread_rng());
        let rhs = Fr::random(&mut rand::thread_rng());

        println!("cycle-tracker-start: bn254-add-fr");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-fr");

        println!("cycle-tracker-start: bn254-sub-fr");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bn254-sub-fr");

        println!("cycle-tracker-start: bn254-mul-fr");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bn254-mul-fr");
    }

    {
        let lhs =
            Fq2::new(Fq::random(&mut rand::thread_rng()), Fq::random(&mut rand::thread_rng()));
        let rhs =
            Fq2::new(Fq::random(&mut rand::thread_rng()), Fq::random(&mut rand::thread_rng()));

        println!("cycle-tracker-start: bn254-add-fq2");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-fq2");

        println!("cycle-tracker-start: bn254-sub-fq2");
        let _ = lhs - rhs;
        println!("cycle-tracker-end: bn254-sub-fq2");

        println!("cycle-tracker-start: bn254-mul-fq2");
        let _ = lhs * rhs;
        println!("cycle-tracker-end: bn254-mul-fq2");
    }

    {
        let lhs = G1::random(&mut rand::thread_rng());
        let rhs = G1::random(&mut rand::thread_rng());

        println!("cycle-tracker-start: bn254-add-g1");
        let _ = lhs + rhs;
        println!("cycle-tracker-end: bn254-add-g1");

        println!("cycle-tracker-start: bn254-mul-g1");
        let _ = lhs * Fr::random(&mut rand::thread_rng());
        println!("cycle-tracker-end: bn254-mul-g1");
    }

    {
        {
            let lhs = G2::random(&mut rand::thread_rng());
            let rhs = G2::random(&mut rand::thread_rng());

            println!("cycle-tracker-start: bn254-add-g2");
            let _ = lhs + rhs;
            println!("cycle-tracker-end: bn254-add-g2");

            println!("cycle-tracker-start: bn254-mul-g2");
            let _ = lhs * Fr::random(&mut rand::thread_rng());
            println!("cycle-tracker-end: bn254-mul-g2");
        }
    }

    {
        let p1 = G1::random(&mut rand::thread_rng());
        let p2 = G2::random(&mut rand::thread_rng());

        println!("cycle-tracker-start: bn254-pairing");
        let _ = pairing(p1, p2);
        println!("cycle-tracker-end: bn254-pairing");
    }

    {
        let p1 = G1::random(&mut rand::thread_rng());
        let q1 = G2::random(&mut rand::thread_rng());
        let p2 = G1::random(&mut rand::thread_rng());
        let q2 = G2::random(&mut rand::thread_rng());

        println!("cycle-tracker-start: bn254-pairing-check");
        pairing_batch(&[(p1, q1), (p2, q2)]).final_exponentiation();
        println!("cycle-tracker-end: bn254-pairing-check");
    }
}
