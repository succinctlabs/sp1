#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::lib::bn254::Bn254AffinePoint;
use sp1_zkvm::lib::utils::AffinePoint;

#[sp1_derive::cycle_tracker]
pub fn main() {
    for _ in 0..4 {
        // generator.
        // 1
        // 2
        let a: [u32; 16] = [1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0];

        let mut a_point = Bn254AffinePoint::new(a);

        // scalar.
        // 3
        let scalar: [u32; 2] = [3, 0];

        println!("cycle-tracker-start: bn254_mul");
        a_point.mul_assign(&scalar).unwrap();
        println!("cycle-tracker-end: bn254_mul");

        // 3 * generator.
        // 3353031288059533942658390886683067124040920775575537747144343083137631628272
        // 19321533766552368860946552437480515441416830039777911637913418824951667761761
        let c: [u32; 16] = [
            420850672, 4073936278, 364439161, 2467682375, 2981543189, 4093784764, 3312183871,
            124370842, 3657310817, 3455188797, 194796375, 832463796, 2366137461, 1431296892,
            3762852905, 716675518,
        ];

        assert_eq!(a_point.0, c);
    }

    println!("done");
}
