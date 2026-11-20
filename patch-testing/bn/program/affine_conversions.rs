macro_rules! check_conversions {
    ($bn:ident) => {{
        use $bn::{AffineG1, AffineG2, Fq, Fq2, Fr, Group, G1, G2};

        let mut results = Vec::new();
        // Start with a doubled point so the old G2 conversion fails immediately.
        for scalar in [
            Fr::from_str("2").unwrap(),
            Fr::zero(),
            Fr::one(),
            Fr::from_str("3").unwrap(),
            Fr::from_str("17").unwrap(),
            Fr::from_str("1337").unwrap(),
            -Fr::one(),
        ] {
            let g1 = G1::one() * scalar;
            let g2 = G2::one() * scalar;
            let a1: AffineG1 = g1.into();
            let a2 = AffineG2::from(g2);
            assert_eq!(a1, AffineG1::from_jacobian(g1).unwrap_or_else(AffineG1::zero));
            assert_eq!(a2, AffineG2::from_jacobian(g2).unwrap_or_else(AffineG2::zero));
            let round_trip: G1 = a1.into();
            assert_eq!(round_trip, g1);
            assert_eq!(G2::from(a2), g2);

            let mut normalized1 = g1;
            let mut normalized2 = g2;
            normalized1.normalize();
            normalized2.normalize();
            let normalized_affine1: AffineG1 = normalized1.into();
            assert_eq!(normalized_affine1, a1);
            assert_eq!(AffineG2::from(normalized2), a2);

            // Equivalent Jacobian coordinates use X*z^2 and Y*z^3.
            for scale in [Fq::from_str("2").unwrap(), -Fq::one()] {
                let square = scale * scale;
                let scaled = G1::new(g1.x() * square, g1.y() * square * scale, g1.z() * scale);
                assert_eq!(scaled, g1);
                let scaled_affine: AffineG1 = scaled.into();
                assert_eq!(scaled_affine, a1);
            }
            for scale in [Fq2::new(Fq::from_str("2").unwrap(), Fq::one()), -Fq2::one()] {
                let square = scale * scale;
                let scaled = G2::new(g2.x() * square, g2.y() * square * scale, g2.z() * scale);
                assert_eq!(scaled, g2);
                assert_eq!(AffineG2::from(scaled), a2);
            }

            let coordinates = [
                a1.x(),
                a1.y(),
                a2.x().real(),
                a2.x().imaginary(),
                a2.y().real(),
                a2.y().imaginary(),
            ];
            let mut encoded = vec![0u8; 192];
            for (coordinate, bytes) in coordinates.into_iter().zip(encoded.chunks_mut(32)) {
                coordinate.to_big_endian(bytes).unwrap();
            }
            results.push(encoded);
        }

        let doubled1: AffineG1 = G1::one().double().into();
        let added1: AffineG1 = (G1::one() + G1::one()).into();
        assert_eq!(doubled1, added1);
        assert_eq!(
            AffineG2::from(G2::one() + G2::one()),
            AffineG2::from(G2::one() * Fr::from_str("2").unwrap())
        );
        let zero1: AffineG1 = (G1::one() - G1::one()).into();
        assert_eq!(zero1, AffineG1::zero());
        assert_eq!(AffineG2::from(G2::one() - G2::one()), AffineG2::zero());
        results
    }};
}
