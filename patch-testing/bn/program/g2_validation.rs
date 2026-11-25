macro_rules! validation_point {
    ($bn:ident, $coordinates:expr, $scaled:expr) => {{
        use $bn::{Fq, Fq2, G2};
        let coordinates = $coordinates;
        let x = Fq2::new(
            Fq::from_slice(&coordinates[0]).unwrap(),
            Fq::from_slice(&coordinates[1]).unwrap(),
        );
        let y = Fq2::new(
            Fq::from_slice(&coordinates[2]).unwrap(),
            Fq::from_slice(&coordinates[3]).unwrap(),
        );
        let z = if $scaled { Fq2::new(Fq::from_str("2").unwrap(), Fq::one()) } else { Fq2::one() };
        G2::new(x * z * z, y * z * z * z, z)
    }};
}
