use super::*;
use elliptic_curve::Field;
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint as K256ProjectivePoint, Scalar};
use rand::{rngs::StdRng, SeedableRng};
use std::{hint::black_box, time::Instant};

type Point = AffinePoint<SwCurve<Secp256k1Parameters>>;

// Keep the original implementation as an independent correctness and performance baseline.
impl AffinePoint<SwCurve<Secp256k1Parameters>> {
    pub fn reference_add(&self, other: &Self) -> Self {
        let this_bytes = self.to_sec1_uncompressed();
        let other_bytes = other.to_sec1_uncompressed();

        let this: K256AffinePoint =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(this_bytes).unwrap())
                .unwrap();
        let this = K256ProjectivePoint::from(this);

        let other =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(other_bytes).unwrap())
                .unwrap();
        let other = K256ProjectivePoint::from(other);

        let result = this + other;
        let result = result.to_affine();
        // Save it as a uncompressed point
        let result_bytes = result.to_encoded_point(false);
        let result_bytes = result_bytes.as_bytes();

        // Skip the first byte which is the compression flag
        AffinePoint::new(
            BigUint::from_bytes_be(&result_bytes[1..33]),
            BigUint::from_bytes_be(&result_bytes[33..65]),
        )
    }

    pub fn reference_double(&self) -> Self {
        let this_bytes = self.to_sec1_uncompressed();
        let this =
            K256AffinePoint::from_encoded_point(&EncodedPoint::from_bytes(this_bytes).unwrap())
                .unwrap();

        let this = K256ProjectivePoint::from(this);

        let result = this.double();
        let result = result.to_affine();

        // Save it as a uncompressed point
        let result_bytes = result.to_encoded_point(false);
        let result_bytes = result_bytes.as_bytes();

        // Skip the first byte which is the compression flag
        AffinePoint::new(
            BigUint::from_bytes_be(&result_bytes[1..33]),
            BigUint::from_bytes_be(&result_bytes[33..65]),
        )
    }
}

fn from_projective(point: K256ProjectivePoint) -> Point {
    let encoded = point.to_affine().to_encoded_point(false);
    Point::new(
        BigUint::from_bytes_be(encoded.x().unwrap()),
        BigUint::from_bytes_be(encoded.y().unwrap()),
    )
}

fn sample_points() -> Vec<Point> {
    let mut rng = StdRng::seed_from_u64(0x5ec_256);
    (0..256)
        .map(|_| from_projective(K256ProjectivePoint::GENERATOR * Scalar::random(&mut rng)))
        .collect()
}

#[test]
fn secp256k1_matches_projective_reference() {
    let points = sample_points();
    for (i, p) in points.iter().enumerate() {
        let q = &points[(i + 1) % points.len()];
        assert_eq!(p.sw_add_k256(q), p.reference_add(q));
        assert_eq!(p.sw_double_k256(), p.reference_double());
        assert_eq!(p.sw_add_k256(p), p.reference_add(p));
        let neg = <SwCurve<Secp256k1Parameters> as EllipticCurve>::ec_neg(p);
        assert_eq!(neg.sw_double_k256(), neg.reference_double());
        let sum = p.sw_add_k256(q);
        assert_eq!(sum.sw_add_k256(&neg), *q);
        for coord in [&sum.x, &sum.y] {
            assert!(
                coord < &<Secp256k1Parameters as EllipticCurveParameters>::BaseField::modulus()
            );
        }
    }

    let mut actual = SwCurve::<Secp256k1Parameters>::generator();
    let mut expected = actual.clone();
    for q in &points {
        actual = actual.sw_double_k256().sw_double_k256().sw_add_k256(q);
        expected = expected.reference_double().reference_double().reference_add(q);
        assert_eq!(actual, expected);
    }
}

#[test]
fn secp256k1_inverse_matches_reference() {
    for value in [FieldElement::ONE, -FieldElement::ONE, FieldElement::from_u64(2)]
        .into_iter()
        .chain(sample_points().iter().map(|p| p.k256_coordinates().0))
    {
        assert_eq!(secp256k1_inverse(value).to_bytes(), value.invert().unwrap().to_bytes());
    }
    assert!(std::panic::catch_unwind(|| secp256k1_inverse(FieldElement::ZERO)).is_err());
}

#[test]
fn secp256k1_inverse_accepts_non_normalized_inputs() {
    let mut rng = StdRng::seed_from_u64(0x5ec_256_1);
    let random_values = std::iter::repeat_with(|| FieldElement::random(&mut rng))
        .filter(|value| !bool::from(value.is_zero()))
        .take(1024);

    // Include a boundary case: doubling p - 1 produces 2p - 2, representing p - 2.
    let p_minus_one = (-FieldElement::ONE).normalize();
    for value in std::iter::once(p_minus_one).chain(random_values) {
        // Point doubling uses this same unreduced operation for its denominator, 2y.
        let unreduced = value.double();
        let reduced = unreduced.normalize();
        assert_eq!(
            secp256k1_inverse(unreduced).to_bytes(),
            reduced.invert().unwrap().to_bytes(),
            "inverse mismatch for doubled input {:?}",
            value.to_bytes(),
        );
    }
}

#[test]
fn secp256k1_preserves_rejections() {
    let generator = SwCurve::<Secp256k1Parameters>::generator();
    let modulus = <Secp256k1Parameters as EllipticCurveParameters>::BaseField::modulus();
    let invalid = [
        Point::new(BigUint::zero(), BigUint::zero()),
        Point::new(generator.x.clone(), BigUint::zero()),
        Point::new(modulus.clone(), generator.y.clone()),
        Point::new(generator.x.clone(), modulus.clone()),
        Point::new(&modulus + &generator.x, generator.y.clone()),
        Point::new(generator.x.clone(), &modulus + &generator.y),
        Point::new(BigUint::from(1u32) << 256, generator.y.clone()),
    ];
    for p in &invalid {
        assert!(std::panic::catch_unwind(|| p.reference_double()).is_err());
        assert!(std::panic::catch_unwind(|| p.sw_double_k256()).is_err());
        assert!(std::panic::catch_unwind(|| p.reference_add(&generator)).is_err());
        assert!(std::panic::catch_unwind(|| p.sw_add_k256(&generator)).is_err());
        assert!(std::panic::catch_unwind(|| generator.reference_add(p)).is_err());
        assert!(std::panic::catch_unwind(|| generator.sw_add_k256(p)).is_err());
        assert!(std::panic::catch_unwind(|| p.sw_add_k256(p)).is_err());
    }
    let neg = <SwCurve<Secp256k1Parameters> as EllipticCurve>::ec_neg(&generator);
    assert!(std::panic::catch_unwind(|| generator.reference_add(&neg)).is_err());
    assert!(std::panic::catch_unwind(|| generator.sw_add_k256(&neg)).is_err());
}

/// Run with cargo test -p sp1-curves --release benchmark_secp256k1 -- --ignored --nocapture
/// Both paths include the original BigUint/SEC1 conversions and input validation.
#[test]
#[ignore = "manual release-mode before/after performance comparison"]
fn benchmark_secp256k1() {
    assert!(!cfg!(debug_assertions), "run this benchmark with --release");
    let points = sample_points();
    let iterations = 20_000;
    let measure = |operation: fn(&Point, &Point) -> Point| {
        let start = Instant::now();
        for i in 0..iterations {
            black_box(operation(
                black_box(&points[i % points.len()]),
                black_box(&points[(i + 1) % points.len()]),
            ));
        }
        start.elapsed().as_secs_f64() * 1e9 / iterations as f64
    };
    let operations: [(&str, fn(&Point, &Point) -> Point, fn(&Point, &Point) -> Point); 2] = [
        ("add", Point::reference_add, Point::sw_add_k256),
        ("double", |p, _| p.reference_double(), |p, _| p.sw_double_k256()),
    ];
    for (name, before, after) in operations {
        measure(before);
        measure(after);
        let mut old = Vec::new();
        let mut new = Vec::new();
        for trial in 0..7 {
            if trial % 2 == 0 {
                old.push(measure(before));
                new.push(measure(after));
            } else {
                new.push(measure(after));
                old.push(measure(before));
            }
        }
        old.sort_by(f64::total_cmp);
        new.sort_by(f64::total_cmp);
        eprintln!("{name}: before={:.0} ns after={:.0} ns speedup={:.2}x (median of 7 x {iterations}; before range {:.0}..{:.0}, after {:.0}..{:.0})",
            old[3], new[3], old[3]/new[3], old[0], old[6], new[0], new[6]);
    }
}
