//! Example: ZK proof of knowledge of a polynomial root.
//!
//! Proves that the prover knows a root of a public polynomial p(x) without revealing
//! the root. No PCS needed — this is a pure constraint-based proof.
//!
//! Protocol:
//! 1. Prover sends (masked) root value r
//! 2. Both sides constrain: p(r) = 0

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_algebra::{AbstractField, UnivariatePolynomial};
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::zk::{compute_mask_length, NoPcsConfig, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;
type EF = <GC as IopCtx>::EF;

/// Horner's method: evaluate polynomial with public coefficients at an expression point.
///
/// Since Expr: Algebra<Extension>, we have Expr * Extension and Expr + Extension.
/// We bootstrap from `Expr::one() * leading_coeff` to get an Expr, then fold.
fn horner_eval<C: ConstraintCtx>(coeffs: &[C::Extension], point: C::Expr) -> C::Expr {
    let mut iter = coeffs.iter().rev();
    let first = *iter.next().expect("polynomial must be non-empty");
    let init = C::Expr::one() * first;
    iter.fold(init, |acc, &c| acc * point.clone() + c)
}

/// Build the polynomial evaluation constraint: assert p(root) = 0.
fn build_poly_constraint<C: ConstraintCtx>(coeffs: &[C::Extension], root: C::Expr, ctx: &mut C) {
    let eval = horner_eval::<C>(coeffs, root);
    ctx.assert_zero(eval);
}

/// Construct a polynomial with a known root: p(x) = (x - root) * q(x).
fn make_polynomial_with_root(root: EF, degree: usize) -> Vec<EF> {
    // q(x) = 1 + x + x^2 + ... + x^{degree-1}
    let q = UnivariatePolynomial::new(vec![EF::one(); degree]);

    // (x - root) as a polynomial
    let linear = UnivariatePolynomial::new(vec![-root, EF::one()]);

    // Multiply: p(x) = (x - root) * q(x) via schoolbook multiplication
    let mut result = vec![EF::zero(); degree + 1];
    for (i, &qi) in q.coefficients.iter().enumerate() {
        for (j, &lj) in linear.coefficients.iter().enumerate() {
            result[i + j] += qi * lj;
        }
    }
    result
}

fn main() {
    let mut rng = ChaCha20Rng::from_entropy();

    // Choose a secret root and build a public polynomial with that root
    let secret_root = EF::from_canonical_u32(42);
    let poly_coeffs = make_polynomial_with_root(secret_root, 5);

    // Sanity check: p(root) = 0
    let poly = UnivariatePolynomial::new(poly_coeffs.clone());
    assert_eq!(poly.eval_at_point(secret_root), EF::zero(), "polynomial should vanish at root");
    eprintln!("Public polynomial degree: {}", poly_coeffs.len() - 1);

    // Compute mask length: read phase returns the root expr, build phase constrains it
    let coeffs_ref = poly_coeffs.clone();
    let mask_length = compute_mask_length::<GC, _>(
        |ctx| ctx.read_one().unwrap(),
        |root, ctx| build_poly_constraint(&coeffs_ref, root, ctx),
    );
    eprintln!("Mask length: {}", mask_length);

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        let now = std::time::Instant::now();
        let mut ctx: ZkProverCtx<GC, NoPcsConfig<MK>> =
            ZkProverCtx::initialize_without_pcs(mask_length, &mut rng);

        // Send the secret root
        let root_expr = ctx.send_value(secret_root);

        // Build constraint: p(root) = 0
        build_poly_constraint(&poly_coeffs, root_expr, &mut ctx);

        let proof = ctx.prove(&mut rng);
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let mut ctx = ZkVerifierCtx::init(proof, None);
        // Read the root from transcript
        let root = ctx.read_one().expect("failed to read root");
        // Constrain: p(root) = 0
        build_poly_constraint(&poly_coeffs, root, &mut ctx);
        ctx.verify().expect("verification failed");
    }

    eprintln!("\n=== PASSED ===");
}
