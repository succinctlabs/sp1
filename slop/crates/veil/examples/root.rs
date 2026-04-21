//! Example: ZK proof of knowledge of a polynomial root.
//!
//! Proves that the prover knows a root of a public polynomial p(x) without revealing
//! it. No PCS is needed — this is a pure constraint-based proof.
//!
//! The example follows the standard two-function verifier shape:
//!
//! - `root_read`: reads the sent root expression into a `RootView`.
//! - `root_build_constraints`: evaluates the public polynomial at the sent root
//!   via Horner and asserts zero. Captures the public polynomial coefficients
//!   via closure where needed.

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

struct RootView<C: ConstraintCtx> {
    root: C::Expr,
}

fn root_read<C: ReadingCtx>(ctx: &mut C) -> RootView<C> {
    let root = ctx.read_one().unwrap();
    RootView { root }
}

fn root_build_constraints<C: ConstraintCtx>(
    coeffs: &[C::Extension],
    view: RootView<C>,
    ctx: &mut C,
) {
    let eval = horner_eval::<C>(coeffs, view.root);
    ctx.assert_zero(eval);
}

/// Horner's method: evaluate a polynomial with public extension-field coefficients
/// at an `Expr`-valued point. Relies on `Expr: Algebra<Extension>`.
fn horner_eval<C: ConstraintCtx>(coeffs: &[C::Extension], point: C::Expr) -> C::Expr {
    let mut iter = coeffs.iter().rev();
    let first = *iter.next().expect("polynomial must be non-empty");
    let init = C::Expr::one() * first;
    iter.fold(init, |acc, &c| acc * point.clone() + c)
}

/// Construct a polynomial with a known root: p(x) = (x - root) * q(x).
fn make_polynomial_with_root(root: EF, degree: usize) -> Vec<EF> {
    let q = UnivariatePolynomial::new(vec![EF::one(); degree]);
    let linear = UnivariatePolynomial::new(vec![-root, EF::one()]);
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

    let secret_root = EF::from_canonical_u32(42);
    let poly_coeffs = make_polynomial_with_root(secret_root, 5);

    // Sanity check: p(root) = 0
    let poly = UnivariatePolynomial::new(poly_coeffs.clone());
    assert_eq!(poly.eval_at_point(secret_root), EF::zero(), "polynomial should vanish at root");
    eprintln!("Public polynomial degree: {}", poly_coeffs.len() - 1);

    let mask_length = compute_mask_length::<GC, _>(root_read, |view, ctx| {
        root_build_constraints(&poly_coeffs, view, ctx)
    });
    eprintln!("Mask length: {mask_length}");

    // === PROVER ===
    eprintln!("\n=== PROVER ===");
    let proof = {
        let now = std::time::Instant::now();
        let mut ctx: ZkProverCtx<GC, NoPcsConfig<MK>> =
            ZkProverCtx::initialize_without_pcs(mask_length, &mut rng);

        let root = ctx.send_value(secret_root);
        root_build_constraints(&poly_coeffs, RootView { root }, &mut ctx);

        let proof = ctx.prove(&mut rng);
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };

    // === VERIFIER ===
    eprintln!("\n=== VERIFIER ===");
    {
        let mut ctx = ZkVerifierCtx::init(proof, None);
        let view = root_read(&mut ctx);
        root_build_constraints(&poly_coeffs, view, &mut ctx);
        ctx.verify().expect("verification failed");
    }

    eprintln!("\n=== PASSED ===");
}
