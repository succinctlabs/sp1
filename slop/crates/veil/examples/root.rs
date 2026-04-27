//! Example: proof of knowledge of a polynomial root, run against two backends.
//!
//! Proves that the prover knows a root of a public polynomial p(x) without revealing
//! it. No PCS is needed — this is a pure constraint-based proof.
//!
//! The protocol is written once, generically over `SendingCtx` / `ReadingCtx`, then
//! run first with the zero-knowledge backend (`ZkProverCtx` / `ZkVerifierCtx`) and
//! afterwards with the transparent backend (`TransparentProverCtx` /
//! `TransparentVerifierCtx`).
//!
//! Shape:
//!
//! - `root_read` / `root_prove`: mirror entry points — one reads the transcript on
//!   the verifier side, the other writes on the prover side. Both return a
//!   [`RootView`].
//! - `root_build_constraints`: the shared constraint-building pass used by both
//!   sides.
//!
//! `main` then runs `init → prove → build_constraints → ctx.prove()` on the prover
//! side and `init(proof) → read → build_constraints → ctx.verify()` on the verifier
//! side.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_algebra::{AbstractField, UnivariatePolynomial};
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::transparent::{TransparentProverCtx, TransparentVerifierCtx};
use slop_veil::zk::{compute_mask_length, NoPcsConfig, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;
type EF = <GC as IopCtx>::EF;

// ============================================================================
// Generic protocol code
// ============================================================================

struct RootView<C: ConstraintCtx> {
    root: C::Expr,
}

/// Verifier-side entry point: read the prover's sent root out of the transcript.
fn root_read<C: ReadingCtx>(ctx: &mut C) -> RootView<C> {
    let root = ctx.read_one().unwrap();
    RootView { root }
}

/// Prover-side entry point: send the secret root through the transcript and
/// return the matching [`RootView`] for the caller to feed into
/// [`root_build_constraints`].
fn root_prove<C: SendingCtx>(ctx: &mut C, secret_root: C::Extension) -> RootView<C> {
    let root = ctx.send_value(secret_root);
    RootView { root }
}

/// Shared constraint-building pass used by both sides.
fn root_build_constraints<C: ConstraintCtx>(
    coeffs: &[C::Extension],
    view: RootView<C>,
    ctx: &mut C,
) {
    let eval = horner_eval::<C>(coeffs, view.root);
    ctx.assert_zero(eval).unwrap();
}

/// Horner's method: evaluate a polynomial with public extension-field coefficients
/// at an `Expr`-valued point. Relies on `Expr: Algebra<Extension>`.
fn horner_eval<C: ConstraintCtx>(coeffs: &[C::Extension], point: C::Expr) -> C::Expr {
    let mut iter = coeffs.iter().rev();
    let first = *iter.next().expect("polynomial must be non-empty");
    let init = C::Expr::one() * first;
    iter.fold(init, |acc, &c| acc * point.clone() + c)
}

// ============================================================================
// Shared setup
// ============================================================================

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
    let poly_coeffs = make_polynomial_with_root(secret_root, 50);

    // Sanity check: p(root) = 0
    let poly = UnivariatePolynomial::new(poly_coeffs.clone());
    assert_eq!(poly.eval_at_point(secret_root), EF::zero(), "polynomial should vanish at root");
    eprintln!("Public polynomial degree: {}", poly_coeffs.len() - 1);

    // ZK backend.
    eprintln!("\n=== ZK BACKEND ===");
    let mask_length = compute_mask_length::<GC, _>(root_read, |view, ctx| {
        root_build_constraints(&poly_coeffs, view, ctx)
    });
    eprintln!("Mask length: {mask_length}");

    let zk_proof = {
        let now = std::time::Instant::now();
        let mut pctx: ZkProverCtx<GC, NoPcsConfig<MK>> =
            ZkProverCtx::initialize_without_pcs(mask_length, &mut rng);
        let view = root_prove(&mut pctx, secret_root);
        root_build_constraints(&poly_coeffs, view, &mut pctx);
        let proof = pctx.prove(&mut rng);
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = ZkVerifierCtx::init(zk_proof, None);
        let view = root_read(&mut vctx);
        root_build_constraints(&poly_coeffs, view, &mut vctx);
        vctx.verify().expect("zk verification failed");
    }
    eprintln!("ZK backend: PASSED");

    // Transparent backend.
    eprintln!("\n=== TRANSPARENT BACKEND ===");
    let transparent_proof = {
        let now = std::time::Instant::now();
        let mut pctx: TransparentProverCtx<GC, MK> = TransparentProverCtx::initialize_without_pcs();
        let view = root_prove(&mut pctx, secret_root);
        root_build_constraints(&poly_coeffs, view, &mut pctx);
        let proof = pctx.prove(&mut rng).expect("transparent prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = TransparentVerifierCtx::<GC>::new(transparent_proof, None);
        let view = root_read(&mut vctx);
        root_build_constraints(&poly_coeffs, view, &mut vctx);
        vctx.verify().expect("transparent verification failed");
    }
    eprintln!("Transparent backend: PASSED");

    eprintln!("\n=== ALL PASSED ===");
}
