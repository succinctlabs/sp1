//! Example: proof of knowledge of a polynomial root, run against two backends.
//!
//! Proves that the prover knows a root of a public polynomial p(x) without revealing
//! it. No PCS is needed — this is a pure constraint-based proof.
//!
//! Two functions encode the protocol:
//!
//! - `root_prove`: prover-only — send the secret root through the transcript.
//! - `root_verify`: reads the root and asserts `p(root) == 0` in one
//!   `ReadingCtx`-generic pass. Runs on the verifier and (via the prover's
//!   replay `ReadingCtx`) on the prover.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use slop_algebra::{AbstractField, UnivariatePolynomial};
use slop_challenger::IopCtx;
use slop_koala_bear::KoalaBearDegree4Duplex;
use slop_merkle_tree::Poseidon2KoalaBear16Prover;
use slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx};
use slop_veil::protocols::ProtocolError;
use slop_veil::transparent::{BasefoldTransparentProverCtx, BasefoldTransparentVerifierCtx};
use slop_veil::zk::{compute_mask_length, NoPcsConfig, ZkProverCtx, ZkVerifierCtx};

type GC = KoalaBearDegree4Duplex;
type MK = Poseidon2KoalaBear16Prover;
type EF = <GC as IopCtx>::EF;

// ============================================================================
// Generic protocol code
// ============================================================================

/// Prover-only entry point: send the secret root through the transcript.
fn root_prove<C: SendingCtx>(ctx: &mut C, secret_root: C::Extension) {
    ctx.send_value(secret_root);
}

/// Unified read+constrain pass: read the root and assert `p(root) == 0`.
fn root_verify<C: ReadingCtx>(
    coeffs: &[C::Extension],
    ctx: &mut C,
) -> Result<(), ProtocolError<C::AssertError>> {
    let root = ctx.read_one()?;
    let eval = horner_eval::<C>(coeffs, root);
    ctx.assert_zero(eval).map_err(ProtocolError::Assert)
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
    // No MLE commitments in this protocol, so the encoding width is irrelevant.
    let mask_length = compute_mask_length::<GC, _>(0, |ctx| root_verify(&poly_coeffs, ctx));
    eprintln!("Mask length: {mask_length}");

    let zk_proof = {
        let now = std::time::Instant::now();
        let mut pctx: ZkProverCtx<GC, NoPcsConfig<MK>> =
            ZkProverCtx::initialize_without_pcs(mask_length, &mut rng).expect("zk init failed");
        root_prove(&mut pctx, secret_root);
        root_verify(&poly_coeffs, &mut pctx).expect("zk assert failed");
        let proof = pctx.prove(&mut rng).expect("zk prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = ZkVerifierCtx::init_without_pcs(zk_proof);
        root_verify(&poly_coeffs, &mut vctx).expect("zk assert failed");
        vctx.verify().expect("zk verification failed");
    }
    eprintln!("ZK backend: PASSED");

    // Transparent backend.
    eprintln!("\n=== TRANSPARENT BACKEND ===");
    let transparent_proof = {
        let now = std::time::Instant::now();
        let mut pctx: BasefoldTransparentProverCtx<GC, MK> =
            BasefoldTransparentProverCtx::initialize_without_pcs();
        root_prove(&mut pctx, secret_root);
        root_verify(&poly_coeffs, &mut pctx).expect("transparent assert failed");
        let proof = pctx.prove(&mut rng).expect("transparent prove failed");
        eprintln!("Prover time: {:?}", now.elapsed());
        proof
    };
    {
        let mut vctx = BasefoldTransparentVerifierCtx::<GC>::new(transparent_proof, None);
        root_verify(&poly_coeffs, &mut vctx).expect("transparent assert failed");
        vctx.verify().expect("transparent verification failed");
    }
    eprintln!("Transparent backend: PASSED");

    eprintln!("\n=== ALL PASSED ===");
}
