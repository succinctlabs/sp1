//! End-to-end test: a toy verifier goes through `IrBuilder` → `Program`
//! and is executed via `run_native`. Honest proofs accept; tampered proofs
//! reject. Covers `read_exact`, `sample`, `assert_zero`, and the arithmetic
//! path through `Mul` and `Sub`.

// Tests inside the slop tree may name concrete field types directly
// (matching the pattern in `slop-veil`'s own test files). The `SP1Field`
// alias lives in the SP1 crate tree, which slop crates must not depend on.
#![allow(clippy::disallowed_types)]

use slop_algebra::{extension::BinomialExtensionField, AbstractField};
use slop_challenger::{FieldChallenger, IopCtx};
use slop_koala_bear::{KoalaBear, KoalaBearDegree4Duplex};
use slop_veil::compiler::{ReadingCtx, TranscriptExhaustedError};
use slop_veil_ir::{
    builder::IrBuilder,
    interp::{run_native, Env, InterpError},
    validate::validate,
    Stmt,
};

type F = KoalaBear;
type E = BinomialExtensionField<KoalaBear, 4>;
type Challenger = <KoalaBearDegree4Duplex as IopCtx>::Challenger;

/// Toy verifier: read `a`, sample `alpha`, read `b`, assert `a·alpha = b`.
///
/// The honest prover observes `a`, samples `alpha` from the mirrored
/// challenger, then sends `b = a·alpha`. Any transcript with a different
/// `b` fails `assert_zero(a·alpha - b)`.
fn toy_verify<C: ReadingCtx>(ctx: &mut C) -> Result<(), TranscriptExhaustedError> {
    let a = ctx.read_one()?;
    let alpha = ctx.sample();
    let b = ctx.read_one()?;
    ctx.assert_zero(a * alpha - b);
    Ok(())
}

fn fresh_challenger() -> Challenger {
    KoalaBearDegree4Duplex::default_challenger()
}

/// Mirror the verifier's observation order to produce an honest proof.
fn honest_proof(a: E) -> Vec<E> {
    let mut ch = fresh_challenger();
    ch.observe_ext_element(a);
    let alpha: E = ch.sample_ext_element();
    let b = a * alpha;
    vec![a, b]
}

#[test]
fn toy_honest_accepts() {
    let mut builder = IrBuilder::<F, E>::new();
    toy_verify(&mut builder).unwrap();
    let program = builder.finish();

    validate(&program).expect("produced program validates");

    let a = E::from_canonical_u32(7);
    let transcript = honest_proof(a);

    let mut ch = fresh_challenger();
    let mut env = Env::new(&transcript, &mut ch);
    run_native(&program, &mut env).expect("honest proof accepts");
}

#[test]
fn toy_tampered_rejects() {
    let mut builder = IrBuilder::<F, E>::new();
    toy_verify(&mut builder).unwrap();
    let program = builder.finish();

    let a = E::from_canonical_u32(7);
    let mut transcript = honest_proof(a);
    // Flip one byte of `b` so the relation no longer holds.
    transcript[1] += E::one();

    let mut ch = fresh_challenger();
    let mut env = Env::new(&transcript, &mut ch);
    match run_native(&program, &mut env) {
        Err(InterpError::AssertZeroFailed { .. }) => {}
        other => panic!("expected AssertZeroFailed, got {other:?}"),
    }
}

#[test]
fn program_snapshot_matches_expected_shape() {
    let mut builder = IrBuilder::<F, E>::new();
    toy_verify(&mut builder).unwrap();
    let program = builder.finish();

    let shape: Vec<&'static str> = program
        .stmts
        .iter()
        .map(|s| match s {
            Stmt::ReadTranscript { .. } => "ReadTranscript",
            Stmt::Sample { .. } => "Sample",
            Stmt::ReadOracle { .. } => "ReadOracle",
            Stmt::AssertZero(_) => "AssertZero",
            Stmt::AssertProduct(..) => "AssertProduct",
            Stmt::AssertMleMultiEval { .. } => "AssertMleMultiEval",
        })
        .collect();
    assert_eq!(
        shape,
        vec!["ReadTranscript", "Sample", "ReadTranscript", "AssertZero"],
        "unexpected statement shape: {shape:?}"
    );
    // 2 transcript reads + 1 challenge sample = 3 var bindings.
    assert_eq!(program.num_vars, 3);
    assert_eq!(program.num_oracles, 0);
}
