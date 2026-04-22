//! Eager native interpreter.
//!
//! Walks a [`Program`] and evaluates every constraint directly against
//! concrete field values from a caller-supplied transcript and challenger.
//! Does **not** support PCS oracles (`ReadOracle` / `AssertMleMultiEval`
//! statements cause [`InterpError::OracleNotSupported`]). Use the future
//! ZK lowering for PCS-backed verifiers.

use std::collections::HashMap;
use std::hash::Hash;

use slop_algebra::{ExtensionField, Field};
use slop_challenger::FieldChallenger;
use thiserror::Error;

use crate::walk::walk_expr_dag;
use crate::{ExprId, ExprKind, Program, Stmt, VarId};

#[derive(Debug, Error)]
pub enum InterpError {
    #[error("transcript exhausted: needed {needed} more scalars")]
    TranscriptExhausted { needed: usize },
    #[error("AssertZero failed at stmt #{stmt_idx}")]
    AssertZeroFailed { stmt_idx: usize },
    #[error("AssertProduct failed at stmt #{stmt_idx}: a·b ≠ c")]
    AssertProductFailed { stmt_idx: usize },
    #[error("oracle statements not supported in the native interpreter (stmt #{stmt_idx})")]
    OracleNotSupported { stmt_idx: usize },
    #[error("use of undefined VarId {0:?}")]
    UndefinedVar(VarId),
}

/// Interpreter environment: proof transcript + challenger + scratch for
/// resolved variable bindings.
pub struct Env<'a, F: Field, E: ExtensionField<F>, Ch: FieldChallenger<F>> {
    /// Proof transcript as a flat slice of extension-field scalars, consumed
    /// sequentially by `ReadTranscript` statements.
    transcript: &'a [E],
    transcript_cursor: usize,
    challenger: &'a mut Ch,
    vars: HashMap<VarId, E>,
    _marker: std::marker::PhantomData<F>,
}

impl<'a, F: Field, E: ExtensionField<F>, Ch: FieldChallenger<F>> Env<'a, F, E, Ch> {
    pub fn new(transcript: &'a [E], challenger: &'a mut Ch) -> Self {
        Self {
            transcript,
            transcript_cursor: 0,
            challenger,
            vars: HashMap::new(),
            _marker: std::marker::PhantomData,
        }
    }

    fn read_next(&mut self, count: usize) -> Result<&[E], InterpError> {
        let start = self.transcript_cursor;
        let end = start + count;
        if end > self.transcript.len() {
            return Err(InterpError::TranscriptExhausted { needed: end - self.transcript.len() });
        }
        self.transcript_cursor = end;
        Ok(&self.transcript[start..end])
    }
}

/// Run a program against the given env. Returns `Ok(())` iff every
/// `AssertZero` and `AssertProduct` statement holds.
pub fn run_native<F, E, Ch>(
    program: &Program<E>,
    env: &mut Env<'_, F, E, Ch>,
) -> Result<(), InterpError>
where
    F: Field,
    E: ExtensionField<F> + Hash + Eq,
    Ch: FieldChallenger<F>,
{
    for (stmt_idx, stmt) in program.stmts.iter().enumerate() {
        match stmt {
            Stmt::ReadTranscript { start, count } => {
                let count = *count as usize;
                let values: Vec<E> = env.read_next(count)?.to_vec();
                for (offset, value) in values.into_iter().enumerate() {
                    // Observe each scalar so the challenger mirrors the
                    // Fiat-Shamir state of the real verifier.
                    env.challenger.observe_ext_element(value);
                    env.vars.insert(VarId(start.0 + offset as u32), value);
                }
            }
            Stmt::Sample { dst } => {
                let value: E = env.challenger.sample_ext_element();
                env.vars.insert(*dst, value);
            }
            Stmt::ReadOracle { .. } | Stmt::AssertMleMultiEval { .. } => {
                return Err(InterpError::OracleNotSupported { stmt_idx });
            }
            Stmt::AssertZero(expr_id) => {
                let value = eval_expr(*expr_id, program, env)?;
                if !is_zero(&value) {
                    return Err(InterpError::AssertZeroFailed { stmt_idx });
                }
            }
            Stmt::AssertProduct(a, b, c) => {
                let av = eval_expr(*a, program, env)?;
                let bv = eval_expr(*b, program, env)?;
                let cv = eval_expr(*c, program, env)?;
                if av * bv != cv {
                    return Err(InterpError::AssertProductFailed { stmt_idx });
                }
            }
        }
    }
    Ok(())
}

fn eval_expr<F, E, Ch>(
    root: ExprId,
    program: &Program<E>,
    env: &Env<'_, F, E, Ch>,
) -> Result<E, InterpError>
where
    F: Field,
    E: ExtensionField<F> + Hash + Eq,
    Ch: FieldChallenger<F>,
{
    let mut cache: HashMap<ExprId, E> = HashMap::new();
    walk_expr_dag(&program.exprs, root, &mut cache, |kind, cache| {
        Ok::<E, InterpError>(match kind {
            ExprKind::ConstExt(v) => *v,
            ExprKind::Var(var) | ExprKind::Challenge(var) => {
                *env.vars.get(var).ok_or(InterpError::UndefinedVar(*var))?
            }
            ExprKind::Add(a, b) => *cache.get(a).unwrap() + *cache.get(b).unwrap(),
            ExprKind::Sub(a, b) => *cache.get(a).unwrap() - *cache.get(b).unwrap(),
            ExprKind::Mul(a, b) => *cache.get(a).unwrap() * *cache.get(b).unwrap(),
            ExprKind::Neg(a) => -*cache.get(a).unwrap(),
        })
    })
}

fn is_zero<E>(v: &E) -> bool
where
    E: slop_algebra::AbstractField + PartialEq,
{
    *v == E::zero()
}
