# Verifier IR — Denotational Semantics

This document specifies the meaning of every node in the typed IR defined by
[`crates/veil-ir/src/ir.rs`](../src/ir.rs). Every backend — the native
interpreter, the (forthcoming) ZK lowering, and future Lean pretty-printer —
must honor these semantics.

## Notation

- `F` is the base field; `E ⊇ F` is the extension field.
- An **environment** `env` is a tuple `(T, Θ, C)` where:
  - `T: [E]` is the proof transcript, consumed sequentially.
  - `Θ` is a Fiat-Shamir challenger.
  - `C: {O → E}` maps oracle ids to evaluation oracles (out of scope for PR1).
- A **variable store** `ρ: {VarId → E}` records values bound by transcript
  reads and challenge samples.
- `⟦e⟧_ρ ∈ E` is the denotation of expression `e` under store `ρ`.

## Expression semantics

```
⟦ConstExt(v)⟧_ρ   = v
⟦Var(x)⟧_ρ        = ρ(x)           (undefined iff x ∉ dom(ρ))
⟦Challenge(x)⟧_ρ  = ρ(x)           (undefined iff x ∉ dom(ρ))
⟦Add(a, b)⟧_ρ     = ⟦a⟧_ρ + ⟦b⟧_ρ
⟦Sub(a, b)⟧_ρ     = ⟦a⟧_ρ - ⟦b⟧_ρ
⟦Mul(a, b)⟧_ρ     = ⟦a⟧_ρ · ⟦b⟧_ρ
⟦Neg(a)⟧_ρ        = -⟦a⟧_ρ
```

The arena is a DAG (shared sub-expressions refer to a common `ExprId`). The
denotation is a pure function of the arena contents; a backend is free to
memoize and share evaluations across statements but must not skip evaluating
asserted expressions.

## Type tags

Every [`Expr`](../src/ir.rs) carries an [`ExprType`](../src/ir.rs):

- **`Ext`** — an extension-field-valued expression. All asserted expressions
  (`AssertZero`, `AssertProduct` operands, `AssertMleMultiEval` eval values)
  must be `Ext`-tagged.
- **`Challenge`** — a Fiat-Shamir challenge bound via `Sample`. Challenges
  are `E`-valued semantically; the tag exists only for validation and for
  backends (e.g. Lean) that want to distinguish challenge-derived subterms.
  A `Challenge`-tagged node may appear wherever an `Ext`-tagged node is
  expected, reflecting `Challenge: Algebra<Extension>` in the trait.

Validation ([`validate::validate`](../src/validate.rs)) is responsible for
checking tag consistency; it rejects malformed arenas produced by buggy
transforms.

## Statement semantics

```
⟦ReadTranscript { start, count }⟧(env, ρ)
    requires len(env.T) - env.cursor ≥ count
    effect: for i ∈ 0..count,
              ρ[start + i] := T[env.cursor + i]
              env.Θ.observe(T[env.cursor + i])
              env.cursor += 1

⟦Sample { dst }⟧(env, ρ)
    effect: ρ[dst] := env.Θ.sample()

⟦ReadOracle { dst, num_encoding_variables, log_num_polynomials }⟧(env, ρ)
    effect: dst is bound to the next PCS commitment in env.T,
            and env.Θ observes its digest.
    status: PR1 native interpreter returns OracleNotSupported;
            ZK lowering (PR2) reads from the ZkProof transcript.

⟦AssertZero(e)⟧(env, ρ)
    requires ⟦e⟧_ρ = 0 in E;
    a backend that cannot decide equality (e.g. the constraint-building ZK
    backend) must instead emit the corresponding constraint into its
    constraint system.

⟦AssertProduct(a, b, c)⟧(env, ρ)
    requires ⟦a⟧_ρ · ⟦b⟧_ρ = ⟦c⟧_ρ in E.
    Equivalent semantically to AssertZero(a*b - c) but avoids materializing
    the product for backends that constrain multiplication directly.

⟦AssertMleMultiEval { claims, point }⟧(env, ρ)
    requires: for each (oracle, eval) in claims,
              committed_mle(env.C[oracle])(⟦point⟧_ρ) = ⟦eval⟧_ρ.
    status: same as ReadOracle — deferred to the ZK lowering.
```

## Program semantics

`⟦Program { stmts, exprs, num_vars, num_oracles }⟧(env)` executes `stmts` in
order over a store `ρ` that starts empty and grows as variables are bound.
The program **accepts** iff every assert succeeds. If any assert fails, the
program **rejects** at that statement index.

Execution is strictly sequential: Fiat-Shamir state depends on the order of
`observe`/`sample` calls. A backend that reorders statements must prove the
reordering is semantically equivalent (Lean proofs of backend correctness
will discharge this obligation).

## Backend correctness

A backend lowering `L` (e.g. `L = zk_lower_verifier`) is correct iff, for
every program `P` and environment `env`, the satisfying assignments of
`L(P)` are in bijection with the inputs on which `⟦P⟧(env)` accepts. For
the native interpreter this collapses to literal equality: `run_native(P,
env) = Ok(())` iff `⟦P⟧(env)` accepts.

## Change policy

Any addition to `ExprKind` or `Stmt` must ship with an entry in this
document in the same PR. If the new node cannot be given semantics without
referencing a specific backend, it is a sign that the node belongs inside
a backend pass, not in the IR.
