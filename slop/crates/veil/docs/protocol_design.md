# Protocol API design sketch

Working document for the refactor of `slop-veil` protocols and examples toward
a uniform shape. The goal is an abstract-protocol-defining API that several
different `ConstraintCtx` backends (default, veil-zk, recursion, lean-codegen)
can execute without the protocol code knowing which backend it is running on.

## Mental model: every protocol is a reduction of relations

All three reference formalisms (the MIOP paper, the zkifyer-formal-verification
Lean repo, and ArkLib) agree on one core noun: **a protocol reduces one
claim-over-a-relation to another**. The protocol's contract is:

> If the transcript's round messages pass the polynomial-identity checks that
> `build_constraints` emits, *and* the output claim is valid with respect to its
> own relation, *then* the input claim is valid with respect to its relation
> (up to some soundness error).

Some protocols are *terminal*: their "output claim" is degenerate because their
`build_constraints` discharges directly using the primitive `ConstraintCtx`
operations (`assert_zero`, `assert_mle_eval`). Others are *reducing*: they
hand the output claim back to the caller to route into a downstream protocol.

In this framework sumcheck stops looking weird — it is just an especially
explicit reducing protocol. `mle_eval` and `root` are the degenerate-terminal
cases of the same shape.

## The three primitive discharge operations

`ConstraintCtx` exposes (at least) three primitive verifier checks. These are
the "base cases" of composition — any output claim ultimately discharges down
to one of them.

- `ctx.assert_zero(expr)` — polynomial identity check on transcript values
- `ctx.assert_mle_eval(oracle, point, eval)` — MLE oracle opening at a point
- `ctx.assert_mle_multi_eval(pairs, point)` — batched form

These correspond exactly to the two verifier primitives in the MIOP paper
(polynomial-identity-over-transcript and multilinear-oracle-opening).

## The three types + three methods per protocol

For each protocol we have:

- **`FooParam`** — static shape (counts, degrees, oracle geometry). Contains no
  field values and no context-dependent data.
- **`FooInputClaim<C: ConstraintCtx>`** — data known to both parties *before*
  the protocol starts. **Never transmitted on the transcript.** It is supplied
  as an argument to `prove`, `read`, and `build_constraints`.
- **`FooView<C: ConstraintCtx>`** — returned by `prove` / `read`. Publicly
  exposes a `FooOutputClaim<C>` (the reduced claim handed to the downstream
  consumer) and holds protocol-local transcript fragments (round messages,
  intermediate challenges) as `pub(crate)` fields used only by
  `build_constraints`.

The three methods:

```rust
impl FooParam {
    pub fn prove<C: SendingCtx>(
        &self,
        in_claim: FooInputClaim<C>,
        witness: FooWitness,     // prover-only polynomial data
        ctx: &mut C,
    ) -> FooView<C>;

    pub fn read<C: ReadingCtx>(
        &self,
        in_claim: FooInputClaim<C>,
        ctx: &mut C,
    ) -> Result<FooView<C>, FooError>;
}

impl<C: ConstraintCtx> FooView<C> {
    pub fn build_constraints(
        self,
        in_claim: &FooInputClaim<C>,
        ctx: &mut C,
    ) -> Result<(), FooError>;
}
```

Key invariants:

1. `in_claim` flows *in* through all three methods. It is NEVER read off the
   transcript. If it is publicly known (e.g. the zerocheck constant `0`), it
   stays out of the transcript entirely. If it came from an upstream protocol's
   output claim, the caller wires it through.
2. `view.out_claim` is the caller's responsibility to discharge — either by
   feeding it as the input claim of a downstream protocol, or by directly
   invoking a primitive check.
3. `build_constraints` emits only the *internal consistency* constraints of
   this protocol (round-to-round checks, final-round-tie-to-claim). It does not
   assert the input claim against anything external; the caller already ensured
   that by virtue of what it passed in.

## 1. Sumcheck — the canonical reducing protocol

Reduces: "the hypercube sum of an `n`-variable composition polynomial `f` of
degree `d` equals `S`" → "`f` evaluates to `v` at a random point `r`
(Fiat-Shamir-sampled), with component-polynomial evaluations `e_1, ..., e_k` at
`r`."

```rust
pub struct SumcheckParam {
    pub num_variables: u32,
    pub degree: usize,
    pub num_component_evals: usize,
}

/// Input claim: the hypercube sum `S`. NOT transmitted on the transcript.
pub struct SumcheckInputClaim<C: ConstraintCtx> {
    pub claimed_sum: C::Expr,
}

/// Output claim: the reduced evaluation claim at the random point.
pub struct SumcheckOutputClaim<C: ConstraintCtx> {
    pub point: Vec<C::Challenge>,
    pub claimed_eval: C::Expr,
    pub component_evals: Vec<C::Expr>,
}

pub struct SumcheckView<C: ConstraintCtx> {
    pub out_claim: SumcheckOutputClaim<C>,
    pub(crate) univariate_poly_coeffs: Vec<Vec<C::Expr>>,
}
```

**Compat note:** `claimed_eval` continues to be physically sent on the
transcript (via `ctx.send_value` in `prove`, `ctx.read_one` in `read`) to
match other parts of the codebase. `build_constraints` continues to assert
`final_round_poly(last_alpha) == claimed_eval` to tie the transcript slot to
the derived value. In principle this field is redundant (derivable from the
final round's coefficients and the last Fiat-Shamir challenge) and could be
dropped; it's kept for external compatibility.

**`claimed_sum` is no longer on the transcript.** The current sumcheck sends
and reads it — that's being removed. Round-0 consistency now ties to
`in_claim.claimed_sum` directly.

Constraints emitted by `build_constraints`:

- Round 0: `eval_one_plus_eval_zero(univariate_poly_coeffs[0]) - in_claim.claimed_sum == 0`
- Round i ∈ [1, n): `poly_eval(univariate_poly_coeffs[i-1], point[n-i]) - eval_one_plus_eval_zero(univariate_poly_coeffs[i]) == 0`
- Final: `poly_eval(univariate_poly_coeffs[n-1], point[0]) - out_claim.claimed_eval == 0`

## 2. `mle_eval` example — terminal, primitive MLE opening

Reduces: "oracle `p` is a committed MLE" → `()` (terminal). Internally, the
protocol samples a random point `z`, reads the claimed evaluation `y`, and
discharges `assert_mle_eval(p, z, y)`.

```rust
pub struct MleEvalParam {
    pub num_encoding_variables: u32,
    pub log_num_polynomials: u32,
}

pub struct MleEvalInputClaim<C: ConstraintCtx> {
    pub oracle: C::MleOracle,
}

pub struct MleEvalOutputClaim<C: ConstraintCtx> {
    // Terminal — nothing reduced to.
    _phantom: PhantomData<C>,
}

pub struct MleEvalView<C: ConstraintCtx> {
    pub out_claim: MleEvalOutputClaim<C>,
    pub(crate) point: Vec<C::Challenge>,
    pub(crate) claimed_eval: C::Expr,
}
```

Constraints emitted by `build_constraints`:

- `ctx.assert_mle_eval(in_claim.oracle, view.point, view.claimed_eval)`

Note how the commit step (`ctx.commit_mle(p, ...)`) happens outside this
protocol — committing is a context operation, not a protocol. The resulting
oracle handle flows into `MleEvalInputClaim`.

## 3. `root` example — terminal, primitive polynomial identity

Reduces: "prover knows `x` such that `p(x) = 0` for a publicly-known polynomial
`p`" → `()` (terminal). Prover sends the root value; build_constraints
evaluates the public polynomial at that sent value via Horner and asserts zero.

```rust
pub struct RootParam {
    pub degree: usize,
}

pub struct RootInputClaim<C: ConstraintCtx> {
    pub coeffs: Vec<C::Extension>,  // public polynomial, known to both sides
}

pub struct RootOutputClaim<C: ConstraintCtx> {
    _phantom: PhantomData<C>,
}

pub struct RootView<C: ConstraintCtx> {
    pub out_claim: RootOutputClaim<C>,
    pub(crate) root: C::Expr,
}
```

Constraints emitted by `build_constraints`:

- `ctx.assert_zero(horner_eval(in_claim.coeffs, view.root))`

Note `coeffs` lives in `InputClaim`, not `Param`. Param is for *shape* (degree
count), InputClaim is for *data* (the actual coefficients). This distinction
matters once we want multiple calls of the same `RootParam` with different
polynomials, or want the Lean backend to generate a theorem parameterized
over the coefficient vector.

## 4. `zerocheck` example — composes sumcheck

This is the first real composition — zerocheck's `build_constraints` consumes
sumcheck's `out_claim`.

Reduces: "oracles `p`, `q`, `r` satisfy `p(x) * q(x) = r(x)` pointwise over
`{0,1}^n`" → `()` (terminal — discharges to MLE openings for `p`, `q`, `r`).

```rust
pub struct ZerocheckParam {
    pub num_variables: u32,
    pub log_num_polynomials: u32,
}

pub struct ZerocheckInputClaim<C: ConstraintCtx> {
    pub p: C::MleOracle,
    pub q: C::MleOracle,
    pub r: C::MleOracle,
}

pub struct ZerocheckOutputClaim<C: ConstraintCtx> {
    _phantom: PhantomData<C>,
}

pub struct ZerocheckView<C: ConstraintCtx> {
    pub out_claim: ZerocheckOutputClaim<C>,
    pub(crate) z_0: Vec<C::Challenge>,
    pub(crate) sumcheck_view: SumcheckView<C>,
}
```

Inside `prove` / `read`:

1. Sample `z_0` via `ctx.sample_point(num_variables)`.
2. Build a `SumcheckInputClaim { claimed_sum: C::Expr::zero() }` — literally
   zero, not read from the transcript.
3. Run `SumcheckParam::with_component_evals(num_variables, 3, 3)` with that
   claim and the `ZerocheckPoly` witness, getting back a `SumcheckView`.

Inside `build_constraints`:

1. Destructure `sumcheck_view.out_claim` into `point`, `claimed_eval`,
   `component_evals = [p_eval, q_eval, r_eval]`.
2. Emit `claimed_eval - eq(point, z_0) * (p_eval * q_eval - r_eval) == 0` via
   `assert_zero`.
3. Emit `assert_mle_multi_eval([(p, p_eval), (q, q_eval), (r, r_eval)], point)`.
4. Recurse into `sumcheck_view.build_constraints(&SumcheckInputClaim { claimed_sum: C::Expr::zero() }, ctx)`
   to emit the sumcheck's own round-consistency constraints.

**This fixes the current zerocheck bug** where nothing asserts that the
sumcheck's `claimed_sum` equals zero — the input-claim-as-argument design
makes it impossible to forget: the zerocheck caller must *construct* the
zero input claim, and the sumcheck's round-0 check ties its first-round
consistency to that zero.

## How composition looks in a main function

The `main` function then follows a uniform pattern across all examples:

```rust
// Prover side
let mut ctx = /* prover ctx — default, veil-zk, recursion, ... */;
let witness = /* ... */;
let in_claim = FooInputClaim { /* ... */ };
let view = foo_param.prove(in_claim.clone(), witness, &mut ctx);
view.build_constraints(&in_claim, &mut ctx)?;
let proof = ctx.prove(&mut rng);

// Verifier side
let mut ctx = /* verifier ctx matching the prover's */;
let in_claim = FooInputClaim { /* same construction — public data */ };
let view = foo_param.read(&in_claim, &mut ctx)?;
view.build_constraints(&in_claim, &mut ctx)?;
ctx.verify()?;
```

For `mask_length` counting (the veil-zk backend's pre-pass) the same
read/build-constraints pair runs under a counting context, so no duplication
of protocol logic is needed.

For a Lean-codegen backend, `read` + `build_constraints` running under a
Lean-emitting `ReadingCtx`/`ConstraintCtx` impl would emit a Lean proof
obligation — no protocol code changes.

## Branching (multiple output sub-claims) handled via struct shape

If a protocol needs to reduce one input claim to several output claims (e.g.
MIOP-to-PCS turning one MIOP verification into multiple oracle openings), its
`OutputClaim` struct just holds a `Vec` of whatever:

```rust
pub struct MiopCompileOutputClaim<C: ConstraintCtx> {
    pub openings: Vec<(C::MleOracle, Vec<C::Challenge>, C::Expr)>,
}
```

No changes to the overall framework.

## What we are intentionally NOT doing in this refactor

- **No `Protocol` trait yet.** Each protocol is a free-standing struct + impl.
  Wait until 4+ protocols visibly share the exact same signature before
  hoisting. GATs + context-parametric associated types hurt inference.
- **No explicit `Relation` runtime objects.** The relation a protocol is over
  is documented, not materialized. ZKifyer gets by with this and so can we.
- **No round-by-round knowledge-soundness typing.** Single monolithic
  soundness error is fine for now; refine if the Lean backend demands it.
- **No change to the `claimed_eval` transcript slot in sumcheck.** Kept for
  downstream compatibility even though it is derivable.
- **ZK layering remains a property of the context, not a protocol transform.**
  A context that implements the veil paper's transformations *is* what gives
  any abstract protocol its zk compilation.

## Tentative: top-level protocols vs. reusable sub-protocols

The Param / InputClaim / OutputClaim / View split above is the shape for
**reusable sub-protocol libraries** — code that lives in `src/protocols/` and
is imported by downstream users (sumcheck being the current canonical example).
Those libraries need the full split because they get composed: a caller must
be able to construct an InputClaim from arbitrary upstream data and pipe an
OutputClaim onward.

**Top-level protocols — the kind a user writes in their own binary to actually
produce and verify a proof — may not need the full split.** The emerging
pattern across `examples/` is simpler:

- A single `MyView<C>` struct that bundles *everything the verifier's
  constraint-building pass needs*: input-claim-like data (oracle handles,
  public constants), Fiat-Shamir samples, sub-protocol views.
- Two top-level functions:
  - `my_read<C: ReadingCtx>(ctx: &mut C) -> MyView<C>`
  - `my_build_constraints<C: ConstraintCtx>(view: MyView<C>, ctx: &mut C)`
- Inside these, sub-protocols are invoked through their full
  Param/InputClaim/View API — the user constructs `SumcheckInputClaim` locally
  where needed, destructures the sumcheck `out_claim` to feed downstream
  constraints, etc.

The verifier main body is then just:

```rust
let view = my_read(&mut ctx);
my_build_constraints(view, &mut ctx);
ctx.verify()?;
```

And the mask counter is literally two bare function references:

```rust
let mask_length = compute_mask_length::<GC, _>(my_read, my_build_constraints);
```

No tuple threading, no helper wrappers, no `InputClaim` boilerplate at the top
level — the single `MyView` carries all shared state between the two phases,
mirroring what a user would naturally write.

The three current examples match this shape:

- [examples/zerocheck.rs](../examples/zerocheck.rs): `ZerocheckView` bundles
  the three oracles + `z_0` + a nested `SumcheckView`. Composes sumcheck as a
  sub-protocol.
- [examples/mle_eval.rs](../examples/mle_eval.rs): `MleEvalView` bundles the
  oracle + point + claimed_eval. Terminal (discharges via `assert_mle_eval`).
- [examples/root.rs](../examples/root.rs): `RootView` carries just the sent
  root expression; public coefficients are captured by closure where
  needed.

This is tentative. Open questions: does the split between "sub-protocol
shape" and "top-level shape" hold up across more protocols? Is there a way
to unify them without forcing the InputClaim boilerplate at the top level?
Should composing protocols also follow the top-level shape, in which case
the sumcheck library API itself might want revisiting? Leaving as plan-of-
record until more protocols shake out the edges.

## Implementation conventions

1. **`InputClaim` structs derive `Clone`.** The caller typically constructs
   one, passes it by value to `prove`/`read`, and then passes it by reference
   to `build_constraints`; cloning is the simplest way to keep both live.
2. **`build_constraints` consumes `self` by value.** Signals that the View has
   been "spent" and prevents double-emission of constraints. When a View
   contains a sub-View whose `build_constraints` also needs to run, the outer
   protocol destructures the sub-View out and dispatches explicitly
   (as zerocheck does with its nested `sumcheck_view`).
3. **Per-protocol error types** (`SumcheckError`, `ZerocheckError`, ...). Each
   protocol has distinct failure modes (transcript exhaustion, empty proof,
   shape mismatch); a unified `ProtocolError` would obscure them. Protocols
   that compose wrap sub-errors via `#[from]` on `thiserror::Error`.
4. **`Param` construction: direct struct literals for simple params, `new` (or
   named constructors like `with_component_evals`) for params that need
   validation or have non-obvious defaults.** Keep fields `pub` on simple
   params so callers can build them inline.
