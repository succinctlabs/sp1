//! R1CS Compiler - compiles DslIr directly to R1CS matrices.
//!
//! This is the core compiler that converts SP1's recursion IR to R1CS constraints.
//! Each opcode is carefully lowered to preserve the semantic equivalence with
//! SP1's native execution.

use p3_field::{AbstractExtensionField, AbstractField, Field, PrimeField64};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use std::any::TypeId;

use crate::ir::{Config, DslIr, Ext};
use super::types::{R1CS, SparseRow};
use super::poseidon2::Poseidon2R1CS;

/// Returns true if `id` is being watched via `R1CS_WATCH_ID`.
///
/// Supports either a single id (`felt123`) or a comma-separated list
/// (`felt1,felt2,ext9__0`).
#[inline]
fn r1cs_watch_id(id: &str) -> bool {
    static WATCH_IDS: OnceLock<Option<Vec<String>>> = OnceLock::new();
    let watch = WATCH_IDS.get_or_init(|| {
        std::env::var("R1CS_WATCH_ID").ok().map(|s| {
            s.split(',')
                .map(|t| t.trim())
                .filter(|t| !t.is_empty())
                .map(|t| t.to_string())
                .collect::<Vec<_>>()
        })
    });
    match watch.as_deref() {
        None => false,
        Some(ids) => ids.iter().any(|w| w == id),
    }
}

/// The BabyBear prime modulus
#[allow(dead_code)]
const BABYBEAR_P: u64 = 2013265921;

/// Runtime-provided inputs for witness generation.
///
/// This is intentionally trait-object based so `compile_one` can remain non-generic.
struct WitnessCtx<'a, F: PrimeField64> {
    witness: &'a mut Vec<F>,
    /// For non-hint variables, get their value from runtime memory.
    get_value: &'a mut dyn FnMut(&str) -> Option<F>,
    /// Live hint stream consumers (used when hint_felt_values is empty)
    next_hint_felt: &'a mut dyn FnMut() -> Option<F>,
    next_hint_ext: &'a mut dyn FnMut() -> Option<[F; 4]>,
    /// Pre-consumed hint values (populated in Phase 1, consumed in Phase 2).
    ///
    /// Important: hint IDs are memory locations, and the same location may be hinted
    /// multiple times throughout the program. We therefore store a FIFO queue per ID.
    hint_felt_values: HashMap<String, VecDeque<F>>,
    hint_ext_values: HashMap<String, VecDeque<[F; 4]>>,
    /// Set of IDs that are hint-sourced (should NOT use get_value for these)
    hinted_ids: HashSet<String>,
}

impl<'a, F: PrimeField64> WitnessCtx<'a, F> {
    #[inline]
    fn ensure_len(&mut self, len: usize) {
        if self.witness.len() < len {
            self.witness.resize(len, F::zero());
        }
    }

    #[inline]
    fn get(&self, idx: usize) -> F {
        self.witness[idx]
    }

    #[inline]
    fn set(&mut self, idx: usize, val: F) {
        if self.witness.len() <= idx {
            self.ensure_len(idx + 1);
        }
        self.witness[idx] = val;
    }
}

/// R1CS Compiler state
pub struct R1CSCompiler<C: Config> {
    /// The R1CS being constructed
    pub r1cs: R1CS<C::F>,
    /// Mapping from DSL variable IDs to R1CS indices
    pub var_map: HashMap<String, usize>,
    /// Whether the current `var_map[id]` has been *defined* by a write-like opcode.
    ///
    /// We allow forward references (reads before the defining op). Those create an entry with
    /// `defined=false`. The first subsequent write to the same id will *reuse* that index and
    /// flip it to `defined=true`. Any later writes allocate a fresh variable and update the map.
    pub defined: HashMap<String, bool>,
    /// Next available variable index
    pub next_var: usize,
    /// Public input indices
    pub public_inputs: Vec<usize>,
    /// Witness input indices (for witness opcodes)
    pub witness_felts: Vec<usize>,
    pub witness_exts: Vec<usize>,
    pub witness_vars: Vec<usize>,
    /// VkeyHash index (public)
    pub vkey_hash_idx: Option<usize>,
    /// CommittedValuesDigest index (public)
    pub committed_values_digest_idx: Option<usize>,
}

impl<C: Config> R1CSCompiler<C>
where
    C::F: PrimeField64,
{
    #[inline]
    fn require_var_field_is_base_field()
    where
        C::N: 'static,
        C::F: 'static,
    {
        // This backend encodes `Var<C::N>` arithmetic as constraints over `C::F`.
        // That is only sound if `C::N` and `C::F` are the same field.
        //
        // For the recursion circuit `AsmConfig`, this holds (N=F). For other Configs (e.g. OuterConfig),
        // treating Var arithmetic as BabyBear constraints would be a semantic mismatch.
        if TypeId::of::<C::N>() != TypeId::of::<C::F>() {
            panic!(
                "R1CSCompiler: encountered Var<C::N> arithmetic but C::N != C::F. \
                 This backend only supports Var ops when N==F (AsmConfig)."
            );
        }
    }

    // --- Septic extension gadgets (for CircuitV2HintAddCurve constraints) ---
    //
    // We represent a septic extension element as 7 base-field variable indices, least-significant
    // coefficient first (matching `SepticExtension([c0..c6])`).
    fn septic_add(
        &mut self,
        a: &[usize; 7],
        b: &[usize; 7],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) -> [usize; 7] {
        let mut out = [0usize; 7];
        for i in 0..7 {
            let o = self.alloc_var(ctx.as_deref_mut());
            let mut sum = SparseRow::new();
            sum.add_term(a[i], C::F::one());
            sum.add_term(b[i], C::F::one());
            self.r1cs.add_constraint(SparseRow::single(0), sum, SparseRow::single(o));
            if let Some(c) = ctx.as_deref_mut() {
                c.set(o, c.get(a[i]) + c.get(b[i]));
            }
            out[i] = o;
        }
        out
    }

    fn septic_sub(
        &mut self,
        a: &[usize; 7],
        b: &[usize; 7],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) -> [usize; 7] {
        let mut out = [0usize; 7];
        for i in 0..7 {
            let o = self.alloc_var(ctx.as_deref_mut());
            let mut diff = SparseRow::new();
            diff.add_term(a[i], C::F::one());
            diff.add_term(b[i], -C::F::one());
            self.r1cs.add_constraint(SparseRow::single(0), diff, SparseRow::single(o));
            if let Some(c) = ctx.as_deref_mut() {
                c.set(o, c.get(a[i]) - c.get(b[i]));
            }
            out[i] = o;
        }
        out
    }

    fn septic_mul(
        &mut self,
        a: &[usize; 7],
        b: &[usize; 7],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) -> [usize; 7] {
        // Compute all 49 products a[i]*b[j].
        let mut prod = [[0usize; 7]; 7];
        for i in 0..7 {
            for j in 0..7 {
                let p = self.alloc_var(ctx.as_deref_mut());
                self.add_mul(p, a[i], b[j]);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(p, c.get(a[i]) * c.get(b[j]));
                }
                prod[i][j] = p;
            }
        }

        // Reduce modulo z^7 - 2z - 5, matching `sp1_stark::septic_extension`:
        // ret[t] = sum_{i+j=t} prod[i][j]
        //        + 5 * sum_{i+j=t+7} prod[i][j]
        //        + 2 * sum_{i+j=t+6, i+j>=7} prod[i][j]
        let five = C::F::from_canonical_u64(5);
        let two = C::F::from_canonical_u64(2);
        let mut out = [0usize; 7];
        for t in 0..7 {
            let o = self.alloc_var(ctx.as_deref_mut());
            let mut lin = SparseRow::new();
            // For witness generation, compute the same linear combo over prod vars.
            let mut acc = C::F::zero();
            for i in 0..7 {
                for j in 0..7 {
                    let s = i + j;
                    let mut coeff = C::F::zero();
                    if s == t {
                        coeff += C::F::one();
                    }
                    if t <= 5 && s == t + 7 {
                        coeff += five;
                    }
                    if t >= 1 && s == t + 6 {
                        // This corresponds to i+j = 7..12.
                        coeff += two;
                    }
                    if !coeff.is_zero() {
                        lin.add_term(prod[i][j], coeff);
                        if let Some(c) = ctx.as_deref() {
                            acc += coeff * c.get(prod[i][j]);
                        }
                    }
                }
            }
            self.r1cs.add_constraint(SparseRow::single(0), lin, SparseRow::single(o));
            if let Some(c) = ctx.as_deref_mut() {
                c.set(o, acc);
            }
            out[t] = o;
        }
        out
    }

    /// Phase 0 helper: collect committed "public input" variable IDs in first-occurrence order.
    ///
    /// IMPORTANT: Our R1CS format encodes public inputs positionally: indices `1..=num_public`
    /// are public. We therefore must allocate these variables first so they occupy that prefix.
    fn phase0_collect_public_ids(ops: &[DslIr<C>], out: &mut Vec<String>, seen: &mut HashSet<String>) {
        for op in ops {
            match op {
                DslIr::CircuitCommitVkeyHash(var) => {
                    let id = var.id();
                    if seen.insert(id.clone()) {
                        out.push(id);
                    }
                }
                DslIr::CircuitCommitCommittedValuesDigest(var) => {
                    let id = var.id();
                    if seen.insert(id.clone()) {
                        out.push(id);
                    }
                }
                DslIr::CircuitV2CommitPublicValues(public_values) => {
                    // Deterministic statement binding for the SP1 recursion public values.
                    //
                    // We intentionally only export the *Poseidon2 digest* of the full public-values
                    // vector as the R1CS public input (digest-only binding).
                    //
                    // The recursion circuit itself enforces:
                    //   `public_values.digest == Poseidon2(public_values[..NUM_PV_ELMS_TO_HASH])`
                    // so exporting only `digest` preserves statement binding while keeping `l_pub`
                    // minimal (DIGEST_SIZE felts).
                    //
                    // Order matters: keep it stable across versions.
                    for felt in public_values.digest.iter() {
                        let id = felt.id();
                        if seen.insert(id.clone()) {
                            out.push(id);
                        }
                    }
                }
                DslIr::Parallel(blocks) => {
                    for b in blocks {
                        Self::phase0_collect_public_ids(&b.ops, out, seen);
                    }
                }
                DslIr::For(boxed) => {
                    let (_, _, _, _, body) = boxed.as_ref();
                    Self::phase0_collect_public_ids(body, out, seen);
                }
                DslIr::IfEq(boxed) | DslIr::IfNe(boxed) => {
                    let (_, _, then_body, else_body) = boxed.as_ref();
                    Self::phase0_collect_public_ids(then_body, out, seen);
                    Self::phase0_collect_public_ids(else_body, out, seen);
                }
                DslIr::IfEqI(boxed) | DslIr::IfNeI(boxed) => {
                    let (_, _, then_body, else_body) = boxed.as_ref();
                    Self::phase0_collect_public_ids(then_body, out, seen);
                    Self::phase0_collect_public_ids(else_body, out, seen);
                }
                _ => {}
            }
        }
    }

    /// Allocate the public-input variables first so they occupy indices `1..=num_public`.
    ///
    /// We allocate them via `read_id` (forward placeholders) and rely on `write_id` to reuse the
    /// placeholder on the first defining write.
    fn phase0_preallocate_public_inputs(
        &mut self,
        public_ids: &[String],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        if public_ids.is_empty() {
            self.r1cs.num_public = 0;
            return;
        }
        self.public_inputs.clear();
        for (j, id) in public_ids.iter().enumerate() {
            let idx = self.read_id(id, ctx.as_deref_mut());
            debug_assert_eq!(
                idx,
                j + 1,
                "public inputs must occupy prefix indices 1..=num_public"
            );
            self.public_inputs.push(idx);
        }
        self.r1cs.num_public = public_ids.len();
    }

    /// Multiply two degree-4 binomial extension elements over `C::F` with modulus `u^4 = 11`.
    #[inline]
    fn ext4_mul_vals(a: [C::F; 4], b: [C::F; 4]) -> [C::F; 4] {
        let nr = C::F::from_canonical_u64(11);
        // (a0 + a1 u + a2 u^2 + a3 u^3) * (b0 + b1 u + b2 u^2 + b3 u^3) reduced with u^4 = nr.
        let (a0, a1, a2, a3) = (a[0], a[1], a[2], a[3]);
        let (b0, b1, b2, b3) = (b[0], b[1], b[2], b[3]);
        [
            a0 * b0 + nr * (a1 * b3 + a2 * b2 + a3 * b1),
            a0 * b1 + a1 * b0 + nr * (a2 * b3 + a3 * b2),
            a0 * b2 + a1 * b1 + a2 * b0 + nr * (a3 * b3),
            a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0,
        ]
    }

    /// Invert a degree-4 binomial extension element over `C::F` with modulus `u^4 = 11`.
    ///
    /// Uses the tower representation:
    /// - Let v = u^2, so K = F[v]/(v^2 - 11) is quadratic.
    /// - Then L = K[u]/(u^2 - v) is quadratic over K.
    ///
    /// This reduces inversion in L to:
    /// 1) one inversion in K, and
    /// 2) one inversion in F.
    #[inline]
    fn ext4_inv_vals(x: [C::F; 4]) -> Option<[C::F; 4]> {
        let nr = C::F::from_canonical_u64(11);
        // K element is (x0 + x1 v) with v^2 = nr.
        let k_mul = |a0: C::F, a1: C::F, b0: C::F, b1: C::F| -> (C::F, C::F) {
            // (a0 + a1 v)(b0 + b1 v) = (a0 b0 + nr a1 b1) + (a0 b1 + a1 b0) v
            (a0 * b0 + nr * (a1 * b1), a0 * b1 + a1 * b0)
        };
        let k_inv = |a0: C::F, a1: C::F| -> Option<(C::F, C::F)> {
            // (a0 + a1 v)^{-1} = (a0 - a1 v) / (a0^2 - nr a1^2)
            let denom = a0 * a0 - nr * (a1 * a1);
            let inv = denom.try_inverse()?;
            Some((a0 * inv, (-a1) * inv))
        };
        let k_mul_by_v = |a0: C::F, a1: C::F| -> (C::F, C::F) {
            // v*(a0 + a1 v) = (nr*a1) + (a0) v
            (nr * a1, a0)
        };

        // x = A + u B, with A,B in K and u^2 = v.
        // A = a0 + a2 v, B = a1 + a3 v.
        let (a0, a1, a2, a3) = (x[0], x[1], x[2], x[3]);
        let (a0_k, a1_k) = (a0, a2);
        let (b0_k, b1_k) = (a1, a3);

        // N = A^2 - v*B^2 in K.
        let (a2_0, a2_1) = k_mul(a0_k, a1_k, a0_k, a1_k);
        let (b2_0, b2_1) = k_mul(b0_k, b1_k, b0_k, b1_k);
        let (vb2_0, vb2_1) = k_mul_by_v(b2_0, b2_1);
        let (n0, n1) = (a2_0 - vb2_0, a2_1 - vb2_1);

        // N^{-1} in K.
        let (ninv0, ninv1) = k_inv(n0, n1)?;

        // x^{-1} = (A - u B) * N^{-1}.
        let (ainv0, ainv1) = k_mul(a0_k, a1_k, ninv0, ninv1);
        let (neg_b0, neg_b1) = (-b0_k, -b1_k);
        let (binv0, binv1) = k_mul(neg_b0, neg_b1, ninv0, ninv1);

        // Recompose: (Ainv0 + Ainv1 v) + u (Binv0 + Binv1 v)
        // = Ainv0 + Binv0 u + Ainv1 u^2 + Binv1 u^3.
        Some([ainv0, binv0, ainv1, binv1])
    }

    #[inline]
    fn ext4_div_vals(lhs: [C::F; 4], rhs: [C::F; 4]) -> Option<[C::F; 4]> {
        let inv = Self::ext4_inv_vals(rhs)?;
        Some(Self::ext4_mul_vals(lhs, inv))
    }

    pub fn new() -> Self {
        let mut compiler = Self {
            r1cs: R1CS::new(),
            var_map: HashMap::new(),
            defined: HashMap::new(),
            next_var: 1, // Index 0 is reserved for constant 1
            public_inputs: Vec::new(),
            witness_felts: Vec::new(),
            witness_exts: Vec::new(),
            witness_vars: Vec::new(),
            vkey_hash_idx: None,
            committed_values_digest_idx: None,
        };
        compiler.r1cs.num_vars = 1;
        compiler
    }

    /// Allocate a new variable and return its index
    #[track_caller]
    fn alloc_var(&mut self, mut ctx: Option<&mut WitnessCtx<'_, C::F>>) -> usize {
        let idx = self.next_var;
        self.next_var += 1;
        self.r1cs.num_vars = self.next_var;

        // Optional targeted debug: print a backtrace when a specific R1CS index is allocated.
        // This is useful to identify which lowering path created an internal temp that later
        // appears in an unsatisfied constraint.
        static WATCH_IDX: OnceLock<Option<usize>> = OnceLock::new();
        let watch = WATCH_IDX.get_or_init(|| {
            std::env::var("R1CS_WATCH_IDX").ok().and_then(|s| s.parse::<usize>().ok())
        });
        if watch.as_ref().copied() == Some(idx) {
            println!("[R1CS_WATCH_IDX] allocated idx={idx}");
            let loc = std::panic::Location::caller();
            println!("[R1CS_WATCH_IDX] caller: {}:{}:{}", loc.file(), loc.line(), loc.column());
        }

        if let Some(c) = ctx.as_deref_mut() {
            c.ensure_len(self.next_var);
            // Default to 0; callers should assign the semantic value immediately.
            c.witness[idx] = C::F::zero();
        }
        idx
    }

    /// Read a variable id (may forward-allocate).
    ///
    /// For forward-referenced variables:
    /// - If the ID is hint-sourced (in `hinted_ids`), populate witness from pre-consumed `hint_felt_values`
    /// - Otherwise, populate from `get_value` (runtime memory)
    ///
    /// This ensures hint-sourced variables get their authoritative values from the hint stream,
    /// while non-hint variables (e.g., from runtime memory writes) still work correctly.
    #[track_caller]
    fn read_id(&mut self, id: &str, mut ctx: Option<&mut WitnessCtx<'_, C::F>>) -> usize {
        let watching = r1cs_watch_id(id);

        if let Some(&idx) = self.var_map.get(id) {
            if watching {
                println!("[R1CS_WATCH_ID] read existing {id} -> idx={idx}");
                let loc = std::panic::Location::caller();
                println!(
                    "[R1CS_WATCH_ID] read caller: {}:{}:{}",
                    loc.file(),
                    loc.line(),
                    loc.column()
                );
            }
            idx
        } else {
            let idx = self.alloc_var(ctx.as_deref_mut());
            self.var_map.insert(id.to_string(), idx);
            self.defined.insert(id.to_string(), false);
            if watching {
                println!("[R1CS_WATCH_ID] read new {id} -> idx={idx}");
                let loc = std::panic::Location::caller();
                println!(
                    "[R1CS_WATCH_ID] read caller: {}:{}:{}",
                    loc.file(),
                    loc.line(),
                    loc.column()
                );
            }
            
            // Populate witness value for forward-referenced variable
            if let Some(c) = ctx.as_deref_mut() {
                if c.hinted_ids.contains(id) {
                    // Hint-sourced variable: get value from pre-consumed hint map
                    let mut found = false;
                    
                    // Check hint_felt_values first
                    if let Some(v) = c.hint_felt_values.get(id).and_then(|q| q.front()).copied() {
                        c.set(idx, v);
                        found = true;
                    }
                    
                    // For ext components (IDs like "ext123__0"), check hint_ext_values
                    if !found && id.contains("__") {
                        if let Some(pos) = id.rfind("__") {
                            let base_id = &id[..pos];
                            let limb: usize = id[pos+2..].parse().unwrap_or(0);
                            if let Some(ext_val) = c
                                .hint_ext_values
                                .get(base_id)
                                .and_then(|q| q.front())
                                .copied()
                            {
                                c.set(idx, ext_val[limb]);
                                found = true;
                            }
                        }
                    }
                    
                    // If ID is in hinted_ids but not in maps, that's a Phase 1 bug
                    if !found {
                        panic!(
                            "R1CS read_id: forward-referenced hint ID '{}' is in hinted_ids but not in hint maps. \
                             This indicates Phase 1 didn't process the defining CircuitV2HintFelts/Exts op.",
                            id
                        );
                    }
                } else {
                    // Non-hint variable: prefill from runtime memory snapshot.
                    // This provides initial values for read-before-write IDs that are not hint-sourced.
                    if let Some(v) = (c.get_value)(id) {
                        c.set(idx, v);
                    }
                }
            }
            idx
        }
    }

    /// Write/define a variable id.
    ///
    /// - If `id` is unseen: allocate fresh and mark defined.
    /// - If `id` exists but was forward-allocated (`defined=false`): reuse same idx and flip to defined.
    /// - If `id` exists and was already defined: allocate fresh, update mapping.
    ///
    /// This preserves forward-reference semantics: when a variable is used before defined,
    /// the read allocates a placeholder. The defining write reuses that placeholder so both
    /// the read and write refer to the same R1CS variable.
    #[track_caller]
    fn write_id(&mut self, id: &str, mut ctx: Option<&mut WitnessCtx<'_, C::F>>) -> usize {
        let watching = r1cs_watch_id(id);

        match self.var_map.get(id).copied() {
            None => {
                // First time seeing this ID - allocate fresh
                let idx = self.alloc_var(ctx.as_deref_mut());
                self.var_map.insert(id.to_string(), idx);
                self.defined.insert(id.to_string(), true);
                if watching {
                    println!("[R1CS_WATCH_ID] write new {id} -> idx={idx}");
                    let loc = std::panic::Location::caller();
                    println!(
                        "[R1CS_WATCH_ID] write caller: {}:{}:{}",
                        loc.file(),
                        loc.line(),
                        loc.column()
                    );
                }
                idx
            }
            Some(idx) => {
                let was_defined = self.defined.get(id).copied().unwrap_or(true);
                if was_defined {
                    // Already defined - allocate fresh for new version
                    let new_idx = self.alloc_var(ctx.as_deref_mut());
                    self.var_map.insert(id.to_string(), new_idx);
                    self.defined.insert(id.to_string(), true);
                    if watching {
                        println!("[R1CS_WATCH_ID] write redef {id} old_idx={idx} -> new_idx={new_idx}");
                        let loc = std::panic::Location::caller();
                        println!(
                            "[R1CS_WATCH_ID] write caller: {}:{}:{}",
                            loc.file(),
                            loc.line(),
                            loc.column()
                        );
                    }
                    new_idx
                } else {
                    // Forward-allocated.
                    //
                    // Important distinction:
                    // - Hint-sourced IDs are legitimately used before their hint op defines them.
                    //   In that case, the "define" must reuse the placeholder so earlier uses and
                    //   the defining hint op refer to the same R1CS variable.
                    // - Non-hint IDs can be read before written because they represent mutable
                    //   memory locations with an existing value. In that case, the later write is
                    //   a *new version* and must allocate a fresh index (do NOT reuse).
                    let is_hinted = ctx
                        .as_deref()
                        .is_some_and(|c| c.hinted_ids.contains(id));
                    // Public inputs are encoded positionally in the R1CS format: indices 1..=num_public.
                    // We preallocate those IDs into the prefix, and MUST reuse the placeholder on the
                    // first defining write so the committed value lives in the public slot.
                    let is_public_placeholder = idx >= 1 && idx <= self.r1cs.num_public;
                    if is_hinted || is_public_placeholder {
                        self.defined.insert(id.to_string(), true);
                        if watching {
                            println!("[R1CS_WATCH_ID] write define {id} reuse_idx={idx} (hinted/public)");
                            let loc = std::panic::Location::caller();
                            println!(
                                "[R1CS_WATCH_ID] write caller: {}:{}:{}",
                                loc.file(),
                                loc.line(),
                                loc.column()
                            );
                        }
                        idx
                    } else {
                        let new_idx = self.alloc_var(ctx.as_deref_mut());
                        self.var_map.insert(id.to_string(), new_idx);
                        self.defined.insert(id.to_string(), true);
                        if watching {
                            println!(
                                "[R1CS_WATCH_ID] write define {id} old_placeholder_idx={idx} -> new_idx={new_idx} (non-hint)",
                            );
                            let loc = std::panic::Location::caller();
                            println!(
                                "[R1CS_WATCH_ID] write caller: {}:{}:{}",
                                loc.file(),
                                loc.line(),
                                loc.column()
                            );
                        }
                        new_idx
                    }
                }
            }
        }
    }

    /// Backwards-compatible helper: in this backend, "get_or_alloc" is used for destinations
    /// (writes), so it is equivalent to `write_id`.
    fn get_or_alloc(&mut self, id: &str, ctx: Option<&mut WitnessCtx<'_, C::F>>) -> usize {
        self.write_id(id, ctx)
    }

    /// Check if a variable is already defined (has a mapping AND was marked as defined).
    #[allow(dead_code)]
    fn is_defined(&self, id: &str) -> bool {
        self.var_map.contains_key(id)
            && self.defined.get(id).copied().unwrap_or(false)
    }

    /// Get the index of an already-defined variable. Returns None if not defined.
    #[allow(dead_code)]
    fn get_defined(&self, id: &str) -> Option<usize> {
        if self.is_defined(id) {
            self.var_map.get(id).copied()
        } else {
            None
        }
    }

    /// Get existing variable index, or allocate if not found.
    /// 
    /// NOTE: We allow forward references (using a variable before it's "declared") because
    /// the SP1 verifier IR can reference variables that are declared later via hint ops.
    /// This matches the behavior of the circuit compiler's `Entry::Vacant` pattern.
    fn get_var(&mut self, id: &str, ctx: Option<&mut WitnessCtx<'_, C::F>>) -> usize {
        self.read_id(id, ctx)
    }

    /// Allocate a constant and return its index
    #[track_caller]
    fn alloc_const(&mut self, value: C::F, mut ctx: Option<&mut WitnessCtx<'_, C::F>>) -> usize {
        let idx = self.alloc_var(ctx.as_deref_mut());
        // Optional targeted debug: show the constant being allocated for a watched index.
        static WATCH_IDX: OnceLock<Option<usize>> = OnceLock::new();
        let watch = WATCH_IDX.get_or_init(|| {
            std::env::var("R1CS_WATCH_IDX").ok().and_then(|s| s.parse::<usize>().ok())
        });
        if watch.as_ref().copied() == Some(idx) {
            let loc = std::panic::Location::caller();
            println!(
                "[R1CS_WATCH_IDX] alloc_const idx={} value={} (canonical_u64={}) ctx_is_some={}",
                idx,
                value,
                value.as_canonical_u64(),
                ctx.is_some()
            );
            println!(
                "[R1CS_WATCH_IDX] alloc_const caller: {}:{}:{}",
                loc.file(),
                loc.line(),
                loc.column()
            );
        }
        if let Some(c) = ctx.as_deref_mut() {
            c.set(idx, value);
        }
        // Constraint: idx = value (using constant 1 at index 0)
        // (1) * (value) = (idx)
        self.r1cs.add_constraint(
            SparseRow::single(0), // A: 1
            SparseRow::constant(value), // B: value
            SparseRow::single(idx), // C: idx
        );
        idx
    }

    /// Add multiplication constraint: out = a * b
    fn add_mul(&mut self, out: usize, a: usize, b: usize) {
        self.r1cs.add_constraint(
            SparseRow::single(a),
            SparseRow::single(b),
            SparseRow::single(out),
        );
    }

    /// Add equality constraint: a = b
    /// Encoded as: (a - b) * 1 = 0
    fn add_eq(&mut self, a: usize, b: usize) {
        let mut a_row = SparseRow::new();
        a_row.add_term(a, C::F::one());
        a_row.add_term(b, -C::F::one());
        self.r1cs.add_constraint(
            a_row,
            SparseRow::single(0), // B: 1
            SparseRow::zero(), // C: 0
        );
    }

    /// Add constraint: a != b (via inverse hint)
    /// We compute diff = a - b, then prove diff has an inverse
    /// diff_inv is hinted, and we check diff * diff_inv = 1
    fn add_neq(&mut self, a: usize, b: usize, mut ctx: Option<&mut WitnessCtx<'_, C::F>>) {
        // diff = a - b (linear, allocated as witness)
        let diff = self.alloc_var(ctx.as_deref_mut());
        // diff_inv = 1/(a-b) (hinted)
        let diff_inv = self.alloc_var(ctx.as_deref_mut());

        if let Some(c) = ctx.as_deref_mut() {
            let diff_val = c.get(a) - c.get(b);
            c.set(diff, diff_val);
            let inv = diff_val
                .try_inverse()
                .expect("R1CSCompiler witness: attempted to invert zero in add_neq");
            c.set(diff_inv, inv);
        }
        
        // Constraint: diff = a - b
        // (1) * (a - b) = diff
        let mut ab_diff = SparseRow::new();
        ab_diff.add_term(a, C::F::one());
        ab_diff.add_term(b, -C::F::one());
        self.r1cs.add_constraint(
            SparseRow::single(0),
            ab_diff,
            SparseRow::single(diff),
        );
        
        // Constraint: diff * diff_inv = 1
        self.r1cs.add_constraint(
            SparseRow::single(diff),
            SparseRow::single(diff_inv),
            SparseRow::single(0), // C: constant 1
        );
    }

    /// Add boolean constraint: b * (1 - b) = 0
    /// This ensures b ∈ {0, 1}
    fn add_boolean(&mut self, b: usize) {
        // b * (1 - b) = 0
        // A: b, B: (1 - b), C: 0
        let mut one_minus_b = SparseRow::new();
        one_minus_b.add_term(0, C::F::one()); // 1
        one_minus_b.add_term(b, -C::F::one()); // - b
        self.r1cs.add_constraint(
            SparseRow::single(b),
            one_minus_b,
            SparseRow::zero(),
        );
    }

    /// Add select constraint: out = cond ? a : b
    /// Encoded as: out = cond * (a - b) + b
    /// Which is: out - b = cond * (a - b)
    /// R1CS: (cond) * (a - b) = (out - b)
    /// 
    /// IMPORTANT: Also adds boolean constraint on cond!
    fn add_select(&mut self, out: usize, cond: usize, a: usize, b: usize) {
        // First ensure cond is boolean
        self.add_boolean(cond);
        
        // (cond) * (a - b) = (out - b)
        let mut a_minus_b = SparseRow::new();
        a_minus_b.add_term(a, C::F::one());
        a_minus_b.add_term(b, -C::F::one());
        
        let mut out_minus_b = SparseRow::new();
        out_minus_b.add_term(out, C::F::one());
        out_minus_b.add_term(b, -C::F::one());
        
        self.r1cs.add_constraint(
            SparseRow::single(cond),
            a_minus_b,
            out_minus_b,
        );
    }

    /// Add bit decomposition constraints: value = sum(bits[i] * 2^i)
    /// Also adds boolean constraints on each bit
    fn add_num2bits(&mut self, value: usize, bits: &[usize], num_bits: usize) {
        // Each bit must be boolean
        for &bit in bits.iter().take(num_bits) {
            self.add_boolean(bit);
        }
        
        // value = sum(bits[i] * 2^i)
        // We express this as: (1) * (sum) = (value)
        let mut sum = SparseRow::new();
        let mut power = C::F::one();
        let two = C::F::from_canonical_u64(2);
        for &bit in bits.iter().take(num_bits) {
            sum.add_term(bit, power);
            power = power * two;
        }
        
        self.r1cs.add_constraint(
            SparseRow::single(0), // A: 1
            sum, // B: sum of bits
            SparseRow::single(value), // C: value
        );
    }

    /// Compile a single DSL instruction to R1CS constraints
    pub fn compile_one(&mut self, instr: DslIr<C>) {
        self.compile_one_inner(instr, None);
    }

    fn compile_one_inner(&mut self, instr: DslIr<C>, mut ctx: Option<&mut WitnessCtx<'_, C::F>>) {
        match instr {
            // === Immediate values ===
            DslIr::ImmV(_dst, _val) => {
                // NOTE: This backend targets BabyBear-native shrink verifier work.
                // `ImmV` operates over `C::N` (Var field), which is not guaranteed to equal `C::F`.
                // Silently allocating would create an unconstrained variable.
                panic!("R1CSCompiler: ImmV not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::ImmF(dst, val) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(val, ctx.as_deref_mut());
                self.add_eq(dst_idx, const_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, val);
                }
            }
            
            DslIr::ImmE(dst, val) => {
                // Extension element: 4 base field elements
                let base = val.as_base_slice();
                for (i, &coeff) in base.iter().enumerate() {
                    let dst_idx =
                        self.write_id(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let const_idx = self.alloc_const(coeff, ctx.as_deref_mut());
                    self.add_eq(dst_idx, const_idx);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, coeff);
                    }
                }
            }

            // === Addition (linear, no constraint needed - just track wiring) ===
            DslIr::AddV(dst, lhs, rhs) => {
                Self::require_var_field_is_base_field();
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(rhs_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) + c.get(rhs_idx));
                }
            }
            
            DslIr::AddF(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(rhs_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) + c.get(rhs_idx));
                }
            }
            
            DslIr::AddVI(_dst, _lhs, _rhs) => {
                // NOTE: This backend targets BabyBear-native shrink verifier work.
                // `AddVI` operates over `C::N` (Var field), which is not guaranteed to equal `C::F`.
                // Silently skipping would create unconstrained variables, so we fail fast.
                panic!("R1CSCompiler: AddVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::AddFI(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(const_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) + rhs);
                }
            }

            // === Subtraction ===
            DslIr::SubV(dst, lhs, rhs) => {
                Self::require_var_field_is_base_field();
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs_idx, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) - c.get(rhs_idx));
                }
            }
            
            DslIr::SubF(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs_idx, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) - c.get(rhs_idx));
                }
            }
            
            DslIr::SubFI(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs_idx, C::F::one());
                diff.add_term(const_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) - rhs);
                }
            }
            
            DslIr::SubFIN(dst, lhs, rhs) => {
                // dst = lhs (constant) - rhs (variable)
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(lhs, ctx.as_deref_mut());
                
                let mut diff = SparseRow::new();
                diff.add_term(const_idx, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, lhs - c.get(rhs_idx));
                }
            }

            // === Multiplication ===
            DslIr::MulV(dst, lhs, rhs) => {
                Self::require_var_field_is_base_field();
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                self.add_mul(dst_idx, lhs_idx, rhs_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) * c.get(rhs_idx));
                }
            }
            
            DslIr::MulF(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                self.add_mul(dst_idx, lhs_idx, rhs_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) * c.get(rhs_idx));
                }
            }
            
            DslIr::MulVI(_dst, _lhs, _rhs) => {
                panic!("R1CSCompiler: MulVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::MulFI(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                self.add_mul(dst_idx, lhs_idx, const_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, c.get(lhs_idx) * rhs);
                }
            }

            // === Division (via inverse hint) ===
            DslIr::DivF(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                // dst = lhs / rhs
                // Constraint: dst * rhs = lhs
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(rhs_idx),
                    SparseRow::single(lhs_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    let inv = c
                        .get(rhs_idx)
                        .try_inverse()
                        .expect("R1CSCompiler witness: attempted to divide by zero (DivF)");
                    c.set(dst_idx, c.get(lhs_idx) * inv);
                }
            }
            
            DslIr::DivFI(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(const_idx),
                    SparseRow::single(lhs_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    let inv = rhs
                        .try_inverse()
                        .expect("R1CSCompiler witness: attempted to divide by zero (DivFI)");
                    c.set(dst_idx, c.get(lhs_idx) * inv);
                }
            }
            
            DslIr::DivFIN(dst, lhs, rhs) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(lhs, ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(rhs_idx),
                    SparseRow::single(const_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    let inv = c
                        .get(rhs_idx)
                        .try_inverse()
                        .expect("R1CSCompiler witness: attempted to divide by zero (DivFIN)");
                    c.set(dst_idx, lhs * inv);
                }
            }

            // === Negation ===
            DslIr::NegV(dst, src) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let src_idx = self.get_var(&src.id(), ctx.as_deref_mut());
                
                let mut neg_src = SparseRow::new();
                neg_src.add_term(src_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    neg_src,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, -c.get(src_idx));
                }
            }
            
            DslIr::NegF(dst, src) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let src_idx = self.get_var(&src.id(), ctx.as_deref_mut());
                
                let mut neg_src = SparseRow::new();
                neg_src.add_term(src_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    neg_src,
                    SparseRow::single(dst_idx),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst_idx, -c.get(src_idx));
                }
            }

            // === Inversion ===
            DslIr::InvV(dst, src) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let src_idx = self.get_var(&src.id(), ctx.as_deref_mut());
                
                // dst = 1 / src
                // Constraint: dst * src = 1
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(src_idx),
                    SparseRow::single(0), // constant 1
                );
                if let Some(c) = ctx.as_deref_mut() {
                    let inv = c
                        .get(src_idx)
                        .try_inverse()
                        .expect("R1CSCompiler witness: attempted to invert zero (InvV)");
                    c.set(dst_idx, inv);
                }
            }
            
            DslIr::InvF(dst, src) => {
                let dst_idx = self.write_id(&dst.id(), ctx.as_deref_mut());
                let src_idx = self.get_var(&src.id(), ctx.as_deref_mut());
                
                self.r1cs.add_constraint(
                    SparseRow::single(dst_idx),
                    SparseRow::single(src_idx),
                    SparseRow::single(0), // constant 1
                );
                if let Some(c) = ctx.as_deref_mut() {
                    let inv = c
                        .get(src_idx)
                        .try_inverse()
                        .expect("R1CSCompiler witness: attempted to invert zero (InvF)");
                    c.set(dst_idx, inv);
                }
            }

            // === Assertions ===
            DslIr::AssertEqV(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                self.add_eq(lhs_idx, rhs_idx);
            }
            
            DslIr::AssertEqF(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                self.add_eq(lhs_idx, rhs_idx);
            }
            
            DslIr::AssertEqVI(_lhs, _rhs) => {
                panic!("R1CSCompiler: AssertEqVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::AssertEqFI(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                self.add_eq(lhs_idx, const_idx);
            }
            
            DslIr::AssertNeV(lhs, rhs) => {
                Self::require_var_field_is_base_field();
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                self.add_neq(lhs_idx, rhs_idx, ctx.as_deref_mut());
            }
            
            DslIr::AssertNeF(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                self.add_neq(lhs_idx, rhs_idx, ctx.as_deref_mut());
            }
            
            DslIr::AssertNeVI(_lhs, _rhs) => {
                panic!("R1CSCompiler: AssertNeVI not supported (Var field C::N may differ from C::F). Implement Var-field support or restrict Config so C::N == C::F.");
            }
            
            DslIr::AssertNeFI(lhs, rhs) => {
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                self.add_neq(lhs_idx, const_idx, ctx.as_deref_mut());
            }

            // === Select operations ===
            DslIr::CircuitSelectV(cond, a, b, out) => {
                Self::require_var_field_is_base_field();
                let out_idx = self.get_or_alloc(&out.id(), ctx.as_deref_mut());
                let cond_idx = self.get_var(&cond.id(), ctx.as_deref_mut());
                let a_idx = self.get_var(&a.id(), ctx.as_deref_mut());
                let b_idx = self.get_var(&b.id(), ctx.as_deref_mut());
                self.add_boolean(cond_idx);
                self.add_select(out_idx, cond_idx, a_idx, b_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    // Field-linear form: out = cond*(a-b) + b.
                    c.set(out_idx, c.get(cond_idx) * (c.get(a_idx) - c.get(b_idx)) + c.get(b_idx));
                }
            }
            
            DslIr::CircuitSelectF(cond, a, b, out) => {
                Self::require_var_field_is_base_field();
                let out_idx = self.get_or_alloc(&out.id(), ctx.as_deref_mut());
                let cond_idx = self.get_var(&cond.id(), ctx.as_deref_mut());
                let a_idx = self.get_var(&a.id(), ctx.as_deref_mut());
                let b_idx = self.get_var(&b.id(), ctx.as_deref_mut());
                self.add_boolean(cond_idx);
                self.add_select(out_idx, cond_idx, a_idx, b_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(out_idx, c.get(cond_idx) * (c.get(a_idx) - c.get(b_idx)) + c.get(b_idx));
                }
            }
            
            DslIr::CircuitSelectE(cond, a, b, out) => {
                Self::require_var_field_is_base_field();
                let cond_idx = self.get_var(&cond.id(), ctx.as_deref_mut());
                self.add_boolean(cond_idx);

                // Each extension element is 4 base field elements. Apply the same select gadget
                // componentwise.
                for i in 0..4 {
                    let out_i = self.get_or_alloc(&format!("{}__{}", out.id(), i), ctx.as_deref_mut());
                    let a_i = self.get_var(&format!("{}__{}", a.id(), i), ctx.as_deref_mut());
                    let b_i = self.get_var(&format!("{}__{}", b.id(), i), ctx.as_deref_mut());
                    self.add_select(out_i, cond_idx, a_i, b_i);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(out_i, c.get(cond_idx) * (c.get(a_i) - c.get(b_i)) + c.get(b_i));
                    }
                }
            }

            // === Bit decomposition ===
            DslIr::CircuitNum2BitsV(value, num_bits, output) => {
                Self::require_var_field_is_base_field();
                let value_idx = self.get_var(&value.id(), ctx.as_deref_mut());
                let bit_indices: Vec<usize> = output
                    .iter()
                    .map(|v| self.get_or_alloc(&v.id(), ctx.as_deref_mut()))
                    .collect();
                self.add_num2bits(value_idx, &bit_indices, num_bits);
                if let Some(c) = ctx.as_deref_mut() {
                    let mut x = c.get(value_idx).as_canonical_u64();
                    for &b in bit_indices.iter().take(num_bits) {
                        c.set(b, C::F::from_canonical_u64(x & 1));
                        x >>= 1;
                    }
                }
            }
            
            DslIr::CircuitNum2BitsF(value, output) => {
                Self::require_var_field_is_base_field();
                let value_idx = self.get_var(&value.id(), ctx.as_deref_mut());
                let bit_indices: Vec<usize> = output
                    .iter()
                    .map(|v| self.get_or_alloc(&v.id(), ctx.as_deref_mut()))
                    .collect();
                // BabyBear has 31-bit modulus; this opcode is intended to produce a 31-bit
                // canonical decomposition.
                let nbits = bit_indices.len();
                assert!(
                    nbits <= 31,
                    "CircuitNum2BitsF: requested {nbits} bits; expected <= 31 for BabyBear"
                );
                self.add_num2bits(value_idx, &bit_indices, nbits);

                // Canonicality check for 31-bit decompositions (same idea as V2):
                // if top 4 bits are all 1, then all bottom 27 bits must be 0.
                let (b27, b28, b29, b30) = if nbits > 30 {
                    (bit_indices[27], bit_indices[28], bit_indices[29], bit_indices[30])
                } else {
                    (0usize, 0usize, 0usize, 0usize)
                };
                let mut top_and_vars: Option<(usize, usize, usize)> = None;
                if nbits > 30 {
                    let t01 = self.alloc_var(ctx.as_deref_mut());
                    self.add_mul(t01, b30, b29);
                    let t012 = self.alloc_var(ctx.as_deref_mut());
                    self.add_mul(t012, t01, b28);
                    let are_all_top_bits_one = self.alloc_var(ctx.as_deref_mut());
                    self.add_mul(are_all_top_bits_one, t012, b27);
                    top_and_vars = Some((t01, t012, are_all_top_bits_one));

                    let zero = self.alloc_const(C::F::zero(), ctx.as_deref_mut());
                    for &bit in bit_indices.iter().take(27) {
                        self.r1cs.add_constraint(
                            SparseRow::single(bit),
                            SparseRow::single(are_all_top_bits_one),
                            SparseRow::single(zero),
                        );
                    }
                }
                if let Some(c) = ctx.as_deref_mut() {
                    let mut x = c.get(value_idx).as_canonical_u64();
                    for &b in bit_indices.iter().take(nbits) {
                        c.set(b, C::F::from_canonical_u64(x & 1));
                        x >>= 1;
                    }
                    if let Some((t01, t012, are_all_top_bits_one)) = top_and_vars {
                        c.set(t01, c.get(b30) * c.get(b29));
                        c.set(t012, c.get(t01) * c.get(b28));
                        c.set(are_all_top_bits_one, c.get(t012) * c.get(b27));
                    }
                }
            }

            // === Poseidon2 permutation (BabyBear) - V2 with separate input/output ===
            DslIr::CircuitV2Poseidon2PermuteBabyBear(boxed) => {
                // IMPORTANT: This matches the circuit compiler / runtime semantics:
                // `AsmCompiler::poseidon2_permute(dst, src)` is called as
                // `poseidon2_permute(data.0, data.1)`, so tuple order is (output, input).
                let (output, input) = boxed.as_ref();
                
                // Get input variable indices
                let input_indices: Vec<usize> = (0..16)
                    .map(|i| self.get_var(&input[i].id(), ctx.as_deref_mut()))
                    .collect();
                
                // Allocate output variable indices
                let output_indices: Vec<usize> = (0..16)
                    .map(|i| self.get_or_alloc(&output[i].id(), ctx.as_deref_mut()))
                    .collect();
                
                // Expand Poseidon2 and get computed output indices
                let computed_output = if let Some(c) = ctx.as_deref_mut() {
                    Poseidon2R1CS::<C::F>::expand_permute_babybear_with_witness(
                        &mut self.r1cs,
                        &mut self.next_var,
                        &input_indices,
                        c.witness,
                    )
                } else {
                    Poseidon2R1CS::<C::F>::expand_permute_babybear(
                        &mut self.r1cs,
                        &mut self.next_var,
                        &input_indices,
                    )
                };
                
                // Bind computed outputs to the declared output variables
                for i in 0..16 {
                    self.add_eq(output_indices[i], computed_output[i]);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(output_indices[i], c.get(computed_output[i]));
                    }
                }
            }
            
            // === Poseidon2 permutation (BabyBear) - in-place variant (gnark) ===
            DslIr::CircuitPoseidon2PermuteBabyBear(state) => {
                let state_indices: Vec<usize> = (0..16)
                    .map(|i| self.get_var(&state[i].id(), ctx.as_deref_mut()))
                    .collect();
                
                // For in-place variant, computed output overwrites input
                let computed_output = if let Some(c) = ctx.as_deref_mut() {
                    Poseidon2R1CS::<C::F>::expand_permute_babybear_with_witness(
                        &mut self.r1cs,
                        &mut self.next_var,
                        &state_indices,
                        c.witness,
                    )
                } else {
                    Poseidon2R1CS::<C::F>::expand_permute_babybear(
                        &mut self.r1cs,
                        &mut self.next_var,
                        &state_indices,
                    )
                };
                
                // Update the variable map to point to the new output indices
                for i in 0..16 {
                    self.var_map.insert(state[i].id(), computed_output[i]);
                }
            }
            
            // === BN254 Poseidon2 (for outer wrap - not used for Symphony) ===
            DslIr::CircuitPoseidon2Permute(_state) => {
                // This is for BN254 outer wrap, skip for BabyBear R1CS
                panic!("CircuitPoseidon2Permute (BN254) not supported in BabyBear R1CS backend");
            }
            
            // === Select (conditional swap) ===
            // Select(should_swap, first_result, second_result, first_input, second_input)
            // If should_swap == 1: first_result = second_input, second_result = first_input
            // If should_swap == 0: first_result = first_input, second_result = second_input
            DslIr::Select(should_swap, first_result, second_result, first_input, second_input) => {
                let swap_idx = self.get_var(&should_swap.id(), ctx.as_deref_mut());
                let out1_idx = self.get_or_alloc(&first_result.id(), ctx.as_deref_mut());
                let out2_idx = self.get_or_alloc(&second_result.id(), ctx.as_deref_mut());
                let in1_idx = self.get_var(&first_input.id(), ctx.as_deref_mut());
                let in2_idx = self.get_var(&second_input.id(), ctx.as_deref_mut());
                
                // Ensure should_swap is boolean
                self.add_boolean(swap_idx);
                
                // first_result = should_swap * second_input + (1 - should_swap) * first_input
                //              = should_swap * (second_input - first_input) + first_input
                // R1CS: (swap) * (in2 - in1) = (out1 - in1)
                let mut in2_minus_in1 = SparseRow::new();
                in2_minus_in1.add_term(in2_idx, C::F::one());
                in2_minus_in1.add_term(in1_idx, -C::F::one());
                
                let mut out1_minus_in1 = SparseRow::new();
                out1_minus_in1.add_term(out1_idx, C::F::one());
                out1_minus_in1.add_term(in1_idx, -C::F::one());
                
                self.r1cs.add_constraint(
                    SparseRow::single(swap_idx),
                    in2_minus_in1,
                    out1_minus_in1,
                );
                
                // second_result = should_swap * first_input + (1 - should_swap) * second_input
                //               = should_swap * (first_input - second_input) + second_input
                // R1CS: (swap) * (in1 - in2) = (out2 - in2)
                let mut in1_minus_in2 = SparseRow::new();
                in1_minus_in2.add_term(in1_idx, C::F::one());
                in1_minus_in2.add_term(in2_idx, -C::F::one());
                
                let mut out2_minus_in2 = SparseRow::new();
                out2_minus_in2.add_term(out2_idx, C::F::one());
                out2_minus_in2.add_term(in2_idx, -C::F::one());
                
                self.r1cs.add_constraint(
                    SparseRow::single(swap_idx),
                    in1_minus_in2,
                    out2_minus_in2,
                );

                if let Some(c) = ctx.as_deref_mut() {
                    // Same linear form used in constraints.
                    let out1 = c.get(swap_idx) * (c.get(in2_idx) - c.get(in1_idx)) + c.get(in1_idx);
                    let out2 = c.get(swap_idx) * (c.get(in1_idx) - c.get(in2_idx)) + c.get(in2_idx);
                    c.set(out1_idx, out1);
                    c.set(out2_idx, out2);
                }
            }
            
            // === V2 Hint operations (witness inputs for shrink verifier) ===
            //
            // NOTE: `CircuitV2HintFelts(start, len)` and `CircuitV2HintExts(start, len)` are
            // *contiguous ranges* of memory locations. The witness stream is consumed in *program
            // order*, so we record these as an ordered list (append), not by indexing into an array.
            //
            // IMPORTANT: In compile_with_witness's two-phase approach, Phase 1 pre-consumes ALL
            // hints into maps. Phase 2's handlers allocate variables normally (preserving SSA)
            // and get witness values from the pre-consumed maps instead of live stream.
            DslIr::CircuitV2HintFelts(start, len) => {
                for i in 0..len {
                    let id = format!("felt{}", start.idx + i as u32);
                    // Allocate variable (normal SSA semantics)
                    let felt_idx = self.get_or_alloc(&id, ctx.as_deref_mut());
                    self.witness_felts.push(felt_idx);
                    
                    // Set witness from pre-consumed queue (Phase 1 must have populated this)
                    if let Some(c) = ctx.as_deref_mut() {
                        let v = c
                            .hint_felt_values
                            .get_mut(&id)
                            .and_then(|q| q.pop_front())
                            .unwrap_or_else(|| {
                            // If hinted_ids is populated but map is empty, Phase 1 missed this ID
                            // This indicates a bug in Phase 1's traversal (e.g., nested structure not handled)
                            if !c.hinted_ids.is_empty() {
                                panic!(
                                    "R1CS Phase 2: hint felt '{}' not in pre-consumed map but hinted_ids is populated. \
                                     Phase 1 may have missed a CircuitV2HintFelts op (nested structure?).",
                                    id
                                );
                            }
                            // Fallback for non-witness-mode compilation (no Phase 1)
                            (c.next_hint_felt)()
                                .unwrap_or_else(|| panic!("R1CSCompiler witness: witness stream underrun for {id}"))
                        });
                        c.set(felt_idx, v);
                    }
                }
            }

            DslIr::CircuitV2HintExts(start, len) => {
                for j in 0..len {
                    let ext_id = format!("ext{}", start.idx + j as u32);
                    
                    // Get ext values from pre-consumed queue (Phase 1 must have populated this)
                    let ext_vals: Option<[C::F; 4]> = if let Some(c) = ctx.as_deref_mut() {
                        let val = c
                            .hint_ext_values
                            .get_mut(&ext_id)
                            .and_then(|q| q.pop_front())
                            .unwrap_or_else(|| {
                            if !c.hinted_ids.is_empty() {
                                panic!(
                                    "R1CS Phase 2: hint ext '{}' not in pre-consumed map but hinted_ids is populated. \
                                     Phase 1 may have missed a CircuitV2HintExts op (nested structure?).",
                                    ext_id
                                );
                            }
                            // Fallback for non-witness-mode compilation
                            (c.next_hint_ext)().unwrap_or_else(|| {
                                panic!("R1CSCompiler witness: witness stream underrun for {ext_id}")
                            })
                        });
                        Some(val)
                    } else {
                        None
                    };
                    
                    for limb in 0..4 {
                        let component_id = format!("{}__{}", ext_id, limb);
                        // Allocate variable (normal SSA semantics)
                        let ext_idx = self.get_or_alloc(&component_id, ctx.as_deref_mut());
                        self.witness_exts.push(ext_idx);
                        
                        // Set witness value
                        if let (Some(c), Some(vals)) = (ctx.as_deref_mut(), ext_vals) {
                            c.set(ext_idx, vals[limb]);
                        }
                    }
                }
            }
            
            DslIr::CircuitV2HintBitsF(bits, value) => {
                let value_idx = self.get_var(&value.id(), ctx.as_deref_mut());
                let bit_indices: Vec<usize> = bits
                    .iter()
                    .map(|b| self.get_or_alloc(&b.id(), ctx.as_deref_mut()))
                    .collect();
                // Soundness note:
                // BabyBear elements have a unique canonical representative in [0, p-1) with
                // p < 2^31, so a bit decomposition must use at most 31 bits.
                //
                // If the IR ever asked for >31 bits and we only constrained the low 31, the
                // remaining bits would be unconstrained witness degrees of freedom.
                let nbits = bit_indices.len();
                assert!(
                    nbits <= 31,
                    "CircuitV2HintBitsF: requested {nbits} bits for a BabyBear Felt; this would be non-canonical/unsound. Expected <= 31."
                );
                self.add_num2bits(value_idx, &bit_indices, nbits);

                // In witness-mode, populate the hinted bits from the canonical representative
                // BEFORE computing any derived intermediates that depend on them.
                // Canonicality / modulus-range check (matches `circuit/builder.rs::num2bits_v2_f`):
                //
                // BabyBear modulus is p = 2^31 - 2^27 + 1 = (15 * 2^27) + 1.
                //
                // For a 31-bit decomposition, we must rule out non-canonical integers in [p, 2^31)
                // that are congruent mod p (otherwise the circuit could accept wrong bitstrings).
                //
                // The following logic is exactly what the CircuitV2 builder enforces:
                // - Let `are_all_top_bits_one = b30 * b29 * b28 * b27` (bitwise AND of top 4 bits).
                // - Enforce: if are_all_top_bits_one == 1 then all bottom 27 bits are 0.
                //
                // This allows values < 15*2^27 (top4 != 1111) or exactly 15*2^27 (top4==1111, bottom==0),
                // which are precisely the canonical representatives < p.
                let (b27, b28, b29, b30) = if nbits > 30 {
                    // Bits are ordered least-significant first: bit_indices[i] corresponds to 2^i.
                    (bit_indices[27], bit_indices[28], bit_indices[29], bit_indices[30])
                } else {
                    (0usize, 0usize, 0usize, 0usize)
                };

                // We may allocate intermediates for the canonicality check; fill their witness values
                // after bits are assigned.
                let mut top_and_vars: Option<(usize, usize, usize)> = None;

                if nbits > 30 {
                    let (b27, b28, b29, b30) = (b27, b28, b29, b30);

                    let t01 = self.alloc_var(ctx.as_deref_mut());
                    self.add_mul(t01, b30, b29);
                    let t012 = self.alloc_var(ctx.as_deref_mut());
                    self.add_mul(t012, t01, b28);
                    let are_all_top_bits_one = self.alloc_var(ctx.as_deref_mut());
                    self.add_mul(are_all_top_bits_one, t012, b27);
                    top_and_vars = Some((t01, t012, are_all_top_bits_one));

                    let zero = self.alloc_const(C::F::zero(), ctx.as_deref_mut());
                    for &bit in bit_indices.iter().take(27) {
                        // Enforce bit * are_all_top_bits_one = 0.
                        self.r1cs.add_constraint(
                            SparseRow::single(bit),
                            SparseRow::single(are_all_top_bits_one),
                            SparseRow::single(zero),
                        );
                    }
                }
                if let Some(c) = ctx.as_deref_mut() {
                    let mut x = c.get(value_idx).as_canonical_u64();
                    for &b in bit_indices.iter() {
                        c.set(b, C::F::from_canonical_u64(x & 1));
                        x >>= 1;
                    }
                    // Now that bits are assigned, fill the derived AND products witness values.
                    if let Some((t01, t012, are_all_top_bits_one)) = top_and_vars {
                        c.set(t01, c.get(b30) * c.get(b29));
                        c.set(t012, c.get(t01) * c.get(b28));
                        c.set(are_all_top_bits_one, c.get(t012) * c.get(b27));
                    }
                }
            }

            // === FRI operations ===
            //
            // CircuitV2FriFold: For each element i in the batch:
            //   alpha_pow_output[i] = alpha_pow_input[i] * alpha
            //   (ro_output[i] - ro_input[i]) * (z - x) = alpha_pow_input[i] * (mat_opening[i] - ps_at_z[i])
            DslIr::CircuitV2FriFold(boxed) => {
                let (output, input) = boxed.as_ref();
                let n = input.mat_opening.len();
                
                // Get input indices
                let z_idx: Vec<usize> = (0..4)
                    .map(|i| self.get_var(&format!("{}__{}", input.z.id(), i), ctx.as_deref_mut()))
                    .collect();
                let alpha_idx: Vec<usize> = (0..4)
                    .map(|i| self.get_var(&format!("{}__{}", input.alpha.id(), i), ctx.as_deref_mut()))
                    .collect();
                let x_idx = self.get_var(&input.x.id(), ctx.as_deref_mut());
                
                 for j in 0..n {
                    // Get input arrays
                    let mat_opening_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_var(
                                &format!("{}__{}", input.mat_opening[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    let ps_at_z_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_var(
                                &format!("{}__{}", input.ps_at_z[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    let alpha_pow_in_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_var(
                                &format!("{}__{}", input.alpha_pow_input[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    let ro_in_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_var(
                                &format!("{}__{}", input.ro_input[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    
                    // Allocate outputs
                    let alpha_pow_out_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_or_alloc(
                                &format!("{}__{}", output.alpha_pow_output[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    let ro_out_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_or_alloc(
                                &format!("{}__{}", output.ro_output[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    
                    // Constraint 1: alpha_pow_output = alpha_pow_input * alpha
                    // This is extension multiplication
                    self.compile_ext_mul_from_indices(
                        &alpha_pow_out_idx,
                        &alpha_pow_in_idx,
                        &alpha_idx,
                        ctx.as_deref_mut(),
                    );
                    
                     // Constraint 2 (matches recursion-core FriFoldChip):
                     //   (new_ro - old_ro) * (x - z) = (p_at_x - p_at_z) * old_alpha_pow
                     // where:
                     //   p_at_x := mat_opening[j]
                     //   p_at_z := ps_at_z[j]
                     //
                     // See `sp1/crates/recursion/core/src/chips/fri_fold.rs`:
                     //   (new_ro - old_ro) * (BinomialExtension::from_base(x) - z)
                     //     = (p_at_x - p_at_z) * old_alpha_pow
                    // Let diff_ro = ro_output - ro_input
                    // Let diff_p = mat_opening - ps_at_z
                    // Let z_minus_x = z - x (extension - felt, only affects first component)
                    // Then: diff_ro * z_minus_x = alpha_pow_input * diff_p
                    
                    // Compute diff_p = mat_opening - ps_at_z
                    let diff_p_idx: Vec<usize> =
                        (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                    for i in 0..4 {
                        let mut diff = SparseRow::new();
                        diff.add_term(mat_opening_idx[i], C::F::one());
                        diff.add_term(ps_at_z_idx[i], -C::F::one());
                        self.r1cs.add_constraint(
                            SparseRow::single(0),
                            diff,
                            SparseRow::single(diff_p_idx[i]),
                        );
                        if let Some(c) = ctx.as_deref_mut() {
                            c.set(diff_p_idx[i], c.get(mat_opening_idx[i]) - c.get(ps_at_z_idx[i]));
                        }
                    }
                    
                    // Compute rhs = alpha_pow_input * diff_p
                    let rhs_idx: Vec<usize> =
                        (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                    self.compile_ext_mul_from_indices(
                        &rhs_idx,
                        &alpha_pow_in_idx,
                        &diff_p_idx,
                        ctx.as_deref_mut(),
                    );
                    
                    // Compute diff_ro = ro_output - ro_input
                    let diff_ro_idx: Vec<usize> =
                        (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                    for i in 0..4 {
                        let mut diff = SparseRow::new();
                        diff.add_term(ro_out_idx[i], C::F::one());
                        diff.add_term(ro_in_idx[i], -C::F::one());
                        self.r1cs.add_constraint(
                            SparseRow::single(0),
                            diff,
                            SparseRow::single(diff_ro_idx[i]),
                        );
                        if let Some(c) = ctx.as_deref_mut() {
                            c.set(diff_ro_idx[i], c.get(ro_out_idx[i]) - c.get(ro_in_idx[i]));
                        }
                    }
                    
                     // Compute x_minus_z = (x - z) = BinomialExtension::from_base(x) - z.
                     // First component: x - z[0]
                     // Other components: -z[i]
                     let x_minus_z_idx: Vec<usize> =
                         (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                     let mut xmz0 = SparseRow::new();
                     xmz0.add_term(x_idx, C::F::one());
                     xmz0.add_term(z_idx[0], -C::F::one());
                     self.r1cs.add_constraint(
                         SparseRow::single(0),
                         xmz0,
                         SparseRow::single(x_minus_z_idx[0]),
                     );
                     if let Some(c) = ctx.as_deref_mut() {
                         c.set(x_minus_z_idx[0], c.get(x_idx) - c.get(z_idx[0]));
                     }
                     for i in 1..4 {
                         let mut neg = SparseRow::new();
                         neg.add_term(z_idx[i], -C::F::one());
                         self.r1cs.add_constraint(
                             SparseRow::single(0),
                             neg,
                             SparseRow::single(x_minus_z_idx[i]),
                         );
                         if let Some(c) = ctx.as_deref_mut() {
                             c.set(x_minus_z_idx[i], -c.get(z_idx[i]));
                         }
                     }
                    
                     // Constraint: diff_ro * x_minus_z = rhs
                    // This is extension multiplication check
                     self.compile_ext_mul_check_from_indices(
                         &diff_ro_idx,
                         &x_minus_z_idx,
                         &rhs_idx,
                         ctx.as_deref_mut(),
                     );
                }
            }
            
            // CircuitV2BatchFRI: Compute acc = sum(alpha_pows[i] * (p_at_zs[i] - p_at_xs[i]))
            DslIr::CircuitV2BatchFRI(boxed) => {
                let (acc, alpha_pows, p_at_zs, p_at_xs) = boxed.as_ref();
                let n = alpha_pows.len();
                
                // Allocate output accumulator
                let acc_idx: Vec<usize> = (0..4)
                    .map(|i| self.get_or_alloc(&format!("{}__{}", acc.id(), i), ctx.as_deref_mut()))
                    .collect();
                
                // Start with zero
                let mut running_sum_idx: Vec<usize> = (0..4).map(|_| {
                    let idx = self.alloc_var(ctx.as_deref_mut());
                    // Initialize to zero via constraint: 1 * 0 = idx
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        SparseRow::zero(),
                        SparseRow::single(idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(idx, C::F::zero());
                    }
                    idx
                }).collect();
                
                for j in 0..n {
                    // Get alpha_pow[j]
                    let alpha_pow_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_var(
                                &format!("{}__{}", alpha_pows[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    
                    // Get p_at_z[j]
                    let p_at_z_idx: Vec<usize> = (0..4)
                        .map(|i| {
                            self.get_var(
                                &format!("{}__{}", p_at_zs[j].id(), i),
                                ctx.as_deref_mut(),
                            )
                        })
                        .collect();
                    
                    // Get p_at_x[j] (this is a Felt, so it's just one component embedded in ext)
                    let p_at_x_idx = self.get_var(&p_at_xs[j].id(), ctx.as_deref_mut());
                    
                    // Compute diff = p_at_z - p_at_x (ext - felt)
                    let diff_idx: Vec<usize> =
                        (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                    // First component: p_at_z[0] - p_at_x
                    let mut diff0 = SparseRow::new();
                    diff0.add_term(p_at_z_idx[0], C::F::one());
                    diff0.add_term(p_at_x_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff0,
                        SparseRow::single(diff_idx[0]),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(diff_idx[0], c.get(p_at_z_idx[0]) - c.get(p_at_x_idx));
                    }
                    // Other components: p_at_z[i]
                    for i in 1..4 {
                        self.add_eq(diff_idx[i], p_at_z_idx[i]);
                        if let Some(c) = ctx.as_deref_mut() {
                            c.set(diff_idx[i], c.get(p_at_z_idx[i]));
                        }
                    }
                    
                    // Compute term = alpha_pow * diff
                    let term_idx: Vec<usize> =
                        (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                    self.compile_ext_mul_from_indices(
                        &term_idx,
                        &alpha_pow_idx,
                        &diff_idx,
                        ctx.as_deref_mut(),
                    );
                    
                    // Add to running sum: new_sum = running_sum + term
                    let new_sum_idx: Vec<usize> =
                        (0..4).map(|_| self.alloc_var(ctx.as_deref_mut())).collect();
                    for i in 0..4 {
                        let mut sum = SparseRow::new();
                        sum.add_term(running_sum_idx[i], C::F::one());
                        sum.add_term(term_idx[i], C::F::one());
                        self.r1cs.add_constraint(
                            SparseRow::single(0),
                            sum,
                            SparseRow::single(new_sum_idx[i]),
                        );
                        if let Some(c) = ctx.as_deref_mut() {
                            c.set(new_sum_idx[i], c.get(running_sum_idx[i]) + c.get(term_idx[i]));
                        }
                    }
                    running_sum_idx = new_sum_idx;
                }
                
                // Bind final sum to output accumulator
                for i in 0..4 {
                    self.add_eq(acc_idx[i], running_sum_idx[i]);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(acc_idx[i], c.get(running_sum_idx[i]));
                    }
                }
            }
            
             // CircuitV2ExpReverseBits: exponentiation driven by a bit stream.
             //
             // We match the recursion-core ExpReverseBitsLen chip recurrence:
             //   accum_0 = 1
             //   for bit in bits:
             //     multiplier = if bit==1 { base } else { 1 }
             //     accum = accum^2 * multiplier
             //
             // This avoids ambiguity about "reverse" ordering and matches the chip semantics
             // for the provided bit sequence.
            DslIr::CircuitV2ExpReverseBits(output, base, bits) => {
                let output_idx = self.get_or_alloc(&output.id(), ctx.as_deref_mut());
                let base_idx = self.get_var(&base.id(), ctx.as_deref_mut());
                let bit_indices: Vec<usize> =
                    bits.iter().map(|b| self.get_var(&b.id(), ctx.as_deref_mut())).collect();
                 
                 // accum starts at 1 (constant witness slot 0).
                 let mut accum_idx: usize = 0;
                 for bit_idx in bit_indices {
                     // Ensure bit is boolean.
                     self.add_boolean(bit_idx);
                     
                     // accum_sq = accum * accum
                     let accum_sq = self.alloc_var(ctx.as_deref_mut());
                     self.add_mul(accum_sq, accum_idx, accum_idx);
                     if let Some(c) = ctx.as_deref_mut() {
                         c.set(accum_sq, c.get(accum_idx) * c.get(accum_idx));
                     }
                     
                     // multiplier = bit ? base : 1
                     // Encode: (bit) * (base - 1) = (multiplier - 1)
                     let multiplier = self.alloc_var(ctx.as_deref_mut());
                     let mut base_minus_one = SparseRow::new();
                     base_minus_one.add_term(base_idx, C::F::one());
                     base_minus_one.add_term(0, -C::F::one()); // subtract 1
                     let mut mult_minus_one = SparseRow::new();
                     mult_minus_one.add_term(multiplier, C::F::one());
                     mult_minus_one.add_term(0, -C::F::one()); // subtract 1
                     self.r1cs.add_constraint(
                         SparseRow::single(bit_idx),
                         base_minus_one,
                         mult_minus_one,
                     );
                     if let Some(c) = ctx.as_deref_mut() {
                         // multiplier = bit*(base-1) + 1
                         c.set(
                             multiplier,
                             c.get(bit_idx) * (c.get(base_idx) - C::F::one()) + C::F::one(),
                         );
                     }
                     
                     // accum_next = accum_sq * multiplier
                     let accum_next = self.alloc_var(ctx.as_deref_mut());
                     self.add_mul(accum_next, accum_sq, multiplier);
                     if let Some(c) = ctx.as_deref_mut() {
                         c.set(accum_next, c.get(accum_sq) * c.get(multiplier));
                     }
                     accum_idx = accum_next;
                 }
                 
                 // Bind final accum to output.
                 self.add_eq(output_idx, accum_idx);
                 if let Some(c) = ctx.as_deref_mut() {
                     c.set(output_idx, c.get(accum_idx));
                 }
            }

            // === Witness operations ===
            DslIr::WitnessVar(dst, idx) => {
                let dst_idx = self.get_or_alloc(&dst.id(), ctx.as_deref_mut());
                // Track that this variable comes from witness
                while self.witness_vars.len() <= idx as usize {
                    self.witness_vars.push(0);
                }
                self.witness_vars[idx as usize] = dst_idx;
            }
            
            DslIr::WitnessFelt(dst, idx) => {
                let dst_idx = self.get_or_alloc(&dst.id(), ctx.as_deref_mut());
                while self.witness_felts.len() <= idx as usize {
                    self.witness_felts.push(0);
                }
                self.witness_felts[idx as usize] = dst_idx;
            }
            
            DslIr::WitnessExt(dst, idx) => {
                // Extension elements are 4 field elements
                for i in 0..4 {
                    let component_id = format!("{}__{}", dst.id(), i);
                    let dst_idx = self.get_or_alloc(&component_id, ctx.as_deref_mut());
                    let flat_idx = (idx as usize) * 4 + i;
                    while self.witness_exts.len() <= flat_idx {
                        self.witness_exts.push(0);
                    }
                    self.witness_exts[flat_idx] = dst_idx;
                }
            }

            // === Public input commitments ===
            DslIr::CircuitCommitVkeyHash(var) => {
                let var_idx = self.get_var(&var.id(), ctx.as_deref_mut());
                self.vkey_hash_idx = Some(var_idx);
                debug_assert!(
                    var_idx >= 1 && var_idx <= self.r1cs.num_public,
                    "CircuitCommitVkeyHash must refer to a public-input slot (idx={}, num_public={})",
                    var_idx,
                    self.r1cs.num_public
                );
            }
            
            DslIr::CircuitCommitCommittedValuesDigest(var) => {
                let var_idx = self.get_var(&var.id(), ctx.as_deref_mut());
                self.committed_values_digest_idx = Some(var_idx);
                debug_assert!(
                    var_idx >= 1 && var_idx <= self.r1cs.num_public,
                    "CircuitCommitCommittedValuesDigest must refer to a public-input slot (idx={}, num_public={})",
                    var_idx,
                    self.r1cs.num_public
                );
            }

            // === Extension field operations ===
            // These need to be expanded to base field operations
            DslIr::AddE(dst, lhs, rhs) => {
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i), ctx.as_deref_mut());
                    
                    let mut sum = SparseRow::new();
                    sum.add_term(lhs_idx, C::F::one());
                    sum.add_term(rhs_idx, C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        sum,
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, c.get(lhs_idx) + c.get(rhs_idx));
                    }
                }
            }
            
            DslIr::SubE(dst, lhs, rhs) => {
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i), ctx.as_deref_mut());
                    
                    let mut diff = SparseRow::new();
                    diff.add_term(lhs_idx, C::F::one());
                    diff.add_term(rhs_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff,
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, c.get(lhs_idx) - c.get(rhs_idx));
                    }
                }
            }
            
            DslIr::MulE(dst, lhs, rhs) => {
                // Extension field multiplication: F_p[u]/(u^4 - 11)
                // (a0 + a1*u + a2*u^2 + a3*u^3) * (b0 + b1*u + b2*u^2 + b3*u^3)
                self.compile_ext_mul(&dst, &lhs, &rhs, ctx.as_deref_mut());
            }
            
            DslIr::AddEF(dst, lhs, rhs) => {
                // Add base field element to extension (only affects first component)
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0), ctx.as_deref_mut());
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs0, C::F::one());
                sum.add_term(rhs_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst0),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst0, c.get(lhs0) + c.get(rhs_idx));
                }
                
                // Copy other components
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    self.add_eq(dst_i, lhs_i);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_i, c.get(lhs_i));
                    }
                }
            }
            
            DslIr::MulEF(dst, lhs, rhs) => {
                // Multiply extension by base field element
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                    self.add_mul(dst_idx, lhs_idx, rhs_idx);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, c.get(lhs_idx) * c.get(rhs_idx));
                    }
                }
            }
            
            // === Additional extension field operations with immediates ===
            DslIr::AddEI(dst, lhs, rhs) => {
                // Add extension + extension immediate
                let rhs_base = rhs.as_base_slice();
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let const_idx = self.alloc_const(rhs_base[i], ctx.as_deref_mut());
                    
                    let mut sum = SparseRow::new();
                    sum.add_term(lhs_idx, C::F::one());
                    sum.add_term(const_idx, C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        sum,
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, c.get(lhs_idx) + rhs_base[i]);
                    }
                }
            }
            
            DslIr::AddEFI(dst, lhs, rhs) => {
                // Add extension + field immediate (only affects first component)
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0), ctx.as_deref_mut());
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                
                let mut sum = SparseRow::new();
                sum.add_term(lhs0, C::F::one());
                sum.add_term(const_idx, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst0),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst0, c.get(lhs0) + rhs);
                }
                
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    self.add_eq(dst_i, lhs_i);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_i, c.get(lhs_i));
                    }
                }
            }
            
            DslIr::AddEFFI(dst, lhs, rhs) => {
                // Add felt + extension immediate: dst = felt + ext_imm
                let rhs_base = rhs.as_base_slice();
                let lhs_idx = self.get_var(&lhs.id(), ctx.as_deref_mut());
                
                // First component: dst[0] = lhs + rhs[0]
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0), ctx.as_deref_mut());
                let const0 = self.alloc_const(rhs_base[0], ctx.as_deref_mut());
                let mut sum = SparseRow::new();
                sum.add_term(lhs_idx, C::F::one());
                sum.add_term(const0, C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    sum,
                    SparseRow::single(dst0),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst0, c.get(lhs_idx) + rhs_base[0]);
                }
                
                // Other components: dst[i] = rhs[i]
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let const_i = self.alloc_const(rhs_base[i], ctx.as_deref_mut());
                    self.add_eq(dst_i, const_i);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_i, rhs_base[i]);
                    }
                }
            }
            
            DslIr::SubEI(dst, lhs, rhs) => {
                // Subtract extension - extension immediate
                let rhs_base = rhs.as_base_slice();
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let const_idx = self.alloc_const(rhs_base[i], ctx.as_deref_mut());
                    
                    let mut diff = SparseRow::new();
                    diff.add_term(lhs_idx, C::F::one());
                    diff.add_term(const_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff,
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, c.get(lhs_idx) - rhs_base[i]);
                    }
                }
            }
            
            DslIr::SubEIN(dst, lhs, rhs) => {
                // Subtract extension immediate - extension: dst = lhs_imm - rhs
                let lhs_base = lhs.as_base_slice();
                for i in 0..4 {
                    let dst_idx = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let rhs_idx = self.get_var(&format!("{}__{}", rhs.id(), i), ctx.as_deref_mut());
                    let const_idx = self.alloc_const(lhs_base[i], ctx.as_deref_mut());
                    
                    let mut diff = SparseRow::new();
                    diff.add_term(const_idx, C::F::one());
                    diff.add_term(rhs_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        diff,
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, lhs_base[i] - c.get(rhs_idx));
                    }
                }
            }
            
            DslIr::SubEF(dst, lhs, rhs) => {
                // Subtract extension - felt (only affects first component)
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0), ctx.as_deref_mut());
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0), ctx.as_deref_mut());
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs0, C::F::one());
                diff.add_term(rhs_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst0),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst0, c.get(lhs0) - c.get(rhs_idx));
                }
                
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    self.add_eq(dst_i, lhs_i);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_i, c.get(lhs_i));
                    }
                }
            }
            
            DslIr::SubEFI(dst, lhs, rhs) => {
                // Subtract extension - field immediate
                let dst0 = self.get_or_alloc(&format!("{}__{}", dst.id(), 0), ctx.as_deref_mut());
                let lhs0 = self.get_var(&format!("{}__{}", lhs.id(), 0), ctx.as_deref_mut());
                let const_idx = self.alloc_const(rhs, ctx.as_deref_mut());
                
                let mut diff = SparseRow::new();
                diff.add_term(lhs0, C::F::one());
                diff.add_term(const_idx, -C::F::one());
                self.r1cs.add_constraint(
                    SparseRow::single(0),
                    diff,
                    SparseRow::single(dst0),
                );
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(dst0, c.get(lhs0) - rhs);
                }
                
                for i in 1..4 {
                    let dst_i = self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_i = self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    self.add_eq(dst_i, lhs_i);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_i, c.get(lhs_i));
                    }
                }
            }
            
            DslIr::MulEI(dst, lhs, rhs) => {
                // Multiply extension * extension immediate
                // This requires full extension multiplication with constant
                let rhs_base = rhs.as_base_slice();
                let nr = C::F::from_canonical_u64(11);
                
                let a: Vec<usize> = (0..4)
                    .map(|i| self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut()))
                    .collect();
                let c: Vec<usize> = (0..4)
                    .map(|i| self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut()))
                    .collect();
                
                // c[k] = sum_{i+j=k} a[i]*b[j] + 11 * sum_{i+j=k+4} a[i]*b[j]
                // where b[j] are constants
                for k in 0..4 {
                    let mut terms = SparseRow::new();
                    for i in 0..4 {
                        for j in 0..4 {
                            let idx = i + j;
                            let coeff = if idx == k {
                                rhs_base[j]
                            } else if idx == k + 4 {
                                nr * rhs_base[j]
                            } else {
                                C::F::zero()
                            };
                            if coeff != C::F::zero() {
                                terms.add_term(a[i], coeff);
                            }
                        }
                    }
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        terms,
                        SparseRow::single(c[k]),
                    );
                }
                if let Some(w) = ctx.as_deref_mut() {
                    // Compute output using the same reduction rule (u^4 = 11).
                    let a0 = w.get(a[0]);
                    let a1 = w.get(a[1]);
                    let a2 = w.get(a[2]);
                    let a3 = w.get(a[3]);
                    let b0 = rhs_base[0];
                    let b1 = rhs_base[1];
                    let b2 = rhs_base[2];
                    let b3 = rhs_base[3];
                    w.set(c[0], a0 * b0 + nr * (a1 * b3 + a2 * b2 + a3 * b1));
                    w.set(c[1], a0 * b1 + a1 * b0 + nr * (a2 * b3 + a3 * b2));
                    w.set(c[2], a0 * b2 + a1 * b1 + a2 * b0 + nr * (a3 * b3));
                    w.set(c[3], a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0);
                }
            }
            
            DslIr::MulEFI(dst, lhs, rhs) => {
                // Multiply extension * field immediate
                for i in 0..4 {
                    let dst_idx =
                        self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx =
                        self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    
                    // dst[i] = lhs[i] * rhs (constant)
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        SparseRow::single_with_coeff(lhs_idx, rhs),
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, c.get(lhs_idx) * rhs);
                    }
                }
            }
            
            DslIr::DivEI(dst, lhs, rhs) => {
                // Divide extension / extension immediate
                // dst = lhs / rhs, so dst * rhs = lhs
                // Since rhs is constant, we can compute rhs^(-1) and multiply
                // But for R1CS, we just verify: dst * rhs_const = lhs
                let rhs_base = rhs.as_base_slice();
                let nr = C::F::from_canonical_u64(11);
                
                let d: Vec<usize> = (0..4)
                    .map(|i| self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut()))
                    .collect();
                let l: Vec<usize> = (0..4)
                    .map(|i| self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut()))
                    .collect();

                // Compute witness for dst = lhs / rhs_const (deterministically).
                if let Some(w) = ctx.as_deref_mut() {
                    let lhs_vals = [w.get(l[0]), w.get(l[1]), w.get(l[2]), w.get(l[3])];
                    let rhs_vals = [rhs_base[0], rhs_base[1], rhs_base[2], rhs_base[3]];
                    let out = Self::ext4_div_vals(lhs_vals, rhs_vals)
                        .unwrap_or_else(|| panic!("DivEI: non-invertible rhs immediate for {}", dst.id()));
                    for i in 0..4 {
                        w.set(d[i], out[i]);
                    }
                }
                
                // Verify dst * rhs_const = lhs using extension multiplication
                // product[k] = sum_{i+j=k} d[i]*rhs[j] + 11 * sum_{i+j=k+4} d[i]*rhs[j]
                for k in 0..4 {
                    let mut terms = SparseRow::new();
                    for i in 0..4 {
                        for j in 0..4 {
                            let idx = i + j;
                            let coeff = if idx == k {
                                rhs_base[j]
                            } else if idx == k + 4 {
                                nr * rhs_base[j]
                            } else {
                                C::F::zero()
                            };
                            if coeff != C::F::zero() {
                                terms.add_term(d[i], coeff);
                            }
                        }
                    }
                    // terms = lhs[k]
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        terms,
                        SparseRow::single(l[k]),
                    );
                }
            }
            
            DslIr::DivEIN(dst, lhs, rhs) => {
                // Divide extension immediate / extension: dst = lhs_imm / rhs
                // dst * rhs = lhs_imm
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                }
                
                // We need to allocate constant extension and check dst * rhs = const
                let lhs_slice = lhs.as_base_slice();
                let lhs_base: [C::F; 4] = [lhs_slice[0], lhs_slice[1], lhs_slice[2], lhs_slice[3]];
                // Compute witness for dst = lhs_imm / rhs.
                if let Some(w) = ctx.as_deref_mut() {
                    let r: Vec<usize> = (0..4)
                        .map(|i| self.get_var(&format!("{}__{}", rhs.id(), i), Some(w)))
                        .collect();
                    let rhs_vals = [w.get(r[0]), w.get(r[1]), w.get(r[2]), w.get(r[3])];
                    let out = Self::ext4_div_vals(lhs_base, rhs_vals)
                        .unwrap_or_else(|| panic!("DivEIN: non-invertible rhs for {}", dst.id()));
                    for i in 0..4 {
                        let di = self.get_var(&format!("{}__{}", dst.id(), i), Some(w));
                        w.set(di, out[i]);
                    }
                }
                self.compile_ext_mul_check_const(&dst, &rhs, &lhs_base, ctx.as_deref_mut());
            }
            
            DslIr::DivEF(dst, lhs, rhs) => {
                // Divide extension / felt: dst = lhs / rhs
                // dst * rhs = lhs (component-wise since rhs is base field)
                let rhs_idx = self.get_var(&rhs.id(), ctx.as_deref_mut());
                let inv_rhs = if let Some(w) = ctx.as_deref_mut() {
                    Some(
                        w.get(rhs_idx)
                            .try_inverse()
                            .unwrap_or_else(|| panic!("DivEF: non-invertible rhs for {}", dst.id())),
                    )
                } else {
                    None
                };

                for i in 0..4 {
                    // IMPORTANT: allocate dst index exactly once and reuse for witness + constraints.
                    let dst_idx =
                        self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx =
                        self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());

                    // dst[i] * rhs = lhs[i]
                    self.r1cs.add_constraint(
                        SparseRow::single(dst_idx),
                        SparseRow::single(rhs_idx),
                        SparseRow::single(lhs_idx),
                    );

                    if let (Some(w), Some(inv)) = (ctx.as_deref_mut(), inv_rhs) {
                        w.set(dst_idx, w.get(lhs_idx) * inv);
                    }
                }
            }
            
            DslIr::DivEFI(dst, lhs, rhs) => {
                // Divide extension / field immediate
                // dst[i] = lhs[i] / rhs = lhs[i] * rhs^(-1)
                // Verify: dst[i] * rhs = lhs[i]
                let inv_rhs = if let Some(_w) = ctx.as_deref_mut() {
                    Some(
                        rhs.try_inverse()
                            .unwrap_or_else(|| panic!("DivEFI: non-invertible rhs immediate for {}", dst.id())),
                    )
                } else {
                    None
                };
                for i in 0..4 {
                    let dst_idx =
                        self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let lhs_idx =
                        self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    
                    // dst[i] * rhs_const = lhs[i]
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        SparseRow::single_with_coeff(dst_idx, rhs),
                        SparseRow::single(lhs_idx),
                    );

                    if let (Some(w), Some(inv)) = (ctx.as_deref_mut(), inv_rhs) {
                        w.set(dst_idx, w.get(lhs_idx) * inv);
                    }
                }
            }
            
            DslIr::DivEFIN(dst, lhs, rhs) => {
                // Divide field immediate / extension: dst = lhs_imm / rhs
                // dst * rhs = (lhs_imm, 0, 0, 0)
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                }
                let lhs_base = [lhs, C::F::zero(), C::F::zero(), C::F::zero()];
                self.compile_ext_mul_check_const(&dst, &rhs, &lhs_base, ctx.as_deref_mut());
            }
            
            DslIr::NegE(dst, src) => {
                for i in 0..4 {
                    let dst_idx =
                        self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                    let src_idx =
                        self.get_var(&format!("{}__{}", src.id(), i), ctx.as_deref_mut());
                    
                    let mut neg = SparseRow::new();
                    neg.add_term(src_idx, -C::F::one());
                    self.r1cs.add_constraint(
                        SparseRow::single(0),
                        neg,
                        SparseRow::single(dst_idx),
                    );
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(dst_idx, -c.get(src_idx));
                    }
                }
            }
            
            DslIr::InvE(dst, src) => {
                // Extension inverse: hint + multiplication check
                // Hint provides dst, we verify dst * src = 1
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                }
                if let Some(w) = ctx.as_deref_mut() {
                    let s: Vec<usize> = (0..4)
                        .map(|i| self.get_var(&format!("{}__{}", src.id(), i), Some(w)))
                        .collect();
                    let src_vals = [w.get(s[0]), w.get(s[1]), w.get(s[2]), w.get(s[3])];
                    let inv = Self::ext4_inv_vals(src_vals)
                        .unwrap_or_else(|| panic!("InvE: non-invertible src for {}", dst.id()));
                    for i in 0..4 {
                        let di = self.get_var(&format!("{}__{}", dst.id(), i), Some(w));
                        w.set(di, inv[i]);
                    }
                }
                
                // dst * src should equal (1, 0, 0, 0)
                self.compile_ext_mul_and_check_one(&dst, &src, ctx.as_deref_mut());
            }
            
            DslIr::DivE(dst, lhs, rhs) => {
                // dst = lhs / rhs = lhs * rhs^(-1)
                // Hint dst, verify dst * rhs = lhs
                for i in 0..4 {
                    self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut());
                }
                if let Some(w) = ctx.as_deref_mut() {
                    let l: Vec<usize> = (0..4)
                        .map(|i| self.get_var(&format!("{}__{}", lhs.id(), i), Some(w)))
                        .collect();
                    let r: Vec<usize> = (0..4)
                        .map(|i| self.get_var(&format!("{}__{}", rhs.id(), i), Some(w)))
                        .collect();
                    let lhs_vals = [w.get(l[0]), w.get(l[1]), w.get(l[2]), w.get(l[3])];
                    let rhs_vals = [w.get(r[0]), w.get(r[1]), w.get(r[2]), w.get(r[3])];
                    let out = Self::ext4_div_vals(lhs_vals, rhs_vals)
                        .unwrap_or_else(|| panic!("DivE: non-invertible rhs for {}", dst.id()));
                    for i in 0..4 {
                        let di = self.get_var(&format!("{}__{}", dst.id(), i), Some(w));
                        w.set(di, out[i]);
                    }
                }
                self.compile_ext_mul_check(&dst, &rhs, &lhs, ctx.as_deref_mut());
            }
            
            DslIr::AssertEqE(lhs, rhs) => {
                for i in 0..4 {
                    let lhs_idx =
                        self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let rhs_idx =
                        self.get_var(&format!("{}__{}", rhs.id(), i), ctx.as_deref_mut());
                    self.add_eq(lhs_idx, rhs_idx);
                }
            }
            
            DslIr::AssertEqEI(lhs, rhs) => {
                let rhs_base = rhs.as_base_slice();
                for i in 0..4 {
                    let lhs_idx =
                        self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut());
                    let const_idx = self.alloc_const(rhs_base[i], ctx.as_deref_mut());
                    self.add_eq(lhs_idx, const_idx);
                }
            }
            
            DslIr::CircuitExt2Felt(felts, ext) => {
                // Extract 4 felt components from extension
                for i in 0..4 {
                    let felt_idx = self.get_or_alloc(&felts[i].id(), ctx.as_deref_mut());
                    let ext_idx =
                        self.get_var(&format!("{}__{}", ext.id(), i), ctx.as_deref_mut());
                    self.add_eq(felt_idx, ext_idx);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(felt_idx, c.get(ext_idx));
                    }
                }
            }
            
            DslIr::CircuitFelts2Ext(felts, ext) => {
                // Pack 4 felts into extension
                for i in 0..4 {
                    let ext_idx =
                        self.get_or_alloc(&format!("{}__{}", ext.id(), i), ctx.as_deref_mut());
                    let felt_idx = self.get_var(&felts[i].id(), ctx.as_deref_mut());
                    self.add_eq(ext_idx, felt_idx);
                    if let Some(c) = ctx.as_deref_mut() {
                        c.set(ext_idx, c.get(felt_idx));
                    }
                }
            }

            // === CircuitV2 public values commitment ===
            //
            // This is how SP1 recursion circuits expose their public values in BabyBear-native mode.
            // We treat a minimal subset of these public values as *R1CS public inputs* by
            // preallocating them in Phase 0 (see `phase0_collect_public_ids`).
            //
            // Here we only sanity-check that the referenced variable IDs indeed occupy public-input
            // slots (indices 1..=num_public). No extra constraints are needed: these variables are
            // already constrained elsewhere by the recursion verifier logic.
            DslIr::CircuitV2CommitPublicValues(public_values) => {
                for felt in public_values.digest.iter() {
                    let idx = self.get_var(&felt.id(), ctx.as_deref_mut());
                    debug_assert!(
                        idx >= 1 && idx <= self.r1cs.num_public,
                        "CircuitV2CommitPublicValues(digest) must refer to a public-input slot (idx={}, num_public={})",
                        idx,
                        self.r1cs.num_public
                    );
                }
            }
            
            DslIr::CircuitFelt2Var(felt, var) => {
                let felt_idx = self.get_var(&felt.id(), ctx.as_deref_mut());
                let var_idx = self.get_or_alloc(&var.id(), ctx.as_deref_mut());
                self.add_eq(var_idx, felt_idx);
                if let Some(c) = ctx.as_deref_mut() {
                    c.set(var_idx, c.get(felt_idx));
                }
            }
            
            DslIr::ReduceE(_ext) => {
                // Reduce extension field element (no-op in R1CS, just tracks the variable)
                // The reduction is implicit in how we handle values
            }

            // === Parallel blocks ===
            DslIr::Parallel(blocks) => {
                for block in blocks {
                    for op in block.ops {
                        self.compile_one_inner(op, ctx.as_deref_mut());
                    }
                }
            }

            // === Ignored operations (debug/instrumentation) ===
            DslIr::CycleTracker(_) 
            | DslIr::CycleTrackerV2Enter(_) 
            | DslIr::CycleTrackerV2Exit
            | DslIr::DebugBacktrace(_)
            | DslIr::PrintV(_)
            | DslIr::PrintF(_)
            | DslIr::PrintE(_)
            | DslIr::Halt
            | DslIr::Error() => {
                // These are debug/instrumentation/control, no R1CS needed
            }
            
            // === CircuitV2HintAddCurve: Elliptic curve point addition hint ===
            // SepticCurve has x, y fields each with 7 Felt components (SepticExtension).
            DslIr::CircuitV2HintAddCurve(boxed) => {
                // `CircuitV2Builder::add_curve_v2` constrains the hinted sum via sum-checker identities.
                // The IR only carries the hint op; therefore the R1CS backend must implement these
                // constraints here (otherwise the hint is an unconstrained degree of freedom).
                let (sum, p1, p2) = boxed.as_ref();

                // Allocate + assign all 14 felts for sum (7 for x, 7 for y) from runtime memory.
                let mut sum_x = [0usize; 7];
                let mut sum_y = [0usize; 7];
                for (i, felt) in sum.x.0.iter().enumerate() {
                    let id = felt.id();
                    let idx = self.get_or_alloc(&id, ctx.as_deref_mut());
                    sum_x[i] = idx;
                    if let Some(c) = ctx.as_deref_mut() {
                        let v = (c.get_value)(&id).unwrap_or_else(|| {
                            panic!(
                                "R1CS witness: CircuitV2HintAddCurve needs runtime value for '{}', but get_value returned None",
                                id
                            )
                        });
                        c.set(idx, v);
                    }
                }
                for (i, felt) in sum.y.0.iter().enumerate() {
                    let id = felt.id();
                    let idx = self.get_or_alloc(&id, ctx.as_deref_mut());
                    sum_y[i] = idx;
                    if let Some(c) = ctx.as_deref_mut() {
                        let v = (c.get_value)(&id).unwrap_or_else(|| {
                            panic!(
                                "R1CS witness: CircuitV2HintAddCurve needs runtime value for '{}', but get_value returned None",
                                id
                            )
                        });
                        c.set(idx, v);
                    }
                }

                // Read p1/p2 coordinates (must already exist / be constrained elsewhere).
                let mut p1_x = [0usize; 7];
                let mut p1_y = [0usize; 7];
                let mut p2_x = [0usize; 7];
                let mut p2_y = [0usize; 7];
                for i in 0..7 {
                    p1_x[i] = self.get_var(&p1.x.0[i].id(), ctx.as_deref_mut());
                    p1_y[i] = self.get_var(&p1.y.0[i].id(), ctx.as_deref_mut());
                    p2_x[i] = self.get_var(&p2.x.0[i].id(), ctx.as_deref_mut());
                    p2_y[i] = self.get_var(&p2.y.0[i].id(), ctx.as_deref_mut());
                }

                // Enforce sum-checkers to be zero:
                // sum_checker_x = (x1+x2+x3)*(x2-x1)^2 - (y2-y1)^2
                // sum_checker_y = (y1+y3)*(x2-x1) - (y2-y1)*(x1-x3)
                let x1_plus_x2 = self.septic_add(&p1_x, &p2_x, ctx.as_deref_mut());
                let x1_plus_x2_plus_x3 = self.septic_add(&x1_plus_x2, &sum_x, ctx.as_deref_mut());
                let x2_minus_x1 = self.septic_sub(&p2_x, &p1_x, ctx.as_deref_mut());
                let x2_minus_x1_sq = self.septic_mul(&x2_minus_x1, &x2_minus_x1, ctx.as_deref_mut());
                let lhs_x = self.septic_mul(&x1_plus_x2_plus_x3, &x2_minus_x1_sq, ctx.as_deref_mut());
                let y2_minus_y1 = self.septic_sub(&p2_y, &p1_y, ctx.as_deref_mut());
                let y2_minus_y1_sq = self.septic_mul(&y2_minus_y1, &y2_minus_y1, ctx.as_deref_mut());
                let scx = self.septic_sub(&lhs_x, &y2_minus_y1_sq, ctx.as_deref_mut());

                let y1_plus_y3 = self.septic_add(&p1_y, &sum_y, ctx.as_deref_mut());
                let lhs_y = self.septic_mul(&y1_plus_y3, &x2_minus_x1, ctx.as_deref_mut());
                let x1_minus_x3 = self.septic_sub(&p1_x, &sum_x, ctx.as_deref_mut());
                let rhs_y = self.septic_mul(&y2_minus_y1, &x1_minus_x3, ctx.as_deref_mut());
                let scy = self.septic_sub(&lhs_y, &rhs_y, ctx.as_deref_mut());

                // Constrain all coefficients to zero: (1) * coeff = 0.
                for i in 0..7 {
                    self.r1cs.add_constraint(SparseRow::single(0), SparseRow::single(scx[i]), SparseRow::zero());
                    self.r1cs.add_constraint(SparseRow::single(0), SparseRow::single(scy[i]), SparseRow::zero());
                }
            }
            
            // === Catch-all for remaining unhandled variants ===
            // These are variants not used by the shrink verifier circuit.
            DslIr::SubVI(..) => panic!("Unhandled DslIr: SubVI"),
            DslIr::SubVIN(..) => panic!("Unhandled DslIr: SubVIN"),
            DslIr::For(..) => panic!("Unhandled DslIr: For (control flow not supported in R1CS)"),
            DslIr::IfEq(..) => panic!("Unhandled DslIr: IfEq"),
            DslIr::IfNe(..) => panic!("Unhandled DslIr: IfNe"),
            DslIr::IfEqI(..) => panic!("Unhandled DslIr: IfEqI"),
            DslIr::IfNeI(..) => panic!("Unhandled DslIr: IfNeI"),
            DslIr::Break => panic!("Unhandled DslIr: Break"),
            DslIr::AssertNeE(..) => panic!("Unhandled DslIr: AssertNeE"),
            DslIr::AssertNeEI(..) => panic!("Unhandled DslIr: AssertNeEI"),
            DslIr::Alloc(..) => panic!("Unhandled DslIr: Alloc (memory ops not supported)"),
            DslIr::LoadV(..) => panic!("Unhandled DslIr: LoadV"),
            DslIr::LoadF(..) => panic!("Unhandled DslIr: LoadF"),
            DslIr::LoadE(..) => panic!("Unhandled DslIr: LoadE"),
            DslIr::StoreV(..) => panic!("Unhandled DslIr: StoreV"),
            DslIr::StoreF(..) => panic!("Unhandled DslIr: StoreF"),
            DslIr::StoreE(..) => panic!("Unhandled DslIr: StoreE"),
            DslIr::Poseidon2PermuteBabyBear(..) => panic!("Unhandled DslIr: Poseidon2PermuteBabyBear (use CircuitV2 variant)"),
            DslIr::Poseidon2CompressBabyBear(..) => panic!("Unhandled DslIr: Poseidon2CompressBabyBear"),
            DslIr::Poseidon2AbsorbBabyBear(..) => panic!("Unhandled DslIr: Poseidon2AbsorbBabyBear"),
            DslIr::Poseidon2FinalizeBabyBear(..) => panic!("Unhandled DslIr: Poseidon2FinalizeBabyBear"),
            DslIr::HintBitsU(..) => panic!("Unhandled DslIr: HintBitsU"),
            DslIr::HintBitsV(..) => panic!("Unhandled DslIr: HintBitsV"),
            DslIr::HintBitsF(..) => panic!("Unhandled DslIr: HintBitsF"),
            DslIr::HintExt2Felt(..) => panic!("Unhandled DslIr: HintExt2Felt"),
            DslIr::HintLen(..) => panic!("Unhandled DslIr: HintLen"),
            DslIr::HintVars(..) => panic!("Unhandled DslIr: HintVars"),
            DslIr::HintFelts(..) => panic!("Unhandled DslIr: HintFelts"),
            DslIr::HintExts(..) => panic!("Unhandled DslIr: HintExts"),
            DslIr::Commit(..) => panic!("Unhandled DslIr: Commit"),
            DslIr::RegisterPublicValue(..) => panic!("Unhandled DslIr: RegisterPublicValue"),
            DslIr::FriFold(..) => panic!("Unhandled DslIr: FriFold (use CircuitV2FriFold)"),
            DslIr::LessThan(..) => panic!("Unhandled DslIr: LessThan"),
            DslIr::ExpReverseBitsLen(..) => panic!("Unhandled DslIr: ExpReverseBitsLen (use CircuitV2ExpReverseBits)")
        }
    }

    /// Compile extension field multiplication
    fn compile_ext_mul(
        &mut self,
        dst: &Ext<C::F, C::EF>,
        lhs: &Ext<C::F, C::EF>,
        rhs: &Ext<C::F, C::EF>,
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        // F_p[u]/(u^4 - 11)
        // Result[k] = sum_{i+j=k} a[i]*b[j] + 11 * sum_{i+j=k+4} a[i]*b[j]
        let nr = C::F::from_canonical_u64(11);
        
        let a: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", lhs.id(), i), ctx.as_deref_mut()))
            .collect();
        let b: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", rhs.id(), i), ctx.as_deref_mut()))
            .collect();
        let c: Vec<usize> = (0..4)
            .map(|i| self.get_or_alloc(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut()))
            .collect();
        
        // We need intermediate products
        // a[i] * b[j] for all i, j in 0..4
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var(ctx.as_deref_mut());
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
                if let Some(w) = ctx.as_deref_mut() {
                    w.set(prod_idx, w.get(a[i]) * w.get(b[j]));
                }
            }
        }
        
        // Now compute each output component
        for k in 0..4 {
            // c[k] = sum of terms
            let mut terms = SparseRow::new();
            let mut acc_val = C::F::zero();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                        if let Some(w) = ctx.as_deref_mut() {
                            acc_val += w.get(products[i][j]);
                        }
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                        if let Some(w) = ctx.as_deref_mut() {
                            acc_val += nr * w.get(products[i][j]);
                        }
                    }
                }
            }
            
            // c[k] = terms (linear combination)
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
            if let Some(w) = ctx.as_deref_mut() {
                w.set(c[k], acc_val);
            }
        }
    }

    /// Compile extension multiplication and check result equals (1, 0, 0, 0)
    fn compile_ext_mul_and_check_one(
        &mut self,
        dst: &Ext<C::F, C::EF>,
        src: &Ext<C::F, C::EF>,
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        // dst * src = 1
        // Allocate result components and check
        let nr = C::F::from_canonical_u64(11);
        
        let a: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", dst.id(), i), ctx.as_deref_mut()))
            .collect();
        let b: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", src.id(), i), ctx.as_deref_mut()))
            .collect();
        
        // Products
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var(ctx.as_deref_mut());
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
                if let Some(w) = ctx.as_deref_mut() {
                    w.set(prod_idx, w.get(a[i]) * w.get(b[j]));
                }
            }
        }
        
        // Check each component
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // c[0] should be 1, c[1..4] should be 0
            let expected = if k == 0 { C::F::one() } else { C::F::zero() };
            
            // terms = expected
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::constant(expected),
            );
        }
    }

    /// Compile extension multiplication check: a * b = c
    fn compile_ext_mul_check(
        &mut self,
        a: &Ext<C::F, C::EF>,
        b: &Ext<C::F, C::EF>,
        c: &Ext<C::F, C::EF>,
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        let nr = C::F::from_canonical_u64(11);
        
        let a_vars: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", a.id(), i), ctx.as_deref_mut()))
            .collect();
        let b_vars: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", b.id(), i), ctx.as_deref_mut()))
            .collect();
        let c_vars: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", c.id(), i), ctx.as_deref_mut()))
            .collect();
        
        // Products
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var(ctx.as_deref_mut());
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a_vars[i], b_vars[j]);
                if let Some(w) = ctx.as_deref_mut() {
                    w.set(prod_idx, w.get(a_vars[i]) * w.get(b_vars[j]));
                }
            }
        }
        
        // Check each component equals c
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // terms = c[k]
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c_vars[k]),
            );
        }
    }

    /// Compile extension multiplication check: a * b = c_const (where c is a constant)
    fn compile_ext_mul_check_const(
        &mut self,
        a: &Ext<C::F, C::EF>,
        b: &Ext<C::F, C::EF>,
        c_const: &[C::F; 4],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        let nr = C::F::from_canonical_u64(11);
        
        let a_vars: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", a.id(), i), ctx.as_deref_mut()))
            .collect();
        let b_vars: Vec<usize> = (0..4)
            .map(|i| self.get_var(&format!("{}__{}", b.id(), i), ctx.as_deref_mut()))
            .collect();
        
        // Products
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var(ctx.as_deref_mut());
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a_vars[i], b_vars[j]);
                if let Some(w) = ctx.as_deref_mut() {
                    w.set(prod_idx, w.get(a_vars[i]) * w.get(b_vars[j]));
                }
            }
        }
        
        // Check each component equals c_const
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            
            // terms = c_const[k]
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::constant(c_const[k]),
            );
        }
    }

    /// Compile extension multiplication from raw indices: c = a * b
    fn compile_ext_mul_from_indices(
        &mut self,
        c: &[usize],
        a: &[usize],
        b: &[usize],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        let nr = C::F::from_canonical_u64(11);
        
        // Products: a[i] * b[j]
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var(ctx.as_deref_mut());
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
                if let Some(w) = ctx.as_deref_mut() {
                    w.set(prod_idx, w.get(a[i]) * w.get(b[j]));
                }
            }
        }
        
        // Compute each output component
        for k in 0..4 {
            let mut terms = SparseRow::new();
            let mut acc_val = C::F::zero();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                        if let Some(w) = ctx.as_deref_mut() {
                            acc_val += w.get(products[i][j]);
                        }
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                        if let Some(w) = ctx.as_deref_mut() {
                            acc_val += nr * w.get(products[i][j]);
                        }
                    }
                }
            }
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
            if let Some(w) = ctx.as_deref_mut() {
                w.set(c[k], acc_val);
            }
        }
    }

    /// Compile extension multiplication check from raw indices: a * b = c
    fn compile_ext_mul_check_from_indices(
        &mut self,
        a: &[usize],
        b: &[usize],
        c: &[usize],
        mut ctx: Option<&mut WitnessCtx<'_, C::F>>,
    ) {
        let nr = C::F::from_canonical_u64(11);
        
        // Products: a[i] * b[j]
        let mut products = [[0usize; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                let prod_idx = self.alloc_var(ctx.as_deref_mut());
                products[i][j] = prod_idx;
                self.add_mul(prod_idx, a[i], b[j]);
                if let Some(w) = ctx.as_deref_mut() {
                    w.set(prod_idx, w.get(a[i]) * w.get(b[j]));
                }
            }
        }
        
        // Check each component equals c[k]
        for k in 0..4 {
            let mut terms = SparseRow::new();
            for i in 0..4 {
                for j in 0..4 {
                    let idx = i + j;
                    if idx == k {
                        terms.add_term(products[i][j], C::F::one());
                    } else if idx == k + 4 {
                        terms.add_term(products[i][j], nr);
                    }
                }
            }
            self.r1cs.add_constraint(
                SparseRow::single(0),
                terms,
                SparseRow::single(c[k]),
            );
        }
    }

    /// Compile all operations and **also** generate a full witness vector by executing the
    /// same lowering semantics that emit the constraints.
    ///
    /// This is the deterministic alternative to "completing" a partial witness by solving the
    /// finished R1CS.
    ///
    /// ## Two-Phase Compilation
    ///
    /// The DSL IR may contain forward references: operations that USE hint variables BEFORE
    /// the CircuitV2HintFelts/Exts operations that DEFINE them. One-pass compilation would
    /// compute derived values with zeros (forward-referenced witness = 0), producing wrong
    /// intermediate values.
    ///
    /// We solve this with a two-phase approach:
    /// 1. **Phase 1**: Pre-consume ALL hints into maps (no allocations, preserves SSA semantics).
    ///    Also build a set of hint-sourced IDs so `read_id` knows which variables should get
    ///    their values from hint maps vs runtime memory.
    /// 2. **Phase 2**: Compile normally. When `read_id` encounters a forward-referenced variable:
    ///    - If hint-sourced: populate witness from pre-consumed hint maps
    ///    - Otherwise: populate from `get_value` (runtime memory)
    ///    Hint ops pull values from the maps (already consumed) instead of live stream.
    ///
    /// This ensures hint-sourced variables have correct values when operations use them,
    /// while preserving allocation order (SSA semantics) and supporting non-hint variables.
    pub fn compile_with_witness(
        operations: Vec<DslIr<C>>,
        get_value: &mut dyn FnMut(&str) -> Option<C::F>,
        next_hint_felt: &mut dyn FnMut() -> Option<C::F>,
        next_hint_ext: &mut dyn FnMut() -> Option<[C::F; 4]>,
    ) -> (Self, Vec<C::F>) {
        // =====================================================================
        // PHASE 0: Pre-scan for public inputs (commitments) and preallocate them
        // =====================================================================
        let mut public_ids: Vec<String> = Vec::new();
        let mut public_seen: HashSet<String> = HashSet::new();
        Self::phase0_collect_public_ids(&operations, &mut public_ids, &mut public_seen);

        // =====================================================================
        // PHASE 1: Pre-consume hints into per-ID FIFO queues (no allocations)
        // =====================================================================
        let mut hint_felt_values: HashMap<String, VecDeque<C::F>> = HashMap::new();
        let mut hint_ext_values: HashMap<String, VecDeque<[C::F; 4]>> = HashMap::new();
        let mut hinted_ids: HashSet<String> = HashSet::new();
        
        Self::phase1_preconsume_hints(
            &operations,
            next_hint_felt,
            next_hint_ext,
            &mut hint_felt_values,
            &mut hint_ext_values,
            &mut hinted_ids,
        );

        // =====================================================================
        // PHASE 2: Compile normally with hint queues populated
        // =====================================================================
        let mut compiler = Self::new();
        let mut witness: Vec<C::F> = vec![C::F::one()]; // index 0 = constant 1
        let mut ctx = WitnessCtx {
            witness: &mut witness,
            get_value,
            next_hint_felt,
            next_hint_ext,
            hint_felt_values,
            hint_ext_values,
            hinted_ids,
        };

        // Allocate public inputs first so they occupy indices 1..=num_public in the exported R1CS.
        compiler.phase0_preallocate_public_inputs(&public_ids, Some(&mut ctx));

        for op in operations {
            compiler.compile_one_inner(op, Some(&mut ctx));
        }

        // Keep witness length in sync with declared num_vars.
        ctx.ensure_len(compiler.r1cs.num_vars);
        (compiler, witness)
    }

    /// Indices of variables that do not appear in any R1CS constraint row, excluding explicit
    /// witness inputs tracked by the compiler (hint felts/exts, etc.) and the constant 1.
    ///
    /// This is useful as a post-compilation audit to catch accidental "allocated but never
    /// constrained" internal temporaries.
    pub fn unconstrained_internal_vars(&self) -> Vec<usize> {
        let mut allowed: HashSet<usize> = HashSet::new();
        allowed.insert(0);
        // Public inputs (if any) are explicit I/O.
        for i in 1..=self.r1cs.num_public {
            allowed.insert(i);
        }
        allowed.extend(self.witness_felts.iter().copied());
        allowed.extend(self.witness_exts.iter().copied());
        allowed.extend(self.witness_vars.iter().copied());
        if let Some(i) = self.vkey_hash_idx {
            allowed.insert(i);
        }
        if let Some(i) = self.committed_values_digest_idx {
            allowed.insert(i);
        }
        self.r1cs.unconstrained_vars_except(&allowed)
    }

    /// Phase 1 helper: Recursively scan ops and pre-consume hints into maps.
    /// This does NOT allocate variables or touch var_map - it only consumes hints.
    /// IMPORTANT: Must traverse ALL nested block types (Parallel, For, If*, etc.)
    fn phase1_preconsume_hints(
        ops: &[DslIr<C>],
        next_hint_felt: &mut dyn FnMut() -> Option<C::F>,
        next_hint_ext: &mut dyn FnMut() -> Option<[C::F; 4]>,
        hint_felt_values: &mut HashMap<String, VecDeque<C::F>>,
        hint_ext_values: &mut HashMap<String, VecDeque<[C::F; 4]>>,
        hinted_ids: &mut HashSet<String>,
    ) {
        for op in ops {
            match op {
                DslIr::CircuitV2HintFelts(start, len) => {
                    // Pre-consume hint felts into per-ID queues (FIFO)
                    for i in 0..*len {
                        let id = format!("felt{}", start.idx + i as u32);
                        let v = (next_hint_felt)()
                            .expect("next_hint_felt returned None in Phase 1 CircuitV2HintFelts");
                        hint_felt_values.entry(id.clone()).or_default().push_back(v);
                        hinted_ids.insert(id);
                    }
                }
                DslIr::CircuitV2HintExts(start, len) => {
                    // Pre-consume hint exts into per-ID queues (FIFO)
                    for i in 0..*len {
                        let base_id = format!("ext{}", start.idx + i as u32);
                        let ext_val = (next_hint_ext)()
                            .expect("next_hint_ext returned None in Phase 1 CircuitV2HintExts");
                        hint_ext_values
                            .entry(base_id.clone())
                            .or_default()
                            .push_back(ext_val);
                        // Mark all 4 components as hinted
                        for k in 0..4 {
                            let comp_id = format!("{}__{}", base_id, k);
                            hinted_ids.insert(comp_id);
                        }
                    }
                }
                DslIr::CircuitV2HintAddCurve(_boxed) => {
                    // In the shrink verifier pipeline, curve-add results are not provided via the
                    // witness stream. They are produced by the recursion runtime and live in
                    // runtime memory (reachable via `get_value` in Phase 2).
                    //
                    // Therefore Phase 1 must NOT consume any hint blocks here.
                }
                // === Nested block types - must traverse recursively ===
                DslIr::Parallel(blocks) => {
                    for block in blocks {
                        Self::phase1_preconsume_hints(
                            &block.ops,
                            next_hint_felt,
                            next_hint_ext,
                            hint_felt_values,
                            hint_ext_values,
                            hinted_ids,
                        );
                    }
                }
                DslIr::For(boxed) => {
                    // For loop: (start, end, step, var, body)
                    let (_, _, _, _, body) = boxed.as_ref();
                    Self::phase1_preconsume_hints(
                        body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                }
                DslIr::IfEq(boxed) => {
                    // If-then-else: (lhs, rhs, then_body, else_body)
                    let (_, _, then_body, else_body) = boxed.as_ref();
                    Self::phase1_preconsume_hints(
                        then_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                    Self::phase1_preconsume_hints(
                        else_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                }
                DslIr::IfNe(boxed) => {
                    let (_, _, then_body, else_body) = boxed.as_ref();
                    Self::phase1_preconsume_hints(
                        then_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                    Self::phase1_preconsume_hints(
                        else_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                }
                DslIr::IfEqI(boxed) => {
                    let (_, _, then_body, else_body) = boxed.as_ref();
                    Self::phase1_preconsume_hints(
                        then_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                    Self::phase1_preconsume_hints(
                        else_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                }
                DslIr::IfNeI(boxed) => {
                    let (_, _, then_body, else_body) = boxed.as_ref();
                    Self::phase1_preconsume_hints(
                        then_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                    Self::phase1_preconsume_hints(
                        else_body,
                        next_hint_felt,
                        next_hint_ext,
                        hint_felt_values,
                        hint_ext_values,
                        hinted_ids,
                    );
                }
                _ => {
                    // Skip non-hint, non-block ops in phase 1
                }
            }
        }
    }

    /// Compile all operations and return the R1CS
    pub fn compile(operations: Vec<DslIr<C>>) -> R1CS<C::F> {
        let mut public_ids: Vec<String> = Vec::new();
        let mut public_seen: HashSet<String> = HashSet::new();
        Self::phase0_collect_public_ids(&operations, &mut public_ids, &mut public_seen);
        let mut compiler = Self::new();
        compiler.phase0_preallocate_public_inputs(&public_ids, None);
        for op in operations {
            compiler.compile_one(op);
        }
        compiler.r1cs
    }
}

impl<C: Config> Default for R1CSCompiler<C>
where
    C::F: PrimeField64,
{
    fn default() -> Self {
        Self::new()
    }
}
