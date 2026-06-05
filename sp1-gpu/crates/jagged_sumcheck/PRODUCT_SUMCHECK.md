# Product Sumcheck — Project Summary

CPU + GPU provers for three related sumchecks, used to assess the prover cost
of replacing the jagged-assist verifier sum (see `two-stage-gkr.md`):

1. **Plain product** — `∑_x ∏_j A_j(x)` over the Boolean hypercube. K-product
   sumcheck used to compare different K's (depth-vs-width trade-off).
2. **Eq-prefixed product (Option 1)** — `∑_x eq(ζ, x) · ∏_j eq(z_j, p_j(x))`.
   This is the actual shape of the jagged-assist verifier sum the prover wants
   to take over. K is fixed at 64.
3. **Two-stage GKR (Option 2)** — splits the degree-K product into two
   lower-degree sumchecks of degrees `K_2 + 1` and `K_1 + 1` with `K_1·K_2 = K`,
   coupled by an intermediate "send the K_2 outer claims in the clear" step.

The shared provers' K-batched MLE layout, cached Lagrange-to-power matrix,
cooperative kernel design, and fused fold + sum-as-poly pattern are reused
across all three.

---

## Plain product sumcheck

> **Setup.** Data of size 64 × 2^c (think 60-ish multilinears in c variables).
> Stack the 64 columns into K MLEs of (64/K) × 2^c entries each. Sumcheck the
> claim `∑_{x∈{0,1}^n} ∏_{j=0..K} A_j(x)` where n = c + log₂(64/K). Each round's
> prover message has degree K.

K=2 (Hadamard-style, deep low-degree sumcheck) and K=64 (shallow high-degree
sumcheck) sit at the endpoints; K ∈ {4, 8, 16, 32} fill in.

### Where the code lives

**GPU**

- CUDA kernels: `sp1-gpu/crates/sys/lib/product_sumcheck/product_sumcheck.cu`
  - `productSumcheckSumAsPoly<F, K>` — round-0 sum-as-poly (base-field input only).
  - `productSumcheckFixAndSumAsPoly<F, K>` — **simple** fused fold-by-alpha + next-round sum-as-poly. Instantiated for K ∈ {2, 4, 8}.
  - `productSumcheckFixAndSumAsPolyCoop<F, K>` — **cooperative** K-threads-per-tile fused kernel. Instantiated for K ∈ {16, 32, 64}.
- Headers: `sp1-gpu/crates/sys/include/product_sumcheck/product_sumcheck.cuh`
- FFI: `sp1-gpu/crates/sys/src/v2_kernels.rs`
- Rust driver: `sp1-gpu/crates/jagged_sumcheck/src/product.rs`
  - `simple_product_sumcheck(k, mles, challenger, claim)` — round 0 (sum_as_poly) + (n−1) fused rounds + final fold-only.
  - Dispatches simple vs. coop via `should_use_coop(k) = k >= 16`.
- Bench: `sp1-gpu/crates/jagged_sumcheck/benches/product.rs`
- Tests: `mod tests` in `product.rs` (K ∈ {2, 4, 8, 16, 32, 64} at n=5).

**CPU**

- Module: `slop/crates/jagged/src/product.rs`
  - `pub struct ProductPoly<T> { pub mle: Mle<T, CpuBackend> }` — a **single batched MLE** with K polynomial columns. Row-major layout means `mle.guts().as_slice()[i*K .. (i+1)*K]` is the K factor values at hypercube point i, so the inner loop hits one contiguous K-chunk per i.
  - Trait impls (`SumcheckPolyBase`, `SumCheckPolyFirstRoundBackend`, `SumcheckPolyBackend`, `ComponentPolyEvalBackend`) plug into slop's `reduce_sumcheck_to_evaluation`.
- Bench: `slop/crates/jagged/benches/product.rs` (env var `LOG_AREAS=...` for sweep).
- Tests: `mod tests` in `product.rs` (K ∈ {2, 4, 8, 16, 32, 64} at n=8).

### Optimizations that mattered

**GPU**

1. **Add-chain for eval factors** — replaces `lo + t·d` with `cur += d` per eval-point step. Turns K−1 ext-by-felt mults per (i, j) pair into K−1 ext-adds. Modest win on its own, but it composes with everything else.

2. **Fused fix-and-sum** — one kernel does round r's fold AND round r+1's sum-as-poly in one global memory pass. Saves a `K * N/2`-ext-read round-trip per fused round. ~3–6% wins across K.

3. **Cooperative K-tile kernel** (K ≥ 16) — each thread owns ONE eval point (not all K), TILES_PER_BLOCK = 256/K x_top instances cooperate via shared memory. Drops per-thread register footprint from O(K) to O(1), fixing the 1/6-occupancy collapse the simple kernel hit at K=64. Big win: K=64 at log_area=18 went from **39 ms → 6 ms** by itself.

4. **Cached Lagrange-to-power matrix** — precompute (K+1)² Felt matrix `M` once per K (`OnceLock`), apply as one matmul per round (`coef[j] = Σ M[j*n + i] · y[i]`). Replaces slop's O(K³) `interpolate_univariate_polynomial` with O(K²) ext×felt matmul. Took K=64 sumcheck from ~6 ms → **0.9 ms** at log_area=18.

   Combined with (3): K=64 at log_area=18 went from **39 ms → 0.9 ms** (~43×).

5. **`interpolateLinear` only for the fold** — its overloads cover `ext × F` for both F=felt and F=ext, but there's no `kb31_t × (ext - ext) + ext` overload, so for the eval-factor inner loop the cheap "ext × felt + ext" pattern wins over `ext_t::interpolateLinear(ext, ext)` (which forces full ext×ext multiplication).

**CPU**

1. **Single batched MLE** — `ProductPoly` holds one `Mle<T, CpuBackend>` with K columns. The row-major layout makes the inner loop cache-friendly (one contiguous K-chunk per hypercube point).

2. **Add-chain for eval factors** — same as the GPU optimization.

3. **Base-field arithmetic in round 0** — `compute_round_univariate<F, EF>` keeps the inner product loop in F and lifts only the K final sums to EF.

4. **Cached Lagrange-to-power matrix** — TypeId-keyed `OnceLock<Mutex<HashMap<(K, TypeId), Arc<Vec<F>>>>>` caches matrices per (K, F) globally. Replaces slop's generic O(K³) Lagrange routine with an O(K²) matmul. At K=64/log_area=18: **~50 ms → ~12 ms** (~4×).

**What did NOT work**

`with_min_len(...)` chunking of the par_iter. Tried `n_half / num_cpus` and `n_half / (num_cpus * 4)`. Both produced K-dependent mixed results — small-K gains offset by 5–25% regressions at K ≥ 16. The optimal min_chunk depends on K² (per-iter field-op count) but parallelism needs at least `num_cpus` chunks, and a single static formula can't satisfy both. Reverted to rayon defaults.

### Bug fix worth remembering

**Coop kernel deadlock at small `numXTop`.** Original `for (x_top = block_start + tile_id; x_top < numXTop; x_top += step) { …; __syncthreads(); }` has UB when `numXTop < TILES_PER_BLOCK` (the last fused round at any K has input_height=4 ⇒ numXTop=1): inactive tiles never enter the loop body and never reach the `__syncthreads()` calls inside. Observed as a hang at K=16 (TPB=16, half-warp tiles); the K=64 case (TPB=4, warp-aligned) happened to schedule past it without hanging on this GPU.

**Fix.** Compute a block-uniform `iter_count` outside the loop; loop exactly that many times; gate the work on a per-thread `active` flag. Every thread reaches every `__syncthreads()` regardless. `product_sumcheck.cu`, function `productSumcheckFixAndSumAsPolyCoop`.

### Benchmarks

Same machine for both. Criterion `--quick --warm-up-time 1 --measurement-time 2`, median of 10 samples.

| LOG_AREA | K | CPU time | GPU time |
|---------:|--:|---------:|---------:|
| 18 |  2 |   2.08 ms |  311.5 µs |
| 18 |  4 |   2.25 ms |  422.8 µs |
| 18 |  8 |   2.85 ms |  570.2 µs |
| 18 | 16 |   4.10 ms |  418.6 µs |
| 18 | 32 |   6.93 ms |  543.1 µs |
| 18 | 64 |  12.28 ms |  904.7 µs |
| 20 |  2 |   4.24 ms |  389.4 µs |
| 20 |  4 |   5.11 ms |  495.4 µs |
| 20 |  8 |   7.27 ms |  656.8 µs |
| 20 | 16 |  11.96 ms |  523.5 µs |
| 20 | 32 |  21.25 ms |  712.9 µs |
| 20 | 64 |  41.13 ms |   1.18 ms |
| 22 |  2 |  12.70 ms |  504.2 µs |
| 22 |  4 |  16.66 ms |  572.1 µs |
| 22 |  8 |  25.54 ms |  811.3 µs |
| 22 | 16 |  44.31 ms |  745.6 µs |
| 22 | 32 |  81.64 ms |   1.12 ms |
| 22 | 64 | 152.90 ms |   1.86 ms |
| 24 |  2 |         — |   1.08 ms |
| 24 |  4 |         — |   1.17 ms |
| 24 |  8 |         — |   1.52 ms |
| 24 | 16 |         — |   1.55 ms |
| 24 | 32 |         — |   2.59 ms |
| 24 | 64 |         — |   4.54 ms |
| 26 |  2 |         — |   3.35 ms |
| 26 |  4 |         — |   3.45 ms |
| 26 |  8 |         — |   4.02 ms |
| 26 | 16 |         — |   4.51 ms |
| 26 | 32 |         — |   8.00 ms |
| 26 | 64 |         — |  14.61 ms |
| 28 |  2 |         — |  12.10 ms |
| 28 |  4 |         — |  12.20 ms |
| 28 |  8 |         — |  13.55 ms |
| 28 | 16 |         — |  15.95 ms |
| 28 | 32 |         — |  29.85 ms |
| 28 | 64 |         — |  55.10 ms |

**Observations**

- **K=8 → K=16 dip on GPU.** At every log_area, K=16 is *faster* than K=8 because K=16 crosses into the cooperative kernel (better occupancy) while K=8 still uses the simple kernel. The simple-kernel curve (K=2/4/8) and the coop-kernel curve (K=16/32/64) really are two different machines on the same hardware.
- **CPU scaling.** Roughly 4× per +2 log_area at fixed K (data scaling), and ~2× per K-doubling for K ≥ 4 (per-round cost grows like K² while round count drops by log₂K → net ~K). No K=16 dip on CPU because there's no kernel-shape transition.
- **GPU/CPU ratio grows with data.** At K=64: ~14× at log_area=18, ~35× at 20, ~82× at 22. The GPU pulls farther ahead at larger problem sizes.
- **GPU at K=64 has ~7× the cost of K=2 at the same data size.** The deep-product strategy isn't free even on GPU — the coop kernel's K² inner work dominates above K=16.

---

## Eq-prefixed product sumcheck (two-stage-GKR Option 1)

> **Setup.** K=64 base-field MLEs `p_1, …, p_64` over n=c variables, plus
> `ζ ∈ Ext^n` and `z ∈ Ext^K`. Sumcheck the claim
> `∑_{x ∈ {0,1}^n} eq(ζ, x) · ∏_{j=1..K} eq(z_j, p_j(x))`.
> This is degree-(K+1) per round (K factors plus the eq factor).

Each round's prover message factors as `g_r(t) = eq(ζ_r, t) · h_r(t)` where
`h_r` has degree K. The Gruen-style trick lets the prover compute h_r at K
eval points (one less than naive); h_r(1) is recovered from the round claim,
then h_r is built in power form via the cached Lagrange matrix and multiplied
by the linear eq factor to produce g_r.

### Where the code lives

**GPU**

- CUDA kernels: `sp1-gpu/crates/sys/lib/eq_product_sumcheck/eq_product_sumcheck.cu`
  - `eqProductSumAsPolyCoop<F>` — round-0 sum-as-poly (no fold).
  - `eqProductFixAndSumAsPolyCoop<F>` — **fused** fold-MLE + eq-prefix transition + next-round sum-as-poly in one global memory pass.
  - `eqPrefixFold` — standalone eq-prefix update (currently unused, kept for reference).
- Headers: `sp1-gpu/crates/sys/include/eq_product_sumcheck/eq_product_sumcheck.cuh`
- FFI: `sp1-gpu/crates/sys/src/v2_kernels.rs`
- Rust driver: `sp1-gpu/crates/jagged_sumcheck/src/eq_product.rs`
  - `simple_eq_product_sumcheck(base_mles, zeta, z, challenger, claim)` — K=64-only.
  - Initial eq prefix `E_1` built **on device** via `DevicePoint::partial_lagrange()`.
- Bench: `sp1-gpu/crates/jagged_sumcheck/benches/eq_product.rs`
- Tests: `mod tests` in `eq_product.rs` (K=64 at n=5, true claim).

**CPU**

- Module: `slop/crates/jagged/src/eq_product.rs`
  - `pub struct EqProductPoly<F, EF = F>` — batched K-MLE + eq prefix + precomputed `a`, `b` arrays + remaining ζ-coordinates. Trait impls plug into `reduce_sumcheck_to_evaluation`.
- Bench: `slop/crates/jagged/benches/eq_product.rs`
- Tests: `mod tests` in `eq_product.rs` (K=64 at n=6).

### Algorithm-specific machinery

1. **Factor reformulation.** `eq(z_j, p_j(x, t)) = a_j + b_j · p_j(x, t)` with precomputed `a_j = 1 − z_j`, `b_j = 2z_j − 1`. Define `u_j = a_j + b_j · p_lo` and `v_j = b_j · (p_hi − p_lo)`; then `factor_j(t) = u_j + t · v_j` and the add-chain trick from the plain product still walks eval points by one ext-add each.

2. **Eq prefix transition.** Between rounds, `E_{r+1}(y) = eq(ζ_r, α_r) · (E_r(y, 0) + E_r(y, 1))`. The pair-sum drops the just-folded variable's eq factor (since `eq(ζ_r, 0) + eq(ζ_r, 1) = 1`); the scalar `eq(ζ_r, α_r)` carries the running `C_r = ∏_{r' ≤ r} eq(ζ_{r'}, α_{r'})` so the prover never needs to track `C` as a separate field — it lives inside the eq prefix.

3. **Absorption into u_0, v_0.** Rather than scaling each of K running products by `E_r(x)` per x (K ext×ext mults), the j=0 factor's (u_0, v_0) are scaled by `E_r(x)` once. The scaling then propagates through all K running products via the j=0 multiplication for free.

4. **Cached Lagrange matrix is shared** with the plain product shim; the eq factor doesn't change the kernel-eval-point structure (still {0, 2, 3, …, K}). Recovery: `h_r(1) = (claim − (1 − ζ_r) · h_r(0)) / ζ_r`.

5. **g_r construction.** After matrix-applying to get h_r in power form, multiply by the linear `eq(ζ_r, t) = (1 − ζ_r) + (2ζ_r − 1) · t`. **Gotcha**: it's `(2ζ_r − 1)` for the linear coefficient, not `ζ_r` — the verifier check catches this immediately with `InconsistencyWithClaimedSum` if you get it wrong.

### Bugs found during development

1. **Missing running scalar.** First version computed `g_r(t) = eq(ζ_r, t) · h_r(t)` without including the cumulative `C_{r-1}` factor from prior folds. Fixed by absorbing `eq(ζ_r, α_r)` into the eq prefix during the transition, as described above.

2. **Wrong eq polynomial coefficient.** `eq(ζ, t)` as a polynomial in t is `(1 − ζ) + (2ζ − 1) · t`, not `(1 − ζ) + ζ · t`. Verifier check `g(0) + g(1) = claim` catches this; `eval_one_plus_eval_zero` returns the wrong value otherwise.

### Benchmarks

Eq-prefixed numbers below; plain product numbers from the previous table for comparison. Same machine + criterion settings.

| LOG_AREA | K | Plain CPU | Plain GPU | Eq CPU | Eq GPU |
|---------:|--:|---------:|---------:|---------:|---------:|
| 18 | 64 | 12.28 ms |  904.7 µs |  20.49 ms |  935.6 µs |
| 20 | 64 | 41.13 ms |   1.18 ms |  74.21 ms |   1.35 ms |
| 22 | 64 | 152.9 ms |   1.86 ms | 285.58 ms |   2.62 ms |
| 24 | 64 |        — |   4.54 ms |         — |   6.86 ms |
| 26 | 64 |        — |  14.61 ms |         — |  24.02 ms |
| 28 | 64 |        — |  55.10 ms |         — |  92.84 ms |

**Observations**

- **Eq overhead vs plain product on GPU** grows with log_area: ~3% at 18, ~14% at 20, ~41% at 22, ~51% at 24, ~64% at 26, ~68% at 28. At small log_area the kernel-launch and host-side work dominate; at large log_area the per-x ext×ext arithmetic (the eq absorption into u_0, v_0 + the b_j · v_lo mults inside the factor) becomes visible.
- **Eq overhead on CPU** is more stable around ~70–87% across the swept sizes — CPU was already arithmetic-bound, so the eq additions translate directly.
- **GPU/CPU ratio for eq**: 22× at log_area=18, 55× at 20, 109× at 22. Same scaling story as plain product but with bigger ratios because CPU eq overhead is larger.
- **GPU eq at log_area=28** (the actual jagged-assist target): **~93 ms** for K=64. The plain product at the same size is ~55 ms.

---

## Two-stage GKR (Option 2)

> **Setup.** Same data as Option 1 (K=64 base-field MLEs `p_k`, `ζ ∈ Ext^c`,
> `z ∈ Ext^K`), but with K factored as `K_1 · K_2`. Run two stacked
> sumchecks instead of one degree-65:
>
> 1. **Stage 1** (degree K_2 + 1). Build K_2 ext-field outer multilinears
>    `B_j[i] = ∏_{j'=0..K_1} eq(z_{jK_1+j'}, p_{jK_1+j'}[i])` and run the
>    eq-prefixed sumcheck `∑_i eq(ζ, i) · ∏_j B_j[i]`. Prover sends the K_2
>    final claims `B_j(ζ'') = v_j` in the clear.
> 2. **Stage 2** (degree K_1 + 1). Verifier samples `ζ''' ∈ Ext^{log K_2}`,
>    sets `w_j = eq(ζ''', j)`, accepts the new claim `∑_j w_j · v_j`, and both
>    sides run a sumcheck on
>    `∑_i eq(ζ'', i) · ∑_j w_j · ∏_{j'} eq(z_{jK_1+j'}, p_{jK_1+j'}[i])`.
>    The K_2 inner sum stays inside the prover's round univariate — it is *not*
>    sumchecked over. Final eval claim closes the proof.
>
> The PCS still opens the K underlying `p_k`'s at the same single point `η`
> (same as Option 1), so the commitment-side cost is unchanged.

### Where the code lives

**CPU**

- Module: `slop/crates/jagged/src/two_stage_eq_product.rs`
  - `pub struct EqOuterSumPoly<F, EF>` — stage-2 polynomial state (degree-(K_1+1) sumcheck with K_2-loop inner sum).
  - `pub fn build_b_mles(...)` — constructs the K_2-batched ext MLE used in stage 1.
  - `pub fn simple_two_stage_eq_product_sumcheck(...)` — orchestrates stage 1 → ζ''' sample → stage 2.
  - Stage 1 reuses [`EqProductPoly`](../../slop/crates/jagged/src/eq_product.rs) with `z_stage1 = [1, …, 1]` so that `(a_j, b_j) = (0, 1)` collapses the eq-factor to the plain `B_j[i]` factor.
- Bench: `slop/crates/jagged/benches/two_stage_eq_product.rs` (env vars `LOG_AREAS=...`, `KSPLITS=K1xK2,...`).
- Tests: `mod tests` in `two_stage_eq_product.rs` — five `(K_1, K_2)` splits at n=6.

**GPU**

- CUDA kernels: `sp1-gpu/crates/sys/lib/two_stage_eq_product_sumcheck/two_stage_eq_product_sumcheck.cu`
  - `buildBMles<K1, K2>` — builds the K_2 ext outer multilinears on device, one thread per (i, j) pair.
  - `eqProductSumAsPolyCoopT<F, K>` / `eqProductFixAndSumAsPolyCoopT<F, K>` — K-templated eq-product kernels reused for stage 1 (instantiated for K ∈ {2, 4, 8, 16, 32}, ext-input only).
  - `stage2SumAsPolyCoop<F, K1, K2>` — round-0 (base-input) and `stage2FixAndSumCoop<F, K1, K2>` — fused fold + eq-prefix transition + next-round sum-as-poly for both base→ext (round 1) and ext→ext (rounds 2..c-1) transitions.
  - All five (K_1, K_2) splits instantiated via the `BUILD_B_KERNEL` / `STAGE1_KERNELS` / `STAGE2_KERNELS` macros at the bottom of the .cu.
- Headers: `sp1-gpu/crates/sys/include/two_stage_eq_product_sumcheck/two_stage_eq_product_sumcheck.cuh`
- FFI: `sp1-gpu/crates/sys/src/v2_kernels.rs`
- Rust driver: `sp1-gpu/crates/jagged_sumcheck/src/two_stage_eq_product.rs`
  - `simple_two_stage_eq_product_sumcheck(base_mles, zeta, z, k1, k2, challenger, claim)` — runtime dispatch on (k1, k2) via match-based kernel selectors.
  - Initial eq prefixes for both stages built on device via `DevicePoint::partial_lagrange()`; `w = partial_lagrange(ζ''')` is also built on device.
- Bench: `sp1-gpu/crates/jagged_sumcheck/benches/two_stage_eq_product.rs` (sweeps all 5 splits).
- Tests: `mod tests` in `two_stage_eq_product.rs` — all five `(K_1, K_2)` splits at n=5.

### Algorithm-specific machinery

1. **Stage-1 reuse via `z = 1`.** `EqProductPoly` with stage-1 `z_j = 1` gives `a_j = 0, b_j = 1`, so the per-factor expression `a_j + b_j · B_j[i]` collapses to `B_j[i]`. No new polynomial type needed for stage 1.

2. **Stage-2 round univariate.** `g_r(t) = eq(ζ''_r, t) · h_r(t)` where
   `h_r(t) = ∑_y E_r(y) · ∑_j w_j · ∏_{j'} (u_{j,j'} + t · v_{j,j'})`. Evaluated at K_1 kernel points {0, 2, 3, …, K_1}, then h_r(1) recovered from the round claim, Lagrange-applied to power form, multiplied by the linear `eq(ζ''_r, t)`. Same Gruen trick as Option 1, just at smaller degree.

3. **Inner-loop mult savings.** Per (y, j):
   - `w_j` is absorbed into `(u_{j,0}, v_{j,0})` once — propagates through the K_1 running product for free (1 ext-mult per j-group rather than K_1 + K_1 if we'd scaled the result after).
   - `eq_prefix(y)` is applied to the per-y K_1 accumulator *after* the K_2 outer sum, not per-j (K_1 ext-mults per y total, vs K_1·K_2 if scaled per j).

4. **Total per-round ext-mults at round r** (rough count, ignoring the cheap base-by-ext round 0): outer-sum body is `2^{c−r} · K_2 · K_1²` for the K_1-product, plus `2^{c−r} · K_1` for the eq-prefix scale and `2^{c−r} · K_2` for w_j-absorption. The dominant `K_2 · K_1²` term is minimised at K_1 ≈ K_2 ≈ √K, which the bench confirms.

### Benchmarks — CPU

Same machine + criterion settings as the other tables. K = K_1 · K_2 = 64.

| LOG_AREA | (K_1, K_2)   | CPU time | Notes |
|---------:|--------------|---------:|-------|
| 18       | (2, 32)      |  9.85 ms |       |
| 18       | (4, 16)      |  6.50 ms |       |
| **18**   | **(8, 8)**   | **6.37 ms** | best |
| 18       | (16, 4)      |  8.32 ms |       |
| 18       | (32, 2)      | 12.98 ms |       |
| 20       | (2, 32)      | 33.84 ms |       |
| **20**   | **(4, 16)**  | **17.75 ms** | best |
| 20       | (8, 8)       | 18.16 ms |       |
| 20       | (16, 4)      | 28.00 ms |       |
| 20       | (32, 2)      | 47.19 ms |       |
| 22       | (2, 32)      | 133.29 ms |      |
| 22       | (4, 16)      |  72.90 ms |      |
| **22**   | **(8, 8)**   | **69.72 ms** | best |
| 22       | (16, 4)      | 103.03 ms |      |
| 22       | (32, 2)      | 176.86 ms |      |

### Benchmarks — GPU

K = K_1 · K_2 = 64.  All five splits at each LOG_AREA; bold marks the per-row best.

| LOG_AREA | (2, 32)  | (4, 16)  | (8, 8)         | (16, 4)        | (32, 2)  |
|---------:|---------:|---------:|---------------:|---------------:|---------:|
| 18       |  1.43 ms |  1.07 ms |       897 µs   | **    855 µs** |    890 µs |
| 20       |  1.75 ms |  1.27 ms |      1.07 ms   | **   1.03 ms** |   1.16 ms |
| 22       |  2.47 ms |  1.71 ms | **   1.45 ms** |       1.49 ms  |   1.87 ms |
| 24       |  5.03 ms |  3.17 ms | **   2.76 ms** |       3.05 ms  |   4.46 ms |
| 26       | 14.49 ms |  8.78 ms | **   7.64 ms** |       8.84 ms  |  14.49 ms |
| 28       | 52.32 ms | 30.52 ms | **  27.37 ms** |      32.32 ms  |  55.48 ms |

### Option 1 vs Option 2 — CPU & GPU @ K=64

| LOG_AREA | Opt 1 CPU  | Opt 2 best CPU         | CPU speedup | Opt 1 GPU  | Opt 2 best GPU         | GPU speedup |
|---------:|-----------:|-----------------------:|------------:|-----------:|-----------------------:|------------:|
| 18       |  20.49 ms  |   6.37 ms ((8, 8))     | **3.2×**   |  935.6 µs  |   855 µs ((16, 4))     | **1.10×** |
| 20       |  74.21 ms  |  17.75 ms ((4, 16))    | **4.2×**   |   1.35 ms  |  1.03 ms ((16, 4))     | **1.31×** |
| 22       | 285.58 ms  |  69.72 ms ((8, 8))     | **4.1×**   |   2.62 ms  |  1.45 ms ((8, 8))      | **1.81×** |
| 24       |        —   |          —             |       —    |   6.86 ms  |  2.76 ms ((8, 8))      | **2.49×** |
| 26       |        —   |          —             |       —    |  24.02 ms  |  7.64 ms ((8, 8))      | **3.14×** |
| 28       |        —   |          —             |       —    |  92.84 ms  | **27.37 ms ((8, 8))**  | **3.39×** |

### Observations

- **(8, 8) wins at large data on both CPU and GPU.**  Symmetric split minimises neither K_1²·K_2 (stage-2 inner work) nor K_2² (stage-1 outer work) being dominant.  On CPU this holds from log_area=22; on GPU from log_area=22 as well.
- **Small-data crossover on GPU** to (16, 4) at log_area ≤ 20.  A larger K_1 fills warps better (16 threads/tile vs 8) when there's not enough parallelism to amortise overhead.  The win is small (~5%) and disappears once we're compute-bound.
- **Tail splits ((2, 32), (32, 2)) cost 1.5–2× the optimum at large LA** on both CPU and GPU.  (32, 2) is dominated by stage-2's `K_1²·K_2` work; (2, 32) by stage-1's `K_2²` work plus the `K · 2^c` B_j build cost.
- **GPU asymmetry between (4, 16) and (16, 4) is much milder than CPU's.**  On CPU stage-2 cost scales as K_1², so (16, 4) is 1.5–1.7× worse than (4, 16).  On GPU the cooperative kernel parallelises eval points across K_1 threads, so per-thread work is bounded by K_1·K_2 = K = 64 regardless of split — the asymmetry compresses to ~5–15%.
- **Option 2 cleanly beats Option 1 by 3–4× on CPU** at the optimum split (degree 9 + 9 vs single degree 65).
- **Option 2 vs Option 1 on GPU grows with data** (1.10× at log_area=18 → **3.39× at log_area=28**), same compute-bound transition as plain product → eq.  At the jagged-assist target (log_area ≈ 28), Option 2 (8, 8) is the clear winner: **27.37 ms vs 92.84 ms**.
- **GPU speedup is below the theoretical work-reduction ratio (~7×)** because Option 2's two-sumcheck protocol has more kernel launches and stages.  See "Future optimisations" below for the largest remaining gap.

### Future optimisations

1. **Stage-1 z-specialisation.**  Stage 1 reuses the Option-1 eq-product kernel with `a = 0, b = 1` so the factor `a + b·B_j` equals the MLE value.  Each thread still does the formal computation:
   ```
   u_j = a_j + b_j · p_lo  →  0 + 1·p_lo = p_lo
   v_j = b_j · (p_hi − p_lo)  →  1 · d = d
   ```
   This costs **one redundant ext-by-base mult and one redundant ext-add per (eval-point, factor)** that a dedicated stage-1 kernel could elide.  Per round the dead work is `2 · K_2 · 2^{c−r}` ext-by-base ops — small relative to the `K_2² · 2^{c−r}` inner-product cost, but at K_2 = 8 it's ~25% of stage-1 arithmetic.  Estimated gain: ~5–10% on the stage-1 portion of total time (which is small to begin with at the optimum split, since stage 2 dominates).  Implementation would be a separate `stage1*Specialized<K2>` kernel set; the host can keep using the same dispatch.

2. **B_j build coalescing.**  The current `buildBMles<K1, K2>` reads `p_{j·K1+j'}[i]` for K_1 strided columns per thread.  Coalescing is OK within a warp (consecutive i), but for K_1 ≥ 16 the strided reads start to spill cache lines.  An alternative layout that stores p in `[K_2, K_1, height]` order would let a warp cooperatively load all K_1 base values for one (j, i)-tile.  Probably <5% win — the build is a small fraction of total time.

3. **Smaller eval-point set in stage 2.**  Currently `interpolateLinear` produces (u, v) at K_1 eval points {0, 2, …, K_1}.  The K_2 outer sum means we recompute these eval-point factors K_2 times per x_top.  No obvious algebraic shortcut, but worth re-examining if stage-2 timings become important.

---

## How to run

```bash
# === Plain product ===
LOG_AREAS=18,20,22 cargo bench -p slop-jagged --bench product
cargo test --release -p slop-jagged --lib product::tests::
cargo bench -p sp1-gpu-jagged-sumcheck --bench product -- random:18,20,22,24,26,28
cargo test --release -p sp1-gpu-jagged-sumcheck --lib product::tests::

# === Eq-prefixed product (Option 1) ===
LOG_AREAS=18,20,22 cargo bench -p slop-jagged --bench eq_product
cargo test --release -p slop-jagged --lib eq_product::tests::
cargo bench -p sp1-gpu-jagged-sumcheck --bench eq_product -- random:18,20,22,24,26,28
cargo test --release -p sp1-gpu-jagged-sumcheck --lib eq_product::tests::

# === Two-stage GKR (Option 2) ===
LOG_AREAS=18,20,22 KSPLITS=2x32,4x16,8x8,16x4,32x2 \
    cargo bench -p slop-jagged --bench two_stage_eq_product
cargo test --release -p slop-jagged --lib two_stage_eq_product::tests::
cargo bench -p sp1-gpu-jagged-sumcheck --bench two_stage_eq_product -- \
    random:18,20,22,24,26,28
cargo test --release -p sp1-gpu-jagged-sumcheck --lib two_stage_eq_product::tests::
```
