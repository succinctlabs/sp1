// Benchmarking tests are currently disabled pending public API stabilization.
//
// The benchmarks require access to ZK PCS prover/verifier construction
// (e.g., `initialize_zk_prover_and_verifier`) which is not yet exposed through the
// public `compiler` + `zk` API. Once a public constructor for the stacked PCS
// prover/verifier is available, these benchmarks should be rewritten to use:
//
// - `slop_veil::compiler::{ConstraintCtx, ReadingCtx, SendingCtx, SumcheckParam}`
// - `slop_veil::zk::{ZkProverCtx, ZkVerifierCtx, compute_mask_length, MleCommit}`
//
// Key benchmarks to port:
// 1. `benchmark_zk_vs_standard_sumcheck_with_pcs` — single MLE sumcheck + PCS
// 2. `benchmark_zk_vs_standard_hadamard_sumcheck_with_pcs` — Hadamard product with
//    batched PCS eval via `assert_mle_multi_eval`
