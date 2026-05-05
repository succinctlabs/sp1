//! Common test utilities shared across test modules.

/// Benchmark helpers shared across the per-crate Criterion benches. A single
/// [`with_trace_source`] entry point dispatches based on a [`BenchKind`] marker that controls what
/// shape of input the bench's closure receives — nothing ([`NoneKind`]), the trace MLE only
/// ([`JaggedKind`]), or the full execution context ([`FullKind`]). The CLI source arg
/// (`random` / `json/<path>` / `real/<program>`) is parsed once and applied uniformly.
#[cfg(any(test, feature = "test-utils"))]
pub mod bench_utils {
    use std::sync::Arc;

    use std::collections::BTreeSet;

    use criterion::{BenchmarkFilter, BenchmarkId, Criterion};
    use rand::Rng;
    use slop_algebra::AbstractField;
    use slop_futures::queue::WorkerQueue;
    use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir};
    use sp1_gpu_cudart::{run_in_place, run_sync_in_place, PinnedBuffer, TaskScope};
    use sp1_gpu_utils::test_utils::random::{
        random_jagged_trace_mle, random_jagged_trace_mle_from_json,
    };
    use sp1_gpu_utils::{Felt, JaggedTraceMle};
    use sp1_hypercube::air::SP1_PROOF_NUM_PV_ELTS;
    use sp1_hypercube::prover::ProverSemaphore;
    use sp1_hypercube::{Chip, Machine};

    /// All the artifacts a real-trace bench gets after the helper runs setup. Beyond `device_mle`,
    /// this exposes `machine`, the post-tracegen `chip_set`, and `public_values` — all needed by
    /// benches like `zerocheck` that walk the chip layout.
    ///
    /// For random / JSON sources the `chip_set` is synthesized as the full
    /// `machine.chips()` set and `public_values` is a zero-filled vector of the right length.
    /// Values don't need to be meaningful for timing (the prover doesn't validate them), but the
    /// shapes have to be consistent.
    pub struct RealTraceData<'a> {
        pub machine: &'a Machine<Felt, RiscvAir<Felt>>,
        pub chip_set: &'a BTreeSet<Chip<Felt, RiscvAir<Felt>>>,
        pub public_values: &'a [Felt],
        pub device_mle: &'a JaggedTraceMle<Felt, TaskScope>,
    }

    use super::tracegen_setup::{self, CORE_MAX_LOG_ROW_COUNT, LOG_STACKING_HEIGHT};
    use crate::{full_tracegen, CORE_MAX_TRACE_SIZE};

    /// Default log_2 of the synthetic random trace area (in field elements). Used when the user
    /// passes `random` (or no arg) without specifying sizes.
    pub const DEFAULT_RANDOM_LOG_AREA: u32 = 25;

    /// zkVM sample programs available under `real/<name>`. Add entries here to make additional
    /// programs benchable.
    pub fn real_programs() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("fibonacci", &test_artifacts::FIBONACCI_ELF),
            ("ed25519", &test_artifacts::ED25519_ELF),
            ("keccak256", &test_artifacts::KECCAK256_ELF),
            ("sha2", &test_artifacts::SHA2_ELF),
        ]
    }

    /// Which trace source a bench should run against.
    pub enum TraceSource {
        /// Synthetic random trace(s). Each `u32` is a log_2 area in field elements; one bench is
        /// run per entry. Empty list means use the default [`DEFAULT_RANDOM_LOG_AREA`].
        Random(Vec<u32>),
        /// Trace built from a JSON layout file.
        Json(String),
        /// Trace from an actual zkVM execution of a sample program.
        Real { name: &'static str, elf: &'static [u8] },
    }

    /// Detect a `random` / `random:N` / `random:N1,N2,...` arg. Returns the parsed list of log
    /// areas (empty for plain `random`), or `None` if the arg isn't a random spec.
    fn parse_random_arg(arg: &str) -> Option<Vec<u32>> {
        if arg == "random" {
            return Some(vec![]);
        }
        let rest = arg.strip_prefix("random:")?;
        let sizes: Vec<u32> = rest
            .split(',')
            .map(|s| {
                s.trim().parse::<u32>().unwrap_or_else(|_| {
                    panic!("invalid random log-area `{s}` in `{arg}`; expected `random:N[,N,...]`")
                })
            })
            .collect();
        assert!(!sizes.is_empty(), "empty size list in `{arg}`; use `random` for the default",);
        Some(sizes)
    }

    impl TraceSource {
        /// Pick a source from CLI args, in priority order:
        ///
        /// 1. Any positional arg ending in `.json` → [`TraceSource::Json`] with that path.
        /// 2. Any positional arg matching `random` / `random:N` / `random:N1,N2,...` →
        ///    [`TraceSource::Random`] with the parsed log-area list (empty for default size).
        /// 3. Any positional arg matching (substring) a known [`real_programs`] entry → that one.
        /// 4. Otherwise → [`TraceSource::Random`] with the default size.
        ///
        /// This means `cargo bench --bench <name>` (no args) defaults to random; pass an explicit
        /// arg to override.
        pub fn from_cli_args() -> Self {
            let positional: Vec<String> =
                std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();

            if let Some(path) = positional.iter().find(|a| a.ends_with(".json")) {
                return Self::Json(path.clone());
            }
            for arg in &positional {
                if let Some(sizes) = parse_random_arg(arg) {
                    return Self::Random(sizes);
                }
            }
            for (name, elf) in real_programs() {
                let id = format!("real/{name}");
                if positional.iter().any(|a| id.contains(a) || a.contains(&id)) {
                    return Self::Real { name, elf };
                }
            }
            Self::Random(vec![])
        }
    }

    /// Marker trait controlling the closure shape `with_trace_source` invokes the bench with.
    /// Implementors are unit structs ([`NoneKind`], [`JaggedKind`], [`FullKind`]) so the bench
    /// declares its needs by name and the type system carries the rest.
    pub trait BenchKind: Sized {
        /// What the helper passes into the user's closure as the last argument.
        type Input<'a>;

        /// Implementation hook. Don't call directly — go through [`with_trace_source`].
        fn run<R, F>(c: &mut Criterion, rng: &mut R, f: F)
        where
            R: Rng,
            F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, Self::Input<'_>);
    }

    /// `Input = ()`. For benches whose inputs aren't a `JaggedTraceMle` (e.g. `hadamard`).
    /// Ignores the `--source` arg entirely; the helper just opens a `TaskScope`, overrides
    /// Criterion's filter to accept-all so a user-passed `--source <X>` doesn't drop the bench,
    /// and calls `f` once.
    pub struct NoneKind;

    /// `Input = &JaggedTraceMle<Felt, TaskScope>`. For benches that just need the trace.
    /// Source picked from CLI as random / JSON / real.
    pub struct JaggedKind;

    /// `Input = RealTraceData<'_>`. For benches that need the surrounding execution context
    /// (machine, chip_set, public_values) in addition to the trace. Source picked from CLI as
    /// random / JSON / real; for the synthetic sources the `chip_set` and `public_values` are
    /// synthesized so the bench timing reflects the largest-cluster workload.
    pub struct FullKind;

    impl BenchKind for NoneKind {
        type Input<'a> = ();

        fn run<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
        where
            R: Rng,
            F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, ()),
        {
            *c = std::mem::take(c).with_benchmark_filter(BenchmarkFilter::AcceptAll);
            run_sync_in_place(move |scope| {
                // Sentinel id; the bench typically registers its own group / bench_function
                // and ignores this.
                let id = BenchmarkId::new("default", "default");
                f(c, id, &scope, rng, ());
            })
            .unwrap();
        }
    }

    impl BenchKind for JaggedKind {
        type Input<'a> = &'a JaggedTraceMle<Felt, TaskScope>;

        fn run<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
        where
            R: Rng,
            F: FnMut(
                &mut Criterion,
                BenchmarkId,
                &TaskScope,
                &mut R,
                &JaggedTraceMle<Felt, TaskScope>,
            ),
        {
            // The full-data dispatcher always builds a `RealTraceData`; for `JaggedKind` we
            // only need the MLE, so unwrap and discard the rest.
            dispatch_full_data(c, rng, |c, id, scope, rng, data| {
                f(c, id, scope, rng, data.device_mle);
            });
        }
    }

    impl BenchKind for FullKind {
        type Input<'a> = RealTraceData<'a>;

        fn run<R, F>(c: &mut Criterion, rng: &mut R, f: F)
        where
            R: Rng,
            F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, RealTraceData<'_>),
        {
            dispatch_full_data(c, rng, f);
        }
    }

    /// Single entry point for source-aware benches. Routes through `K`'s [`BenchKind::run`] impl.
    /// The `_kind` value is purely for type inference; pass the appropriate marker:
    ///
    /// ```text
    /// cargo bench --bench <name>                          # → random, default 2^25
    /// cargo bench --bench <name> -- random:24             # → random, 2^24
    /// cargo bench --bench <name> -- random:22,24,26       # → sweep 3 sizes
    /// cargo bench --bench <name> -- /path/to/layout.json  # → that JSON
    /// cargo bench --bench <name> -- real/keccak256        # → that real program
    /// ```
    pub fn with_trace_source<K, R, F>(c: &mut Criterion, rng: &mut R, _kind: K, f: F)
    where
        K: BenchKind,
        R: Rng,
        F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, K::Input<'_>),
    {
        K::run(c, rng, f);
    }

    /// Inner dispatcher used by both `JaggedKind` and `FullKind`. Always produces a
    /// `RealTraceData` for the user's closure: real sources use the actual data from
    /// `full_tracegen`; synthetic sources synthesize `chip_set` and `public_values`.
    fn dispatch_full_data<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
    where
        R: Rng,
        F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, RealTraceData<'_>),
    {
        match TraceSource::from_cli_args() {
            TraceSource::Random(sizes) => {
                // Bench IDs we register (`random/total_area_2^N`) don't contain the user's
                // source arg verbatim (e.g. `random:24` has a colon; sweep args have commas), so
                // Criterion's substring CLI filter would drop them. With Random as the chosen
                // source, every bench we register here is intended to run.
                *c = std::mem::take(c).with_benchmark_filter(BenchmarkFilter::AcceptAll);
                let sizes = if sizes.is_empty() { vec![DEFAULT_RANDOM_LOG_AREA] } else { sizes };
                for log_area in sizes {
                    let c: &mut Criterion = &mut *c;
                    let rng: &mut R = &mut *rng;
                    let f: &mut F = &mut f;
                    with_random(c, log_area, rng, |c, id, scope, rng, mle| {
                        let machine = RiscvAir::<Felt>::machine();
                        let chip_set: BTreeSet<_> = machine.chips().iter().cloned().collect();
                        let public_values = vec![Felt::zero(); SP1_PROOF_NUM_PV_ELTS];
                        let data = RealTraceData {
                            machine: &machine,
                            chip_set: &chip_set,
                            public_values: &public_values,
                            device_mle: mle,
                        };
                        f(c, id, scope, rng, data);
                    });
                }
            }
            TraceSource::Json(path) => {
                with_json(c, &path, rng, |c, id, scope, rng, mle| {
                    let machine = RiscvAir::<Felt>::machine();
                    let chip_set: BTreeSet<_> = machine.chips().iter().cloned().collect();
                    let public_values = vec![Felt::zero(); SP1_PROOF_NUM_PV_ELTS];
                    let data = RealTraceData {
                        machine: &machine,
                        chip_set: &chip_set,
                        public_values: &public_values,
                        device_mle: mle,
                    };
                    f(c, id, scope, rng, data);
                });
            }
            TraceSource::Real { name, elf } => with_real(c, name, elf, rng, f),
        }
    }

    fn with_random<R, F>(c: &mut Criterion, log_area: u32, rng: &mut R, f: F)
    where
        R: Rng,
        F: FnOnce(
            &mut Criterion,
            BenchmarkId,
            &TaskScope,
            &mut R,
            &JaggedTraceMle<Felt, TaskScope>,
        ),
    {
        run_sync_in_place(move |scope| {
            let machine = RiscvAir::<Felt>::machine();
            let total_area = 1u64 << log_area;
            let device_mle = random_jagged_trace_mle::<Felt, _, _>(
                rng,
                machine.chips(),
                total_area,
                LOG_STACKING_HEIGHT,
            )
            .into_device(&scope);
            let id = BenchmarkId::new("random", format!("total_area_2^{log_area}"));
            f(c, id, &scope, rng, &device_mle);
        })
        .unwrap();
    }

    fn with_json<R, F>(c: &mut Criterion, path: &str, rng: &mut R, f: F)
    where
        R: Rng,
        F: FnOnce(
            &mut Criterion,
            BenchmarkId,
            &TaskScope,
            &mut R,
            &JaggedTraceMle<Felt, TaskScope>,
        ),
    {
        run_sync_in_place(move |scope| {
            let device_mle =
                random_jagged_trace_mle_from_json::<Felt, _>(rng, path, LOG_STACKING_HEIGHT)
                    .expect("failed to read JSON layout")
                    .into_device(&scope);
            let id = BenchmarkId::new("json", path);
            f(c, id, &scope, rng, &device_mle);
        })
        .unwrap();
    }

    fn with_real<R, F>(c: &mut Criterion, name: &'static str, elf: &'static [u8], rng: &mut R, f: F)
    where
        R: Rng,
        F: FnOnce(&mut Criterion, BenchmarkId, &TaskScope, &mut R, RealTraceData<'_>),
    {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            let (machine, record, program) = tracegen_setup::setup(elf, SP1Stdin::new()).await;
            run_in_place(|scope| async move {
                let buffer = PinnedBuffer::<Felt>::with_capacity(CORE_MAX_TRACE_SIZE as usize);
                let queue = Arc::new(WorkerQueue::new(vec![buffer]));
                let buffer = queue.pop().await.unwrap();
                let (public_values, jagged_trace_data, chip_set, _permit) = full_tracegen(
                    &machine,
                    program.clone(),
                    Arc::new(record),
                    &buffer,
                    CORE_MAX_TRACE_SIZE as usize,
                    LOG_STACKING_HEIGHT,
                    CORE_MAX_LOG_ROW_COUNT,
                    &scope,
                    ProverSemaphore::new(1),
                    true,
                )
                .await;
                let area = jagged_trace_data.dense().dense.len();
                eprintln!(
                    "real/{name} trace area: 2^{:.2} ({area} field elements)",
                    (area as f64).log2(),
                );
                let id = BenchmarkId::new("real", name);
                let data = RealTraceData {
                    machine: &machine,
                    chip_set: &chip_set,
                    public_values: &public_values,
                    device_mle: &jagged_trace_data,
                };
                f(c, id, &scope, rng, data);
            })
            .await;
        });
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod tracegen_setup {
    use sp1_core_executor::{ExecutionRecord, Program, SP1CoreOpts};
    use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir, utils::generate_records};
    use sp1_hypercube::{air::PROOF_NONCE_NUM_WORDS, Machine};
    use std::sync::Arc;

    use sp1_gpu_utils::Felt;

    pub const CORE_MAX_LOG_ROW_COUNT: u32 = 22;
    pub const LOG_STACKING_HEIGHT: u32 = 21;

    /// Execute the given ELF with the provided stdin and return the machine, first record, and
    /// program for use in tracegen tests.
    pub async fn setup(
        elf: &[u8],
        stdin: SP1Stdin,
    ) -> (Machine<Felt, RiscvAir<Felt>>, ExecutionRecord, Arc<Program>) {
        let program =
            Arc::new(Program::from(elf).expect("Failed to load ELF - file may be corrupted"));

        let sp1_core_opts = SP1CoreOpts { global_dependencies_opt: true, ..Default::default() };
        let (records, _cycles) = generate_records::<Felt>(
            program.clone(),
            stdin,
            sp1_core_opts,
            [0; PROOF_NONCE_NUM_WORDS],
        )
        .expect("failed to generate records");

        let record = records[0].clone();
        let machine = RiscvAir::<Felt>::machine();

        (machine, record, program)
    }
}
