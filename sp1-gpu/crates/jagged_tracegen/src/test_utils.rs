//! Common test utilities shared across test modules.

/// Benchmark helpers shared across the per-crate Criterion benches. A single bench invocation
/// runs against one trace source (random / JSON / real ELF), picked from CLI args. See
/// [`bench_utils::with_trace_source`].
#[cfg(any(test, feature = "test-utils"))]
pub mod bench_utils {
    use std::sync::Arc;

    use std::collections::BTreeSet;

    use criterion::{BenchmarkFilter, BenchmarkId, Criterion};
    use rand::Rng;
    use slop_futures::queue::WorkerQueue;
    use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir};
    use sp1_gpu_cudart::{run_in_place, run_sync_in_place, PinnedBuffer, TaskScope};
    use sp1_gpu_utils::test_utils::random::{
        random_jagged_trace_mle, random_jagged_trace_mle_from_json,
    };
    use sp1_gpu_utils::{Felt, JaggedTraceMle};
    use sp1_hypercube::prover::ProverSemaphore;
    use sp1_hypercube::{Chip, Machine};

    /// All the artifacts a real-trace bench gets after [`with_real_trace_source`] runs setup.
    /// Beyond `device_mle`, this exposes `machine`, the post-tracegen `chip_set`, and
    /// `public_values` — all needed by benches like `zerocheck` that walk the chip layout.
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
        assert!(
            !sizes.is_empty(),
            "empty size list in `{arg}`; use `random` for the default",
        );
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

    /// Build the trace MLE for the picked source and hand it to `f`. Wires the bench under one of
    /// `random/total_area_2^N`, `json/<path>`, or `real/<name>`. The bench ID's parameter is
    /// chosen so Criterion's substring CLI filter matches the same arg the user passed.
    ///
    /// For the random source the user may supply a list of log-areas (e.g. `random:22,24,26`),
    /// in which case `f` is called once per size — `f` therefore must be `FnMut`.
    ///
    /// `rng` is shared with the trace generator (the real variant doesn't touch it) and forwarded
    /// to `f` so the caller's per-iter sampling continues from the same stream — a single seed
    /// governs the whole bench.
    ///
    /// Examples:
    ///
    /// ```text
    /// cargo bench --bench <name>                          # → random, default 2^25
    /// cargo bench --bench <name> -- random:24             # → random, 2^24
    /// cargo bench --bench <name> -- random:22,24,26       # → sweep 3 sizes
    /// cargo bench --bench <name> -- /path/to/layout.json  # → that JSON
    /// cargo bench --bench <name> -- real/keccak256        # → that real program
    /// ```
    pub fn with_trace_source<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
    where
        R: Rng,
        F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, &JaggedTraceMle<Felt, TaskScope>),
    {
        match TraceSource::from_cli_args() {
            TraceSource::Random(sizes) => {
                let sizes = if sizes.is_empty() { vec![DEFAULT_RANDOM_LOG_AREA] } else { sizes };
                for log_area in sizes {
                    // Reborrow per iter so the FnOnce wrapper handed to `with_random` doesn't
                    // permanently consume `c` / `rng` / `f`.
                    let c: &mut Criterion = &mut *c;
                    let rng: &mut R = &mut *rng;
                    let f: &mut F = &mut f;
                    with_random(c, log_area, rng, |c, id, scope, rng, mle| {
                        f(c, id, scope, rng, mle);
                    });
                }
            }
            TraceSource::Json(path) => with_json(c, &path, rng, f),
            // Adapt: the real-data path produces a `RealTraceData`; this helper's caller only
            // wants the trace itself, so unwrap `device_mle` and discard the rest.
            TraceSource::Real { name, elf } => {
                with_real(c, name, elf, rng, |c, id, scope, rng, data| {
                    f(c, id, scope, rng, data.device_mle);
                });
            }
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

    /// Like [`with_trace_source`] but for benches that can't operate on synthetic data — for
    /// example, anything that needs constraint-satisfying traces. If the user picks a `random`
    /// or `.json` source from the CLI, the bench prints a one-line skip message and returns
    /// without running. With no CLI arg, defaults to the first entry in [`real_programs`] so
    /// `cargo bench --bench <name>` Just Works.
    ///
    /// The closure receives a [`RealTraceData`] with the trace plus the surrounding `machine`,
    /// `chip_set`, and `public_values`
    pub fn with_real_trace_source<R, F>(c: &mut Criterion, rng: &mut R, f: F)
    where
        R: Rng,
        F: FnOnce(&mut Criterion, BenchmarkId, &TaskScope, &mut R, RealTraceData<'_>),
    {
        let positional: Vec<String> =
            std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();

        if let Some(unsupported) = positional.iter().find(|a| {
            a.ends_with(".json") || a.as_str() == "random" || a.starts_with("random:")
        }) {
            eprintln!(
                "skipping bench: the `{unsupported}` source isn't supported (needs real trace \
                 data). Pass `-- real/<program>` (or no arg for the default) instead."
            );
            return;
        }

        let pick = real_programs().into_iter().find(|(name, _)| {
            let id = format!("real/{name}");
            positional.iter().any(|a| id.contains(a) || a.contains(&id))
        });
        let (name, elf) =
            pick.unwrap_or_else(|| real_programs().into_iter().next().expect("no real programs"));

        with_real(c, name, elf, rng, f);
    }

    /// For benches whose inputs don't fit the trace-source machinery (e.g. `hadamard`, which
    /// runs on flat `Mle`s rather than a `JaggedTraceMle`). Overrides Criterion's CLI filter to
    /// accept every bench in this binary so the bench runs no matter what `--source` arg the
    /// caller passed — without this, any positional like `random` / `real/...` / `*.json` would
    /// be applied as a filter and silently drop benches whose IDs don't contain it.
    pub fn with_default_trace_source<F>(c: &mut Criterion, f: F)
    where
        F: FnOnce(&mut Criterion),
    {
        *c = std::mem::take(c).with_benchmark_filter(BenchmarkFilter::AcceptAll);
        f(c);
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
