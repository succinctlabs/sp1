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
    use sp1_gpu_cudart::{run_sync_in_place, PinnedBuffer, TaskScope};
    use sp1_gpu_utils::test_utils::random::{
        random_jagged_trace_mle, random_jagged_trace_mle_from_layout, read_layout_from_json,
    };
    use sp1_gpu_utils::{Felt, JaggedTraceMle};
    use sp1_hypercube::air::{MachineAir, SP1_PROOF_NUM_PV_ELTS};
    use sp1_hypercube::prover::ProverSemaphore;
    use sp1_hypercube::{Chip, Machine};

    /// All the artifacts a [`FullKind`] bench gets. `cluster` is the chip set the bench should
    /// iterate when slicing per-chip evaluations — for the real source it's the program's actual
    /// `smallest_cluster`; for synthetic sources it's the chip set the trace was built from
    /// (sorted alphabetically to match `BTreeSet` iteration order).
    ///
    /// `public_values` is real for the real source and a zero-filled vector of the right length
    /// for synthetic sources. Values don't need to be meaningful for timing (the prover doesn't
    /// validate them), but the shape has to be consistent.
    pub struct RealTraceData {
        pub machine: Machine<Felt, RiscvAir<Felt>>,
        pub cluster: BTreeSet<Chip<Felt, RiscvAir<Felt>>>,
        pub public_values: Vec<Felt>,
        pub device_mle: JaggedTraceMle<Felt, TaskScope>,
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
            ("fibonacci_blake3", &test_artifacts::FIBONACCI_BLAKE3_ELF),
            ("ed25519", &test_artifacts::ED25519_ELF),
            ("keccak256", &test_artifacts::KECCAK256_ELF),
            ("sha2", &test_artifacts::SHA2_ELF),
            ("ssz_withdrawals", &test_artifacts::SSZ_WITHDRAWALS_ELF),
            ("tendermint", &test_artifacts::TENDERMINT_BENCHMARK_ELF),
            ("groth16", &test_artifacts::GROTH16_ELF),
            ("groth16_blake3", &test_artifacts::GROTH16_BLAKE3_ELF),
            ("plonk", &test_artifacts::PLONK_ELF),
            ("plonk_blake3", &test_artifacts::PLONK_BLAKE3_ELF),
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

    /// Marker trait controlling the data shape `with_trace_source` invokes the bench with.
    /// Implementors are unit structs ([`NoneKind`], [`JaggedKind`], [`FullKind`]) so the bench
    /// declares its needs by name and the type system carries the rest.
    ///
    /// Each Kind provides three pure data generators (one per source). The default [`run`]
    /// parses the CLI source enum, opens a [`TaskScope`], calls the right generator, then
    /// invokes the user's closure with the resulting [`GeneratedData`]. Kinds that don't fit
    /// the source-dispatch shape (currently [`NoneKind`]) override `run` directly; their
    /// generator methods then become dead code, hence the trivial impls.
    pub trait BenchKind: Sized {
        /// The owned data the helper hands to the user's closure.
        type GeneratedData;

        fn generate_random_data<R: Rng>(
            scope: &TaskScope,
            log_area: u32,
            rng: &mut R,
        ) -> Self::GeneratedData;

        fn generate_json_data<R: Rng>(
            scope: &TaskScope,
            path: &str,
            rng: &mut R,
        ) -> Self::GeneratedData;

        fn generate_real_data<R: Rng>(
            scope: &TaskScope,
            name: &'static str,
            elf: &'static [u8],
            rng: &mut R,
        ) -> Self::GeneratedData;

        /// Default: parse CLI source, open a scope, generate data via the right method, call
        /// `f`. Sweep mode loops over sizes for random. Override only if the Kind doesn't
        /// follow source dispatch (see [`NoneKind`]).
        fn run<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
        where
            R: Rng,
            F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, Self::GeneratedData),
        {
            match TraceSource::from_cli_args() {
                TraceSource::Random(sizes) => {
                    // Bench IDs we register (`random/total_area_2^N`) don't contain the user's
                    // source arg verbatim (e.g. `random:24` has a colon; sweep args have commas),
                    // so Criterion's substring CLI filter would drop them. With Random selected,
                    // every bench we register here is intended to run.
                    *c = std::mem::take(c).with_benchmark_filter(BenchmarkFilter::AcceptAll);
                    let sizes =
                        if sizes.is_empty() { vec![DEFAULT_RANDOM_LOG_AREA] } else { sizes };
                    for log_area in sizes {
                        let c: &mut Criterion = &mut *c;
                        let rng: &mut R = &mut *rng;
                        let f: &mut F = &mut f;
                        run_sync_in_place(move |scope| {
                            let data = Self::generate_random_data(&scope, log_area, rng);
                            let id =
                                BenchmarkId::new("random", format!("total_area_2^{log_area}"));
                            f(c, id, &scope, rng, data);
                        })
                        .unwrap();
                    }
                }
                TraceSource::Json(path) => {
                    run_sync_in_place(move |scope| {
                        let data = Self::generate_json_data(&scope, &path, rng);
                        let id = BenchmarkId::new("json", &path);
                        f(c, id, &scope, rng, data);
                    })
                    .unwrap();
                }
                TraceSource::Real { name, elf } => {
                    run_sync_in_place(move |scope| {
                        let data = Self::generate_real_data(&scope, name, elf, rng);
                        let id = BenchmarkId::new("real", name);
                        f(c, id, &scope, rng, data);
                    })
                    .unwrap();
                }
            }
        }
    }

    /// `GeneratedData = ()`. For benches whose inputs aren't a `JaggedTraceMle` (e.g. `hadamard`).
    /// Ignores the `--source` arg entirely; overrides Criterion's filter to accept-all so a
    /// user-passed `--source <X>` doesn't drop the bench, opens a `TaskScope`, calls `f` once.
    pub struct NoneKind;

    /// `GeneratedData = JaggedTraceMle<Felt, TaskScope>`. For benches that just need the trace.
    /// Source picked from CLI as random / JSON / real.
    pub struct JaggedKind;

    /// `GeneratedData = RealTraceData`. For benches that need the full execution context
    /// (machine, cluster, public_values) in addition to the trace. Source picked from CLI as
    /// random / JSON / real; for synthetic sources `cluster` and `public_values` are
    /// synthesized.
    pub struct FullKind;

    impl BenchKind for NoneKind {
        type GeneratedData = ();

        // Trivial generators — never invoked in practice because `run` is overridden, but
        // present so the trait contract is satisfied without `unreachable!()` smell.
        fn generate_random_data<R: Rng>(_: &TaskScope, _: u32, _: &mut R) {}
        fn generate_json_data<R: Rng>(_: &TaskScope, _: &str, _: &mut R) {}
        fn generate_real_data<R: Rng>(_: &TaskScope, _: &'static str, _: &'static [u8], _: &mut R) {
        }

        /// Override: bypass source dispatch entirely. AcceptAll filter + scope + call once.
        fn run<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
        where
            R: Rng,
            F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, ()),
        {
            *c = std::mem::take(c).with_benchmark_filter(BenchmarkFilter::AcceptAll);
            run_sync_in_place(move |scope| {
                // Sentinel id; the bench typically registers its own group / bench_function.
                let id = BenchmarkId::new("default", "default");
                f(c, id, &scope, rng, ());
            })
            .unwrap();
        }
    }

    impl BenchKind for JaggedKind {
        type GeneratedData = JaggedTraceMle<Felt, TaskScope>;

        fn generate_random_data<R: Rng>(
            scope: &TaskScope,
            log_area: u32,
            rng: &mut R,
        ) -> JaggedTraceMle<Felt, TaskScope> {
            let chips = sorted_machine_chips();
            let total_area = 1u64 << log_area;
            random_jagged_trace_mle::<Felt, _, _>(rng, &chips, total_area, LOG_STACKING_HEIGHT)
                .into_device(scope)
        }

        fn generate_json_data<R: Rng>(
            scope: &TaskScope,
            path: &str,
            rng: &mut R,
        ) -> JaggedTraceMle<Felt, TaskScope> {
            let layout = read_layout_from_json(path).expect("failed to read JSON layout");
            random_jagged_trace_mle_from_layout::<Felt, _>(rng, &layout, LOG_STACKING_HEIGHT)
                .into_device(scope)
        }

        fn generate_real_data<R: Rng>(
            scope: &TaskScope,
            name: &'static str,
            elf: &'static [u8],
            _rng: &mut R,
        ) -> JaggedTraceMle<Felt, TaskScope> {
            block_on_real_trace(scope, name, elf).device_mle
        }
    }

    impl BenchKind for FullKind {
        type GeneratedData = RealTraceData;

        fn generate_random_data<R: Rng>(
            scope: &TaskScope,
            log_area: u32,
            rng: &mut R,
        ) -> RealTraceData {
            let machine = RiscvAir::<Felt>::machine();
            let chips = sorted_machine_chips();
            let cluster: BTreeSet<_> = chips.iter().cloned().collect();
            let total_area = 1u64 << log_area;
            let device_mle =
                random_jagged_trace_mle::<Felt, _, _>(rng, &chips, total_area, LOG_STACKING_HEIGHT)
                    .into_device(scope);
            let public_values = vec![Felt::zero(); SP1_PROOF_NUM_PV_ELTS];
            RealTraceData { machine, cluster, public_values, device_mle }
        }

        fn generate_json_data<R: Rng>(
            scope: &TaskScope,
            path: &str,
            rng: &mut R,
        ) -> RealTraceData {
            let layout = read_layout_from_json(path).expect("failed to read JSON layout");
            let machine = RiscvAir::<Felt>::machine();
            let cluster = cluster_from_json_layout(&machine, &layout);
            let device_mle =
                random_jagged_trace_mle_from_layout::<Felt, _>(rng, &layout, LOG_STACKING_HEIGHT)
                    .into_device(scope);
            let public_values = vec![Felt::zero(); SP1_PROOF_NUM_PV_ELTS];
            RealTraceData { machine, cluster, public_values, device_mle }
        }

        fn generate_real_data<R: Rng>(
            scope: &TaskScope,
            name: &'static str,
            elf: &'static [u8],
            _rng: &mut R,
        ) -> RealTraceData {
            block_on_real_trace(scope, name, elf)
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
        F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, K::GeneratedData),
    {
        K::run(c, rng, f);
    }

    // -------------------------------------------------------------------------
    // Shared private helpers: source-agnostic building blocks.
    // -------------------------------------------------------------------------

    /// Sort `machine.chips()` by `Chip`'s `Ord` (= by name). Real tracegen lays out chips in
    /// BTreeMap order (alphabetical); `BTreeSet<Chip>` iteration is alphabetical too. The
    /// synthetic trace's chip layout has to match for downstream per-chip slicing to land on
    /// the right columns.
    fn sorted_machine_chips() -> Vec<Chip<Felt, RiscvAir<Felt>>> {
        let mut chips = RiscvAir::<Felt>::machine().chips().to_vec();
        chips.sort();
        chips
    }

    /// Look up each JSON chip name against the machine and return a BTreeSet of the matching
    /// Chip values. Panics if any name is unknown.
    fn cluster_from_json_layout(
        machine: &Machine<Felt, RiscvAir<Felt>>,
        layout: &sp1_gpu_utils::AbstractChipLayoutWithHeights,
    ) -> BTreeSet<Chip<Felt, RiscvAir<Felt>>> {
        let by_name: std::collections::HashMap<&str, &Chip<Felt, RiscvAir<Felt>>> =
            machine.chips().iter().map(|c| (c.name(), c)).collect();
        layout
            .chip_names()
            .map(|name| {
                by_name
                    .get(name)
                    .copied()
                    .unwrap_or_else(|| panic!("JSON chip `{name}` not present in RiscvAir machine"))
                    .clone()
            })
            .collect()
    }

    /// Drive the async real-trace tracegen against an existing `scope` and return the resulting
    /// owned `RealTraceData`. Used by both `JaggedKind::generate_real_data` (which then drops
    /// everything but `device_mle`) and `FullKind::generate_real_data`.
    fn block_on_real_trace(
        scope: &TaskScope,
        name: &'static str,
        elf: &'static [u8],
    ) -> RealTraceData {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let (machine, record, program) = tracegen_setup::setup(elf, SP1Stdin::new()).await;
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
                scope,
                ProverSemaphore::new(1),
                true,
            )
            .await;
            let area = jagged_trace_data.dense().dense.len();
            eprintln!(
                "real/{name} trace area: 2^{:.2} ({area} field elements)",
                (area as f64).log2(),
            );
            let cluster = machine
                .smallest_cluster(&chip_set)
                .expect("no machine cluster contains the program's chip set")
                .clone();
            RealTraceData {
                machine,
                cluster,
                public_values,
                device_mle: jagged_trace_data,
            }
        })
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
