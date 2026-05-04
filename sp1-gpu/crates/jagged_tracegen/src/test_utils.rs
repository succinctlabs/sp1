//! Common test utilities shared across test modules.

/// Benchmark helpers shared across the per-crate Criterion benches. A single bench invocation
/// runs against one trace source (random / JSON / real ELF), picked from CLI args. See
/// [`bench_utils::with_trace_source`].
#[cfg(any(test, feature = "test-utils"))]
pub mod bench_utils {
    use std::sync::Arc;

    use std::collections::BTreeSet;

    use criterion::{BenchmarkId, Criterion};
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

    /// Total area for the synthetic random trace, in dense field elements.
    pub const RANDOM_TOTAL_AREA: u64 = 1 << 25;

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
        /// Synthetic trace with random column heights summing to [`RANDOM_TOTAL_AREA`].
        Random,
        /// Trace built from a JSON layout file.
        Json(String),
        /// Trace from an actual zkVM execution of a sample program.
        Real { name: &'static str, elf: &'static [u8] },
    }

    impl TraceSource {
        /// Pick a source from CLI args, in priority order:
        ///
        /// 1. Any positional arg ending in `.json` → [`TraceSource::Json`] with that path.
        /// 2. Any positional arg matching (substring) a known [`real_programs`] entry → that one.
        /// 3. Otherwise → [`TraceSource::Random`].
        ///
        /// This means `cargo bench --bench <name>` (no args) defaults to random; pass an explicit
        /// arg to override.
        pub fn from_cli_args() -> Self {
            let positional: Vec<String> =
                std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();

            if let Some(path) = positional.iter().find(|a| a.ends_with(".json")) {
                return Self::Json(path.clone());
            }
            for (name, elf) in real_programs() {
                let id = format!("real/{name}");
                if positional.iter().any(|a| id.contains(a) || a.contains(&id)) {
                    return Self::Real { name, elf };
                }
            }
            Self::Random
        }
    }

    /// Build the trace MLE for the picked source and hand it to `f`. Wires the bench under one of
    /// `random/total_area_2^N`, `json/<path>`, or `real/<name>`. The bench ID's parameter is
    /// chosen so Criterion's substring CLI filter matches the same arg the user passed.
    ///
    /// `rng` is shared with the trace generator (random / JSON variants don't touch it for the
    /// real variant) and forwarded to `f` so the caller's per-iter sampling continues from the
    /// same stream — a single seed governs the whole bench.
    ///
    /// Examples:
    ///
    /// ```text
    /// cargo bench --bench <name>                        # → random
    /// cargo bench --bench <name> -- /path/to/layout.json # → that JSON
    /// cargo bench --bench <name> -- real/keccak256      # → that real program
    /// ```
    pub fn with_trace_source<R, F>(c: &mut Criterion, rng: &mut R, f: F)
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
        match TraceSource::from_cli_args() {
            TraceSource::Random => with_random(c, rng, f),
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

    fn with_random<R, F>(c: &mut Criterion, rng: &mut R, f: F)
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
            let device_mle = random_jagged_trace_mle::<Felt, _, _>(
                rng,
                machine.chips(),
                RANDOM_TOTAL_AREA,
                LOG_STACKING_HEIGHT,
            )
            .into_device(&scope);
            let id =
                BenchmarkId::new("random", format!("total_area_2^{}", RANDOM_TOTAL_AREA.ilog2()));
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

        if let Some(unsupported) =
            positional.iter().find(|a| a.ends_with(".json") || a.as_str() == "random")
        {
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
