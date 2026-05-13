//! Common test utilities shared across test modules.
//!
//! This crate is the home for trace-related test infrastructure: pure-host random trace
//! generators (the [`random`] module), the source-aware Criterion bench dispatcher
//! ([`bench_utils`]), and the async real-trace setup helper ([`tracegen_setup`]).

/// Pure host-side random trace generators. Used by [`bench_utils`] to build the
/// synthetic-source trace MLEs (random / JSON layout) before they're moved to the device.
///
/// Heights from [`generate_random_heights`] are aligned to multiples of 32 to match the
/// alignment that real shard tracegen produces via `pad_rows_fixed`
/// (`sp1_hypercube::util`). The looser-looking
/// `next_start_indices_and_column_heights` (`h.div_ceil(4) * 2`) only needs even heights,
/// but the GKR first-layer construction divides by 4 (`tracegen::generate_first_layer`)
/// and then halves repeatedly, so the effective requirement is "stay even all the way
/// down" — multiples of 32 give us margin and keep synthetic heights shaped like real
/// shards.
#[cfg(any(test, feature = "test-utils"))]
pub mod random {
    use std::path::Path;

    use rand::{
        distributions::{Distribution, Standard},
        Rng,
    };
    use serde::Deserialize;
    use slop_air::BaseAir;
    use slop_algebra::Field;
    use slop_alloc::{Buffer, CpuBackend};
    use sp1_gpu_utils::{AbstractChipLayout, AbstractChipLayoutWithHeights, JaggedTraceMle};
    use sp1_hypercube::{air::MachineAir, Chip};

    /// Build an [`AbstractChipLayout`] from a slice of [`Chip`]s, reading each chip's
    /// name and preprocessed/main widths.
    ///
    /// Free function rather than an inherent method on `AbstractChipLayout` because that
    /// type is defined in `sp1-gpu-utils`, which has no `Chip`/`MachineAir` dependency —
    /// the orphan rule and minimal-deps philosophy both push this construction down here.
    pub fn chip_layout_from_chips<F, A>(chips: &[Chip<F, A>]) -> AbstractChipLayout
    where
        F: Field,
        A: MachineAir<F>,
    {
        AbstractChipLayout::new(
            chips
                .iter()
                .map(|c| (c.air.name().to_string(), c.preprocessed_width(), c.width()))
                .collect(),
        )
    }

    /// One chip's entry in the JSON file consumed by [`read_layout_from_json`].
    #[derive(Deserialize)]
    struct ChipEntry {
        name: String,
        preprocessed_width: usize,
        main_width: usize,
        height: usize,
    }

    /// Read an [`AbstractChipLayoutWithHeights`] from a JSON file.
    ///
    /// The file must be a top-level JSON array of objects, each with the fields
    /// `name`, `preprocessed_width`, `main_width`, and `height`:
    ///
    /// ```json
    /// [
    ///   {"name": "Cpu",    "preprocessed_width": 4, "main_width": 64, "height": 1024},
    ///   {"name": "Memory", "preprocessed_width": 0, "main_width": 32, "height": 512}
    /// ]
    /// ```
    pub fn read_layout_from_json(
        path: impl AsRef<Path>,
    ) -> std::io::Result<AbstractChipLayoutWithHeights> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let entries: Vec<ChipEntry> = serde_json::from_reader(reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(AbstractChipLayoutWithHeights::new(
            entries
                .into_iter()
                .map(|e| (e.name, e.preprocessed_width, e.main_width, e.height))
                .collect(),
        ))
    }

    /// Randomly partition `total_area` field elements among the chips in `layout`,
    /// returning a per-chip row count.
    ///
    /// Every chip is guaranteed at least one 32-row block; downstream consumers like
    /// `round_batch_evaluations` walk the column index expecting one evaluation per
    /// non-zero-height column and underflow if any chip is left empty. Panics if
    /// `total_area` is too small to give every chip its minimum allocation. After the
    /// floor allocation, the remaining budget is distributed greedily: pick a random
    /// fitting chip and give it a random number of 32-row blocks until no chip fits in
    /// the leftover.
    pub fn generate_random_heights<R: Rng>(
        rng: &mut R,
        layout: &AbstractChipLayout,
        total_area: u64,
    ) -> AbstractChipLayoutWithHeights {
        const ALIGN: usize = 32;

        let entries = layout.entries();

        // Cost per row: each row contributes `preprocessed_width + width` field
        // elements to the dense buffer.
        let row_costs: Vec<u64> = entries.iter().map(|(_, p, m)| (p + m) as u64).collect();

        // Floor: every chip gets one ALIGN-row block up front so no chip is left at h=0.
        let min_total: u64 = row_costs.iter().sum::<u64>() * ALIGN as u64;
        assert!(
            total_area >= min_total,
            "total_area = {total_area} is too small to give every chip {ALIGN} rows \
             (need at least {min_total})",
        );

        let mut heights = vec![ALIGN; entries.len()];
        let mut remaining = total_area - min_total;
        loop {
            let candidates: Vec<usize> =
                (0..entries.len()).filter(|&i| row_costs[i] * ALIGN as u64 <= remaining).collect();
            if candidates.is_empty() {
                break;
            }
            let i = candidates[rng.gen_range(0..candidates.len())];
            let max_blocks = remaining / (row_costs[i] * ALIGN as u64);
            let blocks = rng.gen_range(1..=max_blocks);
            heights[i] += blocks as usize * ALIGN;
            remaining -= blocks * row_costs[i] * ALIGN as u64;
        }

        AbstractChipLayoutWithHeights::new(
            entries.iter().zip(heights).map(|((n, p, m), h)| (n.clone(), *p, *m, h)).collect(),
        )
    }

    /// Allocate a `padded_preprocessed + padded_main`-sized buffer of `F::zero()` and
    /// scribble uniformly-random field elements into the unpadded preprocessed and
    /// main regions, leaving the padding zero. The returned values do not satisfy
    /// any chip's AIR — this is purely structural.
    pub fn random_dense_buffer<F, R>(
        rng: &mut R,
        layout: &AbstractChipLayoutWithHeights,
        log_stacking_height: u32,
    ) -> Vec<F>
    where
        F: Field,
        Standard: Distribution<F>,
        R: Rng,
    {
        let stacking = 1usize << log_stacking_height;
        let entries = layout.entries();
        let total_preprocessed: usize = entries.iter().map(|(_, p, _, h)| p * h).sum();
        let total_main: usize = entries.iter().map(|(_, _, m, h)| m * h).sum();
        let padded_preprocessed = total_preprocessed.next_multiple_of(stacking);
        let padded_main = total_main.next_multiple_of(stacking);

        let mut data = vec![F::zero(); padded_preprocessed + padded_main];
        for slot in &mut data[..total_preprocessed] {
            *slot = rng.sample(Standard);
        }
        for slot in &mut data[padded_preprocessed..padded_preprocessed + total_main] {
            *slot = rng.sample(Standard);
        }
        data
    }

    /// Generate a random [`JaggedTraceMle`] for the given `layout` and per-chip row
    /// counts. The dense buffer is filled with uniformly-random field elements in
    /// the unpadded regions; padding regions are zero.
    ///
    /// Requires log_stacking_height as an input to compute padding for the preprocessed
    /// and main regions.
    pub fn random_jagged_trace_mle_from_layout<F, R>(
        rng: &mut R,
        layout: &AbstractChipLayoutWithHeights,
        log_stacking_height: u32,
    ) -> JaggedTraceMle<F, CpuBackend>
    where
        F: Field,
        Standard: Distribution<F>,
        R: Rng,
    {
        let data = random_dense_buffer(rng, layout, log_stacking_height);
        JaggedTraceMle::from_chip_layout(Buffer::from(data), layout, log_stacking_height)
    }

    /// Generate a random [`JaggedTraceMle`] whose total dense size (preprocessed +
    /// main, before stacking-height padding) is approximately `total_area` field
    /// elements, partitioned randomly among `chips` via [`generate_random_heights`].
    ///
    /// Requires log_stacking_height as an input to compute padding for the preprocessed
    /// and main regions.
    pub fn random_jagged_trace_mle<F, A, R>(
        rng: &mut R,
        chips: &[Chip<F, A>],
        total_area: u64,
        log_stacking_height: u32,
    ) -> JaggedTraceMle<F, CpuBackend>
    where
        F: Field,
        A: MachineAir<F>,
        Standard: Distribution<F>,
        R: Rng,
    {
        assert!(!chips.is_empty(), "must have at least one chip");

        let layout = chip_layout_from_chips(chips);
        let layout_with_heights = generate_random_heights(rng, &layout, total_area);
        random_jagged_trace_mle_from_layout(rng, &layout_with_heights, log_stacking_height)
    }

    /// Read a chip layout and per-chip heights from a JSON file (see
    /// [`read_layout_from_json`] for the schema) and produce a random
    /// [`JaggedTraceMle`] with that shape.
    ///
    /// Requires log_stacking_height as an input to compute padding for the preprocessed
    /// and main regions.
    pub fn random_jagged_trace_mle_from_json<F, R>(
        rng: &mut R,
        path: impl AsRef<Path>,
        log_stacking_height: u32,
    ) -> std::io::Result<JaggedTraceMle<F, CpuBackend>>
    where
        F: Field,
        Standard: Distribution<F>,
        R: Rng,
    {
        let layout_with_heights = read_layout_from_json(path)?;
        Ok(random_jagged_trace_mle_from_layout(rng, &layout_with_heights, log_stacking_height))
    }
}

/// Benchmark helpers shared across the per-crate Criterion benches. A single
/// [`with_trace_source`] entry point dispatches based on a [`BenchKind`] marker that controls what
/// shape of input the bench's closure receives — a log_2 area only ([`SizeOnlyKind`]), the
/// trace MLE ([`JaggedKind`]), or the full execution context ([`FullKind`]). The CLI source arg
/// (`random` / `json/<path>` / `real/<program>`) is parsed once and applied uniformly.
#[cfg(any(test, feature = "test-utils"))]
pub mod bench_utils {
    use std::ops::Add;
    use std::sync::Arc;

    use std::collections::BTreeSet;

    use criterion::{BenchmarkFilter, BenchmarkId, Criterion};
    use rand::Rng;
    use slop_algebra::AbstractField;
    use slop_futures::queue::WorkerQueue;
    use sp1_core_machine::riscv::AddChip;
    use sp1_core_machine::SupervisorMode;
    use sp1_core_machine::{io::SP1Stdin, riscv::RiscvAir};
    use sp1_gpu_cudart::{run_sync_in_place, PinnedBuffer, TaskScope};
    use sp1_gpu_utils::{Felt, JaggedTraceMle};

    use super::random::{
        random_jagged_trace_mle, random_jagged_trace_mle_from_layout, read_layout_from_json,
    };
    use sp1_hypercube::air::{MachineAir, SP1_PROOF_NUM_PV_ELTS};
    use sp1_hypercube::prover::ProverSemaphore;
    use sp1_hypercube::{Chip, Machine};

    /// All the artifacts a [`FullKind`] bench gets. `cluster` is the chip set the bench should
    /// iterate when slicing per-chip evaluations — for the real source it's the program's actual
    /// `smallest_cluster`; for synthetic sources it's the [`ChipCluster`] the user asked for
    /// (defaults to `Core`), resolved against the machine and used both as the trace's column
    /// layout and as the bench's iteration set (alphabetical, to match `BTreeSet` iteration).
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
        // TODO: fix real program workflow to use either S3 or local (similar to other scripts)
        vec![]
    }

    /// Which chip set a synthetic random trace should populate. The choice matters because
    /// downstream work (e.g. zerocheck constraint evaluation) iterates per chip — splitting the
    /// same area across more chips shifts the workload from per-row work toward per-chip
    /// constants and stops resembling any real shard.
    #[derive(Clone, Copy, Debug)]
    pub enum ChipCluster {
        /// The smallest cluster the machine knows about (≈ base RISC-V core, no extensions or
        /// precompiles). Default for `random`. Closest synthetic analogue to the cluster a
        /// fibonacci-shaped program would land in.
        Core,
        /// Every chip on the machine. Doesn't correspond to any real shard — use as a stress
        /// test or worst-case upper bound, not as an apples-to-apples comparison against a
        /// real program.
        AllChips,
    }

    impl ChipCluster {
        /// Stable short name used in bench ids and CLI parsing.
        fn name(self) -> &'static str {
            match self {
                ChipCluster::Core => "core",
                ChipCluster::AllChips => "all-chips",
            }
        }

        fn parse(s: &str) -> Option<Self> {
            match s {
                "core" => Some(ChipCluster::Core),
                "all-chips" => Some(ChipCluster::AllChips),
                _ => None,
            }
        }
    }

    /// Which trace source a bench should run against.
    pub enum TraceSource {
        /// Synthetic random trace(s). Each `u32` in `sizes` is a log_2 area in field elements;
        /// one bench is run per entry. Empty list means use the default
        /// [`DEFAULT_RANDOM_LOG_AREA`]. `cluster` controls which chip set the trace populates.
        Random { sizes: Vec<u32>, cluster: ChipCluster },
        /// Trace built from a JSON layout file.
        Json(String),
        /// Trace from an actual zkVM execution of a sample program.
        Real { name: &'static str, elf: &'static [u8] },
    }

    /// Detect a `random` / `random[:,]N[,N,...][,cluster=NAME]` arg. Returns `(sizes, cluster)`,
    /// where `sizes` is empty for plain `random` and `cluster` defaults to [`ChipCluster::Core`].
    /// Returns `None` if the arg doesn't start with `random`. Panics on inputs that start with
    /// `random` but don't match a known form (silent fallback would just look like the default
    /// behavior, which is a bad UX for typos like `random,cluster=foo` getting ignored).
    ///
    /// Both `:` and `,` are accepted as the separator after `random`, so e.g. either
    /// `random:cluster=all-chips` or `random,cluster=all-chips` works.
    fn parse_random_arg(arg: &str) -> Option<(Vec<u32>, ChipCluster)> {
        if arg == "random" {
            return Some((vec![], ChipCluster::Core));
        }
        if !arg.starts_with("random") {
            return None;
        }
        let rest = arg
            .strip_prefix("random:")
            .or_else(|| arg.strip_prefix("random,"))
            .unwrap_or_else(|| {
                panic!(
                    "invalid random spec `{arg}`; expected `random`, \
                     `random:N[,N,...][,cluster=NAME]`, or `random,cluster=NAME`"
                )
            });
        let mut sizes = Vec::new();
        let mut cluster = ChipCluster::Core;
        for part in rest.split(',') {
            let part = part.trim();
            if let Some(name) = part.strip_prefix("cluster=") {
                cluster = ChipCluster::parse(name).unwrap_or_else(|| {
                    panic!("unknown cluster `{name}` in `{arg}`; expected `core` or `all-chips`")
                });
            } else {
                let n = part.parse::<u32>().unwrap_or_else(|_| {
                    panic!("invalid item `{part}` in `{arg}`; expected `N` or `cluster=NAME`")
                });
                sizes.push(n);
            }
        }
        Some((sizes, cluster))
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
                if let Some((sizes, cluster)) = parse_random_arg(arg) {
                    return Self::Random { sizes, cluster };
                }
            }
            for (name, elf) in real_programs() {
                let id = format!("real/{name}");
                if positional.iter().any(|a| id.contains(a) || a.contains(&id)) {
                    return Self::Real { name, elf };
                }
            }
            Self::Random { sizes: vec![], cluster: ChipCluster::Core }
        }
    }

    /// Marker trait controlling the data shape `with_trace_source` invokes the bench with.
    /// Implementors are unit structs ([`SizeOnlyKind`], [`JaggedKind`], [`FullKind`]) so the
    /// bench declares its needs by name and the type system carries the rest.
    ///
    /// Each Kind provides three pure data generators (one per source). The default [`run`]
    /// parses the CLI source enum, opens a [`TaskScope`], calls the right generator, then
    /// invokes the user's closure with the resulting [`GeneratedData`]. Kinds that don't
    /// support every source (e.g. [`SizeOnlyKind`] only makes sense for `random`) panic from
    /// the unsupported generators with a clear message.
    pub trait BenchKind: Sized {
        /// The owned data the helper hands to the user's closure.
        type GeneratedData;

        fn generate_random_data<R: Rng>(
            scope: &TaskScope,
            log_area: u32,
            cluster: ChipCluster,
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
        /// `f`. Sweep mode loops over sizes for random.
        fn run<R, F>(c: &mut Criterion, rng: &mut R, mut f: F)
        where
            R: Rng,
            F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, Self::GeneratedData),
        {
            match TraceSource::from_cli_args() {
                TraceSource::Random { sizes, cluster } => {
                    // Bench IDs we register (`random/<cluster>_2^N`) don't contain the user's
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
                            let data = Self::generate_random_data(&scope, log_area, cluster, rng);
                            let id = BenchmarkId::new(
                                "random",
                                format!("{}_2^{log_area}", cluster.name()),
                            );
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

    /// `GeneratedData = u32` (the log_2 area). For benches that need a size-parameterized buffer
    /// but no trace data (e.g. `hadamard`). Only the `random` source is meaningful — `random`
    /// runs at the default size, `random:N[,N,...]` sweeps. JSON / real arguments panic.
    pub struct SizeOnlyKind;

    /// `GeneratedData = JaggedTraceMle<Felt, TaskScope>`. For benches that just need the trace.
    /// Source picked from CLI as random / JSON / real.
    pub struct JaggedKind;

    /// `GeneratedData = RealTraceData`. For benches that need the full execution context
    /// (machine, cluster, public_values) in addition to the trace. Source picked from CLI as
    /// random / JSON / real; for synthetic sources `cluster` and `public_values` are
    /// synthesized.
    pub struct FullKind;

    impl BenchKind for SizeOnlyKind {
        type GeneratedData = u32;

        fn generate_random_data<R: Rng>(
            _: &TaskScope,
            log_area: u32,
            _: ChipCluster,
            _: &mut R,
        ) -> u32 {
            log_area
        }

        fn generate_json_data<R: Rng>(_: &TaskScope, _: &str, _: &mut R) -> u32 {
            panic!(
                "SizeOnlyKind benches don't take a JSON source; pass `random` or `random:N[,N,...]`"
            )
        }

        fn generate_real_data<R: Rng>(
            _: &TaskScope,
            _: &'static str,
            _: &'static [u8],
            _: &mut R,
        ) -> u32 {
            panic!(
                "SizeOnlyKind benches don't take a real source; pass `random` or `random:N[,N,...]`"
            )
        }
    }

    impl BenchKind for JaggedKind {
        type GeneratedData = JaggedTraceMle<Felt, TaskScope>;

        fn generate_random_data<R: Rng>(
            scope: &TaskScope,
            log_area: u32,
            cluster: ChipCluster,
            rng: &mut R,
        ) -> JaggedTraceMle<Felt, TaskScope> {
            let machine = RiscvAir::<Felt>::machine();
            let chips: Vec<_> = cluster_chip_set(&machine, cluster).into_iter().collect();
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
            cluster: ChipCluster,
            rng: &mut R,
        ) -> RealTraceData {
            let machine = RiscvAir::<Felt>::machine();
            let cluster_set = cluster_chip_set(&machine, cluster);
            let chips: Vec<_> = cluster_set.iter().cloned().collect();
            let total_area = 1u64 << log_area;
            let device_mle =
                random_jagged_trace_mle::<Felt, _, _>(rng, &chips, total_area, LOG_STACKING_HEIGHT)
                    .into_device(scope);
            let public_values = vec![Felt::zero(); SP1_PROOF_NUM_PV_ELTS];
            RealTraceData { machine, cluster: cluster_set, public_values, device_mle }
        }

        fn generate_json_data<R: Rng>(scope: &TaskScope, path: &str, rng: &mut R) -> RealTraceData {
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
    /// The `_kind` value is purely for type inference; pass the appropriate marker.
    ///
    /// For the exact CLI invocations each bench accepts (and the disclaimers about synthetic
    /// data), see the README in the corresponding `benches/` folder:
    /// `sp1-gpu/crates/{commit,jagged_sumcheck,shard_prover,zerocheck}/benches/README.md`.
    pub fn with_trace_source<K, R, F>(c: &mut Criterion, rng: &mut R, _kind: K, f: F)
    where
        K: BenchKind,
        R: Rng,
        F: FnMut(&mut Criterion, BenchmarkId, &TaskScope, &mut R, K::GeneratedData),
    {
        K::run(c, rng, f);
    }

    //
    // Shared private helpers: source-agnostic building blocks.
    //

    /// Resolve a [`ChipCluster`] choice to the actual chip set on this machine. Returned as a
    /// `BTreeSet` because downstream code (real tracegen, `RealTraceData::cluster`) uses that
    /// type and its alphabetical iteration order — synthetic chip layout has to match for
    /// per-chip slicing to land on the right columns.
    ///
    /// `Core` returns the smallest cluster the machine knows about containing the Add chip.
    /// This relies on a structural assumption about how `RiscvAir::machine()` builds clusters:
    /// clusters with Add all stack chips on top of the base core cluster, so the smallest is the base.
    fn cluster_chip_set(
        machine: &Machine<Felt, RiscvAir<Felt>>,
        cluster: ChipCluster,
    ) -> BTreeSet<Chip<Felt, RiscvAir<Felt>>> {
        match cluster {
            ChipCluster::Core => {
                let add_chip = AddChip::<SupervisorMode> { _phantom: Default::default() };
                let add_chip = RiscvAir::<Felt>::Add(add_chip);
                let add_chip = Chip::new(add_chip);
                machine
                    .smallest_cluster(&BTreeSet::from_iter([add_chip]))
                    .expect("machine has no clusters")
                    .clone()
            }
            ChipCluster::AllChips => machine.chips().iter().cloned().collect(),
        }
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
            RealTraceData { machine, cluster, public_values, device_mle: jagged_trace_data }
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
