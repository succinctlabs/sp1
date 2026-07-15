use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, Rng as _, SeedableRng};
use slop_algebra::AbstractField;
use slop_merkle_tree::batch_update::{Digest, Update};
use sp1_gpu_cudart::run_sync_in_place;
use sp1_gpu_merkle_tree::{gpu_batch_update, gpu_build_prev};
use sp1_primitives::SP1Field;

const HEIGHT: usize = 29;
const N_LEAVES: usize = 1_000_000;
const N_UPDATES: usize = 10_000;
const P: u32 = 0x7f00_0001; // KoalaBear prime.

/// Seeded deterministic RNG so bench cases stay reproducible across runs.
struct Rng(StdRng);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(StdRng::seed_from_u64(seed))
    }
    fn next_u64(&mut self) -> u64 {
        self.0.gen()
    }
    fn below(&mut self, n: u64) -> u64 {
        self.0.gen_range(0..n)
    }
}

fn rand_digest(rng: &mut Rng) -> Digest {
    core::array::from_fn(|_| SP1Field::from_canonical_u32((rng.next_u64() as u32) % P))
}

fn gen_leaves(rng: &mut Rng, clustered: bool) -> (Vec<(u64, Digest)>, Vec<u32>, Vec<SP1Field>) {
    let span = 1u64 << HEIGHT;
    let mut idxs: Vec<u64> = if clustered {
        let n = (N_LEAVES as u64).min(span);
        let base = if span > n { rng.below(span - n) } else { 0 };
        (base..base + n).collect()
    } else {
        let mut s = std::collections::BTreeSet::new();
        while (s.len() as u64) < (N_LEAVES as u64).min(span) {
            s.insert(rng.below(span));
        }
        s.into_iter().collect()
    };
    idxs.sort_unstable();
    let leaves: Vec<(u64, Digest)> = idxs.iter().map(|&i| (i, rand_digest(rng))).collect();
    let lidx: Vec<u32> = leaves.iter().map(|l| l.0 as u32).collect();
    let lval: Vec<SP1Field> = leaves.iter().flat_map(|l| l.1).collect();
    (leaves, lidx, lval)
}

fn gen_updates(rng: &mut Rng, leaves: &[(u64, Digest)], dl: Digest) -> Vec<Update> {
    use std::collections::{BTreeMap, BTreeSet};
    let leaf_map: BTreeMap<u64, Digest> = leaves.iter().copied().collect();
    let (foot_lo, foot_hi) = (leaves[0].0, leaves[leaves.len() - 1].0 + 1);
    let mut upd = BTreeSet::new();
    let target = (N_UPDATES as u64).min(foot_hi - foot_lo) as usize;
    while upd.len() < target {
        // ~80% modify an existing leaf, ~20% touch a new page within the footprint.
        let idx = if !rng.next_u64().is_multiple_of(5) {
            leaves[(rng.below(leaves.len() as u64)) as usize].0
        } else {
            foot_lo + rng.below(foot_hi - foot_lo)
        };
        upd.insert(idx);
    }
    upd.into_iter()
        .map(|idx| {
            let prev_leaf = *leaf_map.get(&idx).unwrap_or(&dl);
            let new_leaf = if rng.next_u64().is_multiple_of(4) { dl } else { rand_digest(rng) };
            Update { idx, prev_leaf, new_leaf }
        })
        .collect()
}

fn full_update(c: &mut Criterion) {
    run_sync_in_place(|scope| {
        let mut group = c.benchmark_group("gpu_batch_update_h29_1m");
        group.sample_size(10);
        for clustered in [true, false] {
            let label = if clustered { "clustered" } else { "scattered" };
            let mut rng = Rng::new(0xCAFE);
            let dl = rand_digest(&mut rng);
            let (leaves, lidx, lval) = gen_leaves(&mut rng, clustered);
            let updates = gen_updates(&mut rng, &leaves, dl);
            group.bench_function(BenchmarkId::from_parameter(label), |b| {
                b.iter(|| gpu_batch_update(&scope, dl, &lidx, &lval, &updates, HEIGHT));
            });
        }
        group.finish();
    })
    .unwrap();
}

fn prev_build(c: &mut Criterion) {
    run_sync_in_place(|scope| {
        let mut group = c.benchmark_group("gpu_prev_build_h29_1m");
        group.sample_size(10);
        for clustered in [true, false] {
            let label = if clustered { "clustered" } else { "scattered" };
            let mut rng = Rng::new(0xBEEF);
            let dl = rand_digest(&mut rng);
            let (_, lidx, lval) = gen_leaves(&mut rng, clustered);
            group.bench_function(BenchmarkId::from_parameter(label), |b| {
                b.iter(|| gpu_build_prev(&scope, dl, &lidx, &lval, HEIGHT));
            });
        }
        group.finish();
    })
    .unwrap();
}

criterion_group!(benches, full_update, prev_build);
criterion_main!(benches);
