//! Bench `LeafState::ingest_chunk` — hashing a chunk's dirty pages into the running leaf state.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use sp1_core_machine::merkle_prover::LeafState;
use sp1_jit::{DirtyPage, MERKLE_PAGE_WORDS};

fn make_page(seed: u64) -> [u64; MERKLE_PAGE_WORDS] {
    let mut page = [0u64; MERKLE_PAGE_WORDS];
    for (i, slot) in page.iter_mut().enumerate() {
        *slot = seed.wrapping_mul(2_654_435_761).wrapping_add(i as u64 * 7919);
    }
    page
}

fn ingest_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("leaf_state_ingest_chunk");
    for &n in &[1_000usize, 5_000, 7_000, 11_000, 22_000] {
        let pages: Vec<DirtyPage> = (0..n)
            .map(|i| DirtyPage { page_id: i as u32, final_contents: make_page(i as u64) })
            .collect();
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &pages, |b, pages| {
            // Fresh state per iteration (setup, untimed); the ingest itself is measured.
            b.iter_batched(
                LeafState::new,
                |mut state| black_box(state.ingest_chunk(black_box(pages))),
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, ingest_chunk);
criterion_main!(benches);
