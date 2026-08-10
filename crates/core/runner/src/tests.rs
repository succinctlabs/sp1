use crate::MinimalExecutorRunner;
use sp1_core_executor::{ExecutionError, Program, DEFAULT_MEMORY_LIMIT};
use sp1_core_machine::{io::SP1Stdin, utils::setup_logger};
use std::sync::Arc;
use test_artifacts::{KECCAK256_ELF, MEMORY_TESTER_ELF};

fn run(runner: &mut MinimalExecutorRunner) -> Option<ExecutionError> {
    loop {
        match runner.try_execute_chunk() {
            Ok(Some(_)) => (), // continue
            Ok(None) => return None,
            Err(e) => return Some(e),
        }
    }
}

#[test]
fn test_out_of_bound_access() {
    setup_logger();

    let program = Arc::new(Program::from(&MEMORY_TESTER_ELF).expect("parse program"));
    let mut stdin = SP1Stdin::new();
    stdin.write(&0u8);

    let mut runner =
        MinimalExecutorRunner::new(program, false, Some(1000), DEFAULT_MEMORY_LIMIT, 1);
    for input in &stdin.buffer {
        runner.with_input(input);
    }

    let result = run(&mut runner);
    assert!(matches!(result, Some(ExecutionError::InvalidMemoryAccess(_, _))));
}

#[test]
fn test_using_too_much_memory() {
    setup_logger();

    let program = Arc::new(Program::from(&MEMORY_TESTER_ELF).expect("parse program"));
    let mut stdin = SP1Stdin::new();
    stdin.write(&1u8);

    // 2 executors treat memory limit differently, here we are using different
    // limit numbers respectively.
    #[cfg(sp1_use_native_executor)]
    let memory_limit = 2 * 1024 * 1024 * 1024;
    #[cfg(not(sp1_use_native_executor))]
    let memory_limit = 8 * 256 * 1024;

    let mut runner = MinimalExecutorRunner::new(program, false, Some(16000000), memory_limit, 1);
    for input in &stdin.buffer {
        runner.with_input(input);
    }

    let result = run(&mut runner);
    // Portable builds trip the in-process limiter; native builds are killed by the RSS monitor.
    assert!(matches!(
        result,
        Some(ExecutionError::TooMuchMemory() | ExecutionError::KilledByMemoryMonitor(_))
    ));
}

#[test]
#[cfg(sp1_use_native_executor)]
fn test_dirty_pages_emitted_per_chunk() {
    use bincode::serialize;
    use sp1_jit::dirty_pages_wire_bytes;

    setup_logger();

    // Use the small fibonacci program with a few iterations — enough to
    // produce a couple of dirty pages but small enough to keep the test
    // quick.
    let program = Arc::new(Program::from(&test_artifacts::FIBONACCI_ELF).expect("parse program"));

    // Slot large enough for ~2000 dirty pages (more than fibonacci ever
    // produces). Plenty of headroom for safety.
    let slot_bytes = dirty_pages_wire_bytes(2000);

    let mut runner = MinimalExecutorRunner::new_with_dirty_pages(
        program,
        false,
        Some(100_000), // chunk threshold
        DEFAULT_MEMORY_LIMIT,
        4, // shm slots
        Some(slot_bytes),
    );
    runner.with_input(&serialize(&100u32).unwrap());

    let mut chunk_count = 0usize;
    let mut total_dirty_pages = 0usize;
    let mut all_page_ids = std::collections::HashSet::<u32>::new();

    loop {
        match runner.try_execute_chunk_with_dirty_pages() {
            Ok(Some((chunk, dirty))) => {
                chunk_count += 1;
                total_dirty_pages += dirty.pages.len();
                // Every dirty page must have a u32 page_id and 256 u64 final-contents
                // (the wire roundtrip path).
                for page in &dirty.pages {
                    assert_eq!(page.final_contents.len(), 256);
                    all_page_ids.insert(page.page_id);
                }
                let _ = chunk; // chunk is fine; we just dropped the consumer guard
            }
            Ok(None) => break,
            Err(e) => panic!("execute failed: {e:?}"),
        }
    }

    assert!(chunk_count >= 1, "expected at least one chunk");
    assert!(total_dirty_pages >= 1, "expected at least one dirty page across all chunks");
    assert!(!all_page_ids.is_empty(), "page id set should be non-empty");
}

/// Demonstrates that the gas estimate depends on `minimal_trace_chunk_threshold`.
///
/// The gas estimator treats each trace chunk as a "shard": the first access to each memory
/// word within a chunk is counted as a "first read this shard" (1 `MemoryLocal` rows).
/// Smaller chunks => more chunk boundaries => the carried working set is re-counted more often
/// => higher cost. Real proving cost is unaffected because real shards are cut by the (
/// unchanged) sharding thresholds, not the chunk threshold. PR #2793 cut the chunk threshold 8x
/// (134_217_728 -> 16_777_216), inflating gas above the value #2786 calibrated against v6.1.0.
///
/// The assertions compare the raw per-chunk cost `3 * trace_area + complexity`, not the rounded
/// gas: gas floors that quantity twice per chunk (`/ 10`, then `* 10 / 191`), so summing per-chunk
/// gas loses up to ~1 gas unit per chunk and the summed gas of a many-chunk run can dip below a
/// fewer-chunk run even though the underlying cost is monotonic. The raw cost has no such
/// rounding. Chunked runs are also only compared against the single-chunk baseline (not pairwise):
/// two chunked runs cut boundaries at unrelated positions, so their re-counted working sets are
/// not supersets of each other, while every chunked run only *adds* re-counted rows relative to
/// the boundary-free baseline.
#[test]
#[allow(clippy::print_stdout)] // prints a cost-vs-chunk-count table under `--nocapture`
fn test_gas_depends_on_chunk_threshold() {
    use bincode::serialize;
    use sp1_core_executor::{GasEstimatingVMEnum, RiscvAirId, SP1CoreOpts};

    let program = Arc::new(Program::from(&KECCAK256_ELF).expect("parse program"));

    // A workload with enough cycles to span several small chunks while fitting in one large chunk,
    // with a real keccak working set carried across chunk boundaries.
    let count = 64usize;
    let inputs = {
        let mut v = vec![serialize(&count).unwrap()];
        for i in 0..count {
            v.push(serialize(&vec![i as u8; 256]).unwrap());
        }
        v
    };

    let opts = SP1CoreOpts::default();

    // Total raw cost (the gas formula's numerator, before rounding), chunk count, and total
    // `MemoryLocal` rows (the chunk-boundary-sensitive part of the cost).
    let cost_for_threshold = |threshold: u64| -> (u64, usize, u64) {
        let mut runner = MinimalExecutorRunner::new(
            program.clone(),
            false,
            Some(threshold),
            DEFAULT_MEMORY_LIMIT,
            1,
        );
        for input in &inputs {
            runner.with_input(input);
        }
        let mut total_cost = 0u64;
        let mut num_chunks = 0usize;
        let mut mem_local_rows = 0u64;
        while let Some(chunk) = runner.try_execute_chunk().expect("execute chunk") {
            num_chunks += 1;
            let mut vm = GasEstimatingVMEnum::new(&chunk, program.clone(), [0u32; 4], opts.clone());
            vm.execute().expect("gas execute");
            let (complexity, trace_area) = vm.costs();
            total_cost += 3 * trace_area + complexity;
            mem_local_rows += match &vm {
                GasEstimatingVMEnum::Supervisor(vm) => {
                    vm.gas_calculator.system_chips_counts[RiscvAirId::MemoryLocal]
                }
                GasEstimatingVMEnum::User(vm) => {
                    vm.gas_calculator.system_chips_counts[RiscvAirId::MemoryLocal]
                }
            };
        }
        (total_cost, num_chunks, mem_local_rows)
    };

    // A large threshold (single chunk = calibrated baseline) versus progressively smaller ones
    // that force more chunk boundaries. The exact 134M->16M head-to-head needs a multi-GiB
    // workload to straddle those cadences; here we keep it fast and assert the same coupling
    // that drives the #2793 regression.
    let thresholds = [1u64 << 22, 1 << 18, 1 << 16, 1 << 14];
    let mut results = Vec::new();
    for t in thresholds {
        let (cost, chunks, mem_local) = cost_for_threshold(t);
        println!("threshold={t:>12}  chunks={chunks:>5}  mem_local={mem_local:>9}  cost={cost}");
        results.push((t, cost, chunks));
    }

    // The large (pre-#2793) threshold is a single chunk here: the calibrated baseline.
    let (_, baseline, baseline_chunks) = results[0];
    assert_eq!(baseline_chunks, 1, "baseline threshold did not produce a single chunk");
    // Chunked runs re-count the carried working set at every boundary, so each costs at least as
    // much as the boundary-free baseline.
    for &(t, cost, _) in &results[1..] {
        assert!(
            cost >= baseline,
            "cost should not drop below the single-chunk baseline: threshold {t} gave {cost} < baseline {baseline}",
        );
    }
    // And the smallest threshold must inflate the cost strictly above the calibrated baseline.
    let (_, smallest_cost, smallest_chunks) = *results.last().unwrap();
    assert!(smallest_chunks > 1, "test workload did not span multiple chunks");
    assert!(
        smallest_cost > baseline,
        "expected cost inflation: smallest-threshold cost {smallest_cost} !> baseline {baseline}",
    );
}
