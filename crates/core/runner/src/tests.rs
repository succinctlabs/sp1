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
    assert_eq!(result, Some(ExecutionError::TooMuchMemory()));
}

#[test]
fn test_clks_should_be_available_while_running() {
    use bincode::serialize;

    let program = Program::from(&KECCAK256_ELF).unwrap();
    let program = Arc::new(program);

    let mut executor =
        MinimalExecutorRunner::new(program.clone(), true, Some(10), DEFAULT_MEMORY_LIMIT, 1);
    executor.with_input(&serialize(&5_usize).unwrap());
    for i in 0..5 {
        executor.with_input(&serialize(&vec![i; i]).unwrap());
    }

    let mut last_global_clk = 0;
    let mut last_clk = 0;
    let mut chunk_count = 0;
    while let Some(_chunk) = executor.execute_chunk() {
        assert!(executor.global_clk() > last_global_clk);
        assert!(executor.clk() > last_clk);

        last_global_clk = executor.global_clk();
        last_clk = executor.clk();
        chunk_count += 1;
    }

    assert!(chunk_count > 5, "no chunks were executed");
}

/// Demonstrates that the gas estimate depends on `minimal_trace_chunk_threshold`.
///
/// The gas estimator treats each trace chunk as a "shard": `shard_start_clk` is reset to the
/// chunk start, so every address whose previous access predates the chunk is re-counted as a
/// "first read this shard" (1 `MemoryLocal` + 2 `Global` rows). Smaller chunks => more chunk
/// boundaries => the carried working set is re-counted more often => higher gas. Real proving
/// cost is unaffected because real shards are cut by the (unchanged) sharding thresholds, not the
/// chunk threshold. PR #2793 cut the chunk threshold 8x (134_217_728 -> 16_777_216), inflating
/// gas above the value #2786 calibrated against v6.1.0.
#[test]
#[allow(clippy::print_stdout)] // prints a gas-vs-chunk-count table under `--nocapture`
fn test_gas_depends_on_chunk_threshold() {
    use bincode::serialize;
    use sp1_core_executor::{GasEstimatingVMEnum, SP1CoreOpts};

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

    let gas_for_threshold = |threshold: u64| -> (u64, usize) {
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
        let mut total_gas = 0u64;
        let mut num_chunks = 0usize;
        while let Some(chunk) = runner.try_execute_chunk().expect("execute chunk") {
            num_chunks += 1;
            let mut vm = GasEstimatingVMEnum::new(&chunk, program.clone(), [0u32; 4], opts.clone());
            let report = vm.execute().expect("gas execute");
            total_gas += report.gas().expect("gas present");
        }
        (total_gas, num_chunks)
    };

    // A large threshold (single chunk = calibrated baseline) versus progressively smaller ones
    // that force more chunk boundaries. The exact 134M->16M head-to-head needs a multi-GiB
    // workload to straddle those cadences; here we keep it fast and assert the same monotonic
    // coupling that drives the #2793 regression.
    let thresholds = [1u64 << 22, 1 << 18, 1 << 16, 1 << 14];
    let mut results = Vec::new();
    for t in thresholds {
        let (gas, chunks) = gas_for_threshold(t);
        println!("threshold={t:>12}  chunks={chunks:>5}  gas={gas}");
        results.push((t, gas, chunks));
    }

    // The large (pre-#2793) threshold is a single chunk here: the calibrated baseline.
    let baseline = results[0].1;
    // Smaller thresholds produce more chunks and strictly more gas (monotonic inflation).
    for w in results.windows(2) {
        let (t_big, gas_big, _) = w[0];
        let (t_small, gas_small, _) = w[1];
        assert!(
            gas_small >= gas_big,
            "gas should be monotonic in chunk count: threshold {t_small} gave {gas_small} < threshold {t_big} gave {gas_big}",
        );
    }
    // And the smallest threshold must inflate gas above the calibrated baseline.
    let (_, smallest_gas, smallest_chunks) = *results.last().unwrap();
    assert!(smallest_chunks > 1, "test workload did not span multiple chunks");
    assert!(
        smallest_gas > baseline,
        "expected gas inflation: smallest-threshold gas {smallest_gas} !> baseline {baseline}",
    );
}
