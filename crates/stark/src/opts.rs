use std::env;

use serde::{Deserialize, Serialize};
use sysinfo::System;

const MAX_SHARD_SIZE: usize = 1 << 21;
const RECURSION_MAX_SHARD_SIZE: usize = 1 << 22;
const MAX_SHARD_BATCH_SIZE: usize = 8;
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 1;
const MAX_DEFERRED_SPLIT_THRESHOLD: usize = 1 << 15;

/// Options to configure the SP1 prover for core and recursive proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SP1ProverOpts {
    /// Options for the core prover.
    pub core_opts: SP1CoreOpts,
    /// Options for the recursion prover.
    pub recursion_opts: SP1CoreOpts,
}

impl SP1ProverOpts {
    /// Get the default prover options.
    #[must_use]
    pub fn auto() -> Self {
        let cpu_ram_gb = System::new_all().total_memory() / (1024 * 1024 * 1024);
        SP1ProverOpts::cpu(cpu_ram_gb as usize)
    }

    /// Get the default prover options for a prover on CPU based on the amount of CPU memory.
    ///
    /// We use a soft heuristic based on our understanding of the memory usage in the GPU prover.
    #[must_use]
    pub fn cpu(cpu_ram_gb: usize) -> Self {
        let mut opts = SP1ProverOpts::default();

        // For each 2^21 shard, we need to reserve pessimistically ~14 GB of memory.
        //
        // This means that:
        // - 0..14 GB of RAM -> ~3.5 GB of RAM per shard
        // - 14..32 GB of RAM -> ~7 GB of RAM per shard
        // - 32..64 GB of RAM -> ~14 GB of RAM per shard
        let log2_shard_size = match cpu_ram_gb {
            0..14 => 19,
            14..32 => 20,
            32.. => 21,
        };
        opts.core_opts.shard_size = 1 << log2_shard_size;

        // To calculate the optimal shard batch size, we estimate the number of shards that would
        // result in an OOM error. We then divide this number by 2 to get the optimal shard batch
        // size but we upper bound it by `MAX_SHARD_BATCH_SIZE`.
        //
        // We also make sure that the shard batch size is at least 1.
        let log2_gap_from_21 = 21 - log2_shard_size;
        let lde_size_gb = 14 / (1 << log2_gap_from_21);
        let oom_shard_count = cpu_ram_gb / lde_size_gb;
        let safe_shard_count = std::cmp::min(oom_shard_count / 2, MAX_SHARD_BATCH_SIZE);
        opts.core_opts.shard_batch_size = std::cmp::max(safe_shard_count, 1);

        // We always have at least 1 record and trace channel to maximally use the prover threads.
        //
        // In the CPU setting, the prover is much slower than the record/trace generation, so we
        // can set these values to be very low.
        opts.core_opts.records_and_traces_channel_capacity = 1;
        opts.core_opts.trace_gen_workers = 1;

        // We then divide all the parameters in the split opts by `1 << log2_gap_from_21` to ensure
        // the memory / precompile shards also do not OOM.
        //
        // There could be some careful logic here to handle `combine_memory_threshold` but we
        // don't need to do that for now.
        let factor = 1 << log2_gap_from_21;
        opts.core_opts.split_opts.deferred /= factor;
        opts.core_opts.split_opts.keccak /= factor;
        opts.core_opts.split_opts.sha_extend /= factor;
        opts.core_opts.split_opts.sha_compress /= factor;
        opts.core_opts.split_opts.memory /= factor;

        opts
    }

    /// Get the default prover options for a prover on GPU given the amount of CPU and GPU memory.
    #[must_use]
    pub fn gpu(cpu_ram_gb: usize, gpu_ram_gb: usize) -> Self {
        let mut opts = SP1ProverOpts::default();

        // Set the core options.
        if 24 <= gpu_ram_gb {
            let log2_shard_size = 21;
            opts.core_opts.shard_size = 1 << log2_shard_size;
            opts.core_opts.shard_batch_size = 1;

            let log2_deferred_threshold = 14;
            opts.core_opts.split_opts = SplitOpts::new(1 << log2_deferred_threshold);

            opts.core_opts.records_and_traces_channel_capacity = 4;
            opts.core_opts.trace_gen_workers = 4;

            if cpu_ram_gb <= 20 {
                opts.core_opts.records_and_traces_channel_capacity = 1;
                opts.core_opts.trace_gen_workers = 2;
            }
        } else {
            unreachable!("not enough gpu memory");
        }

        // Set the recursion options.
        opts.recursion_opts.shard_batch_size = 1;

        opts
    }
}

/// Options for the core prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SP1CoreOpts {
    /// The size of a shard in terms of cycles.
    pub shard_size: usize,
    /// The size of a batch of shards in terms of cycles.
    pub shard_batch_size: usize,
    /// Options for splitting deferred events.
    pub split_opts: SplitOpts,
    /// The number of workers to use for generating traces.
    pub trace_gen_workers: usize,
    /// The capacity of the channel for checkpoints.
    pub checkpoints_channel_capacity: usize,
    /// The capacity of the channel for records and traces.
    pub records_and_traces_channel_capacity: usize,
}

impl Default for SP1ProverOpts {
    fn default() -> Self {
        Self { core_opts: SP1CoreOpts::default(), recursion_opts: SP1CoreOpts::recursion() }
    }
}

impl Default for SP1CoreOpts {
    fn default() -> Self {
        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap_or(MAX_DEFERRED_SPLIT_THRESHOLD))
            .unwrap_or(MAX_DEFERRED_SPLIT_THRESHOLD)
            .max(MAX_DEFERRED_SPLIT_THRESHOLD);

        let shard_size = env::var("SHARD_SIZE")
            .map_or_else(|_| MAX_SHARD_SIZE, |s| s.parse::<usize>().unwrap_or(MAX_SHARD_SIZE));

        Self {
            shard_size,
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| MAX_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(MAX_SHARD_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(split_threshold),
            trace_gen_workers: env::var("TRACE_GEN_WORKERS").map_or_else(
                |_| DEFAULT_TRACE_GEN_WORKERS,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_TRACE_GEN_WORKERS),
            ),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY),
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| s.parse::<usize>().unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY),
                ),
        }
    }
}

impl SP1CoreOpts {
    /// Get the default options for the recursion prover.
    #[must_use]
    pub fn recursion() -> Self {
        let mut opts = Self::default();
        opts.shard_size = RECURSION_MAX_SHARD_SIZE;
        opts
    }
}

/// Options for splitting deferred events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitOpts {
    /// The threshold for combining the memory init/finalize events in to the current shard in
    /// terms of cycles.
    pub combine_memory_threshold: usize,
    /// The threshold for default events.
    pub deferred: usize,
    /// The threshold for keccak events.
    pub keccak: usize,
    /// The threshold for sha extend events.
    pub sha_extend: usize,
    /// The threshold for sha compress events.
    pub sha_compress: usize,
    /// The threshold for memory events.
    pub memory: usize,
}

impl SplitOpts {
    /// Create a new [`SplitOpts`] with the given threshold.
    ///
    /// The constants here need to be chosen very carefully to prevent OOM. Consult @jtguibas on
    /// how to change them.
    #[must_use]
    pub fn new(deferred_split_threshold: usize) -> Self {
        Self {
            combine_memory_threshold: 1 << 26,
            deferred: deferred_split_threshold,
            keccak: 8 * deferred_split_threshold / 24,
            sha_extend: 32 * deferred_split_threshold / 48,
            sha_compress: 32 * deferred_split_threshold / 80,
            memory: 64 * deferred_split_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opts() {
        let opts = SP1ProverOpts::cpu(16);
        println!("16: {:?}", opts.core_opts);

        let opts = SP1ProverOpts::cpu(32);
        println!("32: {:?}", opts.core_opts);

        let opts = SP1ProverOpts::cpu(64);
        println!("64: {:?}", opts.core_opts);

        let opts = SP1ProverOpts::cpu(128);
        println!("128: {:?}", opts.core_opts);

        let opts = SP1ProverOpts::cpu(256);
        println!("256: {:?}", opts.core_opts);

        let opts = SP1ProverOpts::cpu(512);
        println!("512: {:?}", opts.core_opts);

        let opts = SP1ProverOpts::auto();
        println!("auto: {:?}", opts.core_opts);
    }
}
