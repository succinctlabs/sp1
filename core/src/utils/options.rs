use std::env;

use crate::runtime::{SplitOpts, DEFERRED_SPLIT_THRESHOLD};

const DEFAULT_SHARD_SIZE: usize = 1 << 22;
const DEFAULT_SHARD_BATCH_SIZE: usize = 16;
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SP1ProverOpts {
    pub core_opts: SP1CoreOpts,
    pub recursion_opts: SP1CoreOpts,
}

impl Default for SP1ProverOpts {
    fn default() -> Self {
        Self {
            core_opts: SP1CoreOpts::default(),
            recursion_opts: SP1CoreOpts::recursion(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SP1CoreOpts {
    pub shard_size: usize,
    pub shard_batch_size: usize,
    pub split_opts: SplitOpts,
    pub reconstruct_commitments: bool,
    pub trace_gen_workers: usize,
    pub checkpoints_channel_capacity: usize,
    pub records_and_traces_channel_capacity: usize,
}

impl Default for SP1CoreOpts {
    fn default() -> Self {
        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap_or(DEFERRED_SPLIT_THRESHOLD))
            .unwrap_or(DEFERRED_SPLIT_THRESHOLD);
        Self {
            shard_size: env::var("SHARD_SIZE").map_or_else(
                |_| DEFAULT_SHARD_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_SIZE),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| DEFAULT_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(split_threshold),
            reconstruct_commitments: true,
            trace_gen_workers: env::var("TRACE_GEN_WORKERS").map_or_else(
                |_| DEFAULT_TRACE_GEN_WORKERS,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_TRACE_GEN_WORKERS),
            ),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| {
                    s.parse::<usize>()
                        .unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY)
                },
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| {
                        s.parse::<usize>()
                            .unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY)
                    },
                ),
        }
    }
}

impl SP1CoreOpts {
    pub fn recursion() -> Self {
        let mut opts = Self::default();
        opts.reconstruct_commitments = false;
        opts.shard_size = DEFAULT_SHARD_SIZE;
        opts
    }
}
