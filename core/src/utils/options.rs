use std::env;

const DEFAULT_SHARD_SIZE: usize = 1 << 22;
const DEFAULT_SHARD_BATCH_SIZE: usize = 16;
const DEFAULT_SHARD_CHUNKING_MULTIPLIER: usize = 1;
const DEFAULT_RECONSTRUCT_COMMITMENTS: bool = true;

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
    pub shard_chunking_multiplier: usize,
    pub reconstruct_commitments: bool,
}

impl Default for SP1CoreOpts {
    fn default() -> Self {
        Self {
            shard_size: env::var("SHARD_SIZE").map_or_else(
                |_| DEFAULT_SHARD_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_SIZE),
            ),
            shard_batch_size: env::var("SHARD_BATCH_SIZE").map_or_else(
                |_| DEFAULT_SHARD_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_SHARD_BATCH_SIZE),
            ),
            shard_chunking_multiplier: env::var("SHARD_CHUNKING_MULTIPLIER").map_or_else(
                |_| DEFAULT_SHARD_CHUNKING_MULTIPLIER,
                |s| {
                    s.parse::<usize>()
                        .unwrap_or(DEFAULT_SHARD_CHUNKING_MULTIPLIER)
                },
            ),
            reconstruct_commitments: env::var("RECONSTRUCT_COMMITMENTS").map_or_else(
                |_| DEFAULT_RECONSTRUCT_COMMITMENTS,
                |s| s.parse::<bool>().unwrap_or(DEFAULT_RECONSTRUCT_COMMITMENTS),
            ),
        }
    }
}

impl SP1CoreOpts {
    pub fn recursion() -> Self {
        Self {
            shard_size: DEFAULT_SHARD_SIZE,
            shard_batch_size: DEFAULT_SHARD_BATCH_SIZE,
            shard_chunking_multiplier: DEFAULT_SHARD_CHUNKING_MULTIPLIER,
            reconstruct_commitments: false,
        }
    }
}
