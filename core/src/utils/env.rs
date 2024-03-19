/// Gets the number of rows which by default should be used for each chip to maximize padding.
///
/// Some chips, such as FieldLTU, may use a constant multiple of this value to optimize performance.
pub fn shard_size() -> usize {
    let value = match std::env::var("SHARD_SIZE") {
        Ok(val) => val.parse().unwrap(),
        Err(_) => 1 << 19,
    };
    assert!(value != 0 && (value & (value - 1)) == 0);
    value
}

/// Gets the number of shards after which we should save the shard commits to disk.
pub fn save_disk_threshold() -> usize {
    match std::env::var("SAVE_DISK_THRESHOLD") {
        Ok(val) => val.parse().unwrap(),
        Err(_) => 256,
    }
}

/// Gets the flag for whether to recreate the shard commitments instead of saving them to disk.
pub fn reconstruct_commitments() -> bool {
    match std::env::var("RECONSTRUCT_COMMITMENTS") {
        Ok(val) => val == "true",
        Err(_) => true,
    }
}

/// Gets the max number of shards that can go in one batch. If set to 0, there will only be 1 batch.
///
/// The prover will generate the events for a whole batch at once, so this param should be the
/// largest number of shards that can be executed and proven at once, subject to memory constraints.
pub fn shard_batch_size() -> u32 {
    match std::env::var("SHARD_BATCH_SIZE") {
        Ok(val) => val.parse().unwrap(),
        Err(_) => 0,
    }
}
