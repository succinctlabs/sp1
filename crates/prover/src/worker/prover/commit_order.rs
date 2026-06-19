use sp1_core_executor::SHARD_KIND_MERKLE;

/// Which kind of shard a global commitment came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitKind {
    /// A merkle-proving sub-shard.
    Merkle,
    /// A SplicingVM-cut core shard.
    Core,
}

/// Canonical sort key for a global commitment.
pub(crate) fn commit_sort_key(kind: CommitKind, shard_index: u32) -> (u8, u32) {
    let kind_rank = match kind {
        CommitKind::Merkle => 0,
        CommitKind::Core => 1,
    };
    (kind_rank, shard_index)
}

/// Sort a chunk's collected global commitments into canonical order.
pub(crate) fn order_commitments<T>(mut commits: Vec<(CommitKind, u32, T)>) -> Vec<T> {
    commits.sort_by_key(|(kind, index, _)| commit_sort_key(*kind, *index));
    commits.into_iter().map(|(_, _, value)| value).collect()
}

/// Canonical sort key for a shard proof: by trace chunk, then `commit_sort_key`'s kind/index.
pub(crate) fn proof_sort_key(
    trace_chunk_idx: u32,
    shard_kind: u32,
    shard_index: u32,
) -> (u32, u8, u32) {
    let kind = if shard_kind == SHARD_KIND_MERKLE { CommitKind::Merkle } else { CommitKind::Core };
    let (kind_rank, index) = commit_sort_key(kind, shard_index);
    (trace_chunk_idx, kind_rank, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_sorts_before_core_regardless_of_insertion_order() {
        let collected = vec![
            (CommitKind::Core, 1u32, "core-1"),
            (CommitKind::Core, 0, "core-0"),
            (CommitKind::Merkle, 1, "merkle-1"),
            (CommitKind::Core, 2, "core-2"),
            (CommitKind::Merkle, 0, "merkle-0"),
        ];

        let ordered = order_commitments(collected);
        assert_eq!(ordered, vec!["merkle-0", "merkle-1", "core-0", "core-1", "core-2"]);
    }

    #[test]
    fn key_orders_kind_then_index() {
        assert!(commit_sort_key(CommitKind::Merkle, 9) < commit_sort_key(CommitKind::Core, 0));
        assert!(commit_sort_key(CommitKind::Merkle, 0) < commit_sort_key(CommitKind::Merkle, 1));
        assert!(commit_sort_key(CommitKind::Core, 0) < commit_sort_key(CommitKind::Core, 1));
    }

    #[test]
    fn proof_key_orders_chunk_then_kind_then_index() {
        use sp1_core_executor::{SHARD_KIND_EXECUTION, SHARD_KIND_MERKLE};

        // Earlier chunk always sorts first, regardless of kind/index.
        assert!(
            proof_sort_key(0, SHARD_KIND_EXECUTION, 9) < proof_sort_key(1, SHARD_KIND_MERKLE, 0)
        );
        // Within a chunk, merkle sorts before execution.
        assert!(
            proof_sort_key(0, SHARD_KIND_MERKLE, 9) < proof_sort_key(0, SHARD_KIND_EXECUTION, 0)
        );
        // Within a chunk and kind, by shard index.
        assert!(
            proof_sort_key(2, SHARD_KIND_EXECUTION, 0) < proof_sort_key(2, SHARD_KIND_EXECUTION, 1)
        );
    }

    #[test]
    fn multi_chunk_sort_is_canonical() {
        use sp1_core_executor::{SHARD_KIND_EXECUTION, SHARD_KIND_MERKLE};

        let mut shards = vec![
            ("c1-core-0", proof_sort_key(1, SHARD_KIND_EXECUTION, 0)),
            ("c0-core-1", proof_sort_key(0, SHARD_KIND_EXECUTION, 1)),
            ("c1-merkle-0", proof_sort_key(1, SHARD_KIND_MERKLE, 0)),
            ("c0-merkle-0", proof_sort_key(0, SHARD_KIND_MERKLE, 0)),
            ("c0-core-0", proof_sort_key(0, SHARD_KIND_EXECUTION, 0)),
        ];
        shards.sort_by_key(|(_, key)| *key);
        let order = shards.into_iter().map(|(name, _)| name).collect::<Vec<_>>();
        assert_eq!(
            order,
            vec!["c0-merkle-0", "c0-core-0", "c0-core-1", "c1-merkle-0", "c1-core-0"]
        );
    }
}
