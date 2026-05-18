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
}
