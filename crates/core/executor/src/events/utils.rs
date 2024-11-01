use serde::Deserialize;
use serde::Serialize;
use std::{
    fmt::Display,
    iter::{Map, Peekable},
};

/// A unique identifier for lookups.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default, Eq, Hash, PartialEq)]

pub struct LookupId(pub u64);

/// Create a random lookup id. This is slower than `record.create_lookup_id()` but is useful for
/// testing.
#[must_use]
pub(crate) fn create_random_lookup_ids() -> [LookupId; 6] {
    std::array::from_fn(|_| LookupId(rand::random()))
}

/// Returns sorted and formatted rows of a table of counts (e.g. `opcode_counts`).
///
/// The table is sorted first by count (descending) and then by label (ascending).
/// The first column consists of the counts, is right-justified, and is padded precisely
/// enough to fit all the numbers. The second column consists of the labels (e.g. `OpCode`s).
/// The columns are separated by a single space character.
#[allow(clippy::type_complexity)]
pub fn sorted_table_lines<'a, K, V>(
    table: impl IntoIterator<Item = (K, V)> + 'a,
) -> Map<
    Peekable<Map<std::vec::IntoIter<(K, V)>, impl FnMut((K, V)) -> (String, String)>>,
    impl FnMut((String, String)) -> String,
>
where
    K: Ord + Display + 'a,
    V: Ord + Display + 'a,
{
    let mut entries = table.into_iter().collect::<Vec<_>>();
    // Sort table by count (descending), then the name order (ascending).
    entries.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse().then_with(|| a.0.cmp(&b.0)));
    // Convert counts to `String`s to prepare them for printing and to measure their width.
    let mut table_with_string_counts = entries
        .into_iter()
        .map(|(label, ct)| (label.to_string().to_lowercase(), ct.to_string()))
        .peekable();
    // Calculate width for padding the counts.
    let width = table_with_string_counts.peek().map(|(_, b)| b.len()).unwrap_or_default();
    table_with_string_counts.map(move |(label, count)| format!("{count:>width$} {label}"))
}
