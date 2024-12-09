use std::fmt::Display;

/// Returns a tuple containing everything needed to to correctly display a table of counts
/// (e.g. `opcode_counts`):
///
/// 1. The number of characters of the highest count, that can be used to right-justify the count
///    column.
///
/// 2. The table sorted first by count (descending) and then by label (ascending). The table
///    itself is an iterator of a tuple (label, count).
pub fn sorted_table_lines<'a, K, V>(
    table: impl IntoIterator<Item = (K, &'a V)> + 'a,
) -> (usize, impl Iterator<Item = (String, &'a V)>)
where
    K: Ord + Display + 'a,
    V: Ord + Display + 'a,
{
    let mut entries = table.into_iter().collect::<Vec<_>>();
    // Sort table by count (descending), then the name order (ascending).
    entries.sort_unstable_by(|a, b| a.1.cmp(b.1).reverse().then_with(|| a.0.cmp(&b.0)));
    // Convert counts to `String`s to prepare them for printing and to measure their width.
    let mut entries =
        entries.into_iter().map(|(label, ct)| (label.to_string().to_lowercase(), ct)).peekable();
    // Calculate width for padding the counts.
    let width = entries.peek().map(|(_, b)| b.to_string().len()).unwrap_or_default();

    (width, entries)
}

/// Returns a formatted row of a table of counts (e.g. `opcode_counts`).
///
/// The first column consists of the counts, is right-justified, and is padded precisely
/// enough to fit all the numbers, using the provided `width`. The second column consists of
/// the labels (e.g. `OpCode`s). The columns are separated by a single space character.
#[must_use]
pub fn format_table_line<V>(width: &usize, label: &str, count: &V) -> String
where
    V: Display,
{
    format!("{count:>width$} {label}")
}

/// Returns sorted and formatted rows of a table of counts (e.g. `opcode_counts`).
///
/// The table is sorted first by count (descending) and then by label (ascending).
/// The first column consists of the counts, is right-justified, and is padded precisely
/// enough to fit all the numbers. The second column consists of the labels (e.g. `OpCode`s).
/// The columns are separated by a single space character.
///
/// It's possible to hide rows with 0 count by setting `hide_zeros` to true.
pub fn generate_execution_report<'a, K, V>(
    table: impl IntoIterator<Item = (K, &'a V)> + 'a,
) -> impl Iterator<Item = String> + 'a
where
    K: Ord + Display + 'a,
    V: Ord + PartialEq<u64> + Display + 'a,
{
    let (width, lines) = sorted_table_lines(table);

    lines
        .filter(move |(_, count)| **count != 0)
        .map(move |(label, count)| format!("  {}", format_table_line(&width, &label, count)))
}
