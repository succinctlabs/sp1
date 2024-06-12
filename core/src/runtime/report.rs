use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::hash::Hash;
use std::ops::{Add, AddAssign};

use super::*;

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    pub opcode_counts: HashMap<Opcode, u64>,
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

impl ExecutionReport {
    /// Compute the total number of instructions run during the execution.
    pub fn total_instruction_count(&self) -> u64 {
        self.opcode_counts.values().sum()
    }

    /// Compute the total number of syscalls made during the execution.
    pub fn total_syscall_count(&self) -> u64 {
        self.syscall_counts.values().sum()
    }

    /// Returns sorted and formatted rows of a table of counts (e.g. `opcode_counts`).
    ///
    /// The table is sorted first by count (descending) and then by label (ascending).
    /// The first column consists of the counts, is right-justified, and is padded precisely
    /// enough to fit all the numbers. The second column consists of the labels (e.g. `OpCode`s).
    /// The columns are separated by a single space character.
    pub fn sorted_table_lines<K, V>(table: &HashMap<K, V>) -> Vec<String>
    where
        K: Ord + Display,
        V: Ord + Display,
    {
        // This function could be optimized here and there,
        // for example by pre-allocating all `Vec`s, or by using less memory.
        let mut lines = Vec::with_capacity(table.len());
        let mut entries = table.iter().collect::<Vec<_>>();
        // Sort table by count (descending), then the name order (ascending).
        entries.sort_unstable_by(|a, b| a.1.cmp(b.1).reverse().then_with(|| a.0.cmp(b.0)));
        // Convert counts to `String`s to prepare them for printing and to measure their width.
        let table_with_string_counts = entries
            .into_iter()
            .map(|(label, ct)| (label.to_string().to_lowercase(), ct.to_string()))
            .collect::<Vec<_>>();
        // Calculate width for padding the counts.
        let width = table_with_string_counts
            .first()
            .map(|(_, b)| b.len())
            .unwrap_or_default();
        for (label, count) in table_with_string_counts {
            lines.push(format!("{count:>width$} {label}"));
        }
        lines
    }
}

/// Combines two `HashMap`s together. If a key is in both maps, the values are added together.
fn hashmap_add_assign<K, V>(lhs: &mut HashMap<K, V>, rhs: HashMap<K, V>)
where
    K: Eq + Hash,
    V: AddAssign,
{
    for (k, v) in rhs.into_iter() {
        // Can't use `.and_modify(...).or_insert(...)` because we want to use `v` in both places.
        match lhs.entry(k) {
            Entry::Occupied(e) => *e.into_mut() += v,
            Entry::Vacant(e) => drop(e.insert(v)),
        }
    }
}

impl AddAssign for ExecutionReport {
    fn add_assign(&mut self, rhs: Self) {
        hashmap_add_assign(&mut self.opcode_counts, rhs.opcode_counts);
        hashmap_add_assign(&mut self.syscall_counts, rhs.syscall_counts);
    }
}

impl Add for ExecutionReport {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl Display for ExecutionReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        writeln!(
            f,
            "opcode counts ({} total instructions):",
            self.total_instruction_count()
        )?;
        for line in Self::sorted_table_lines(&self.opcode_counts) {
            writeln!(f, "  {line}")?;
        }

        writeln!(
            f,
            "syscall counts ({} total syscall instructions):",
            self.total_syscall_count()
        )?;
        for line in Self::sorted_table_lines(&self.syscall_counts) {
            writeln!(f, "  {line}")?;
        }

        Ok(())
    }
}
