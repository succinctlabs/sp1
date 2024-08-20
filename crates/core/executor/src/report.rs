use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::{Display, Formatter, Result as FmtResult},
    hash::Hash,
    ops::{Add, AddAssign},
};

use crate::{events::sorted_table_lines, syscalls::SyscallCode, Opcode};

/// An execution report.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The opcode counts.
    pub opcode_counts: HashMap<Opcode, u64>,
    /// The syscall counts.
    pub syscall_counts: HashMap<SyscallCode, u64>,
    /// The cycle tracker counts.
    pub cycle_tracker: HashMap<String, u64>,
    /// The unique memory address counts.
    pub touched_memory_addresses: u64,
}

impl ExecutionReport {
    /// Compute the total number of instructions run during the execution.
    #[must_use]
    pub fn total_instruction_count(&self) -> u64 {
        self.opcode_counts.values().sum()
    }

    /// Compute the total number of syscalls made during the execution.
    #[must_use]
    pub fn total_syscall_count(&self) -> u64 {
        self.syscall_counts.values().sum()
    }
}

/// Combines two `HashMap`s together. If a key is in both maps, the values are added together.
fn hashmap_add_assign<K, V>(lhs: &mut HashMap<K, V>, rhs: HashMap<K, V>)
where
    K: Eq + Hash,
    V: AddAssign,
{
    for (k, v) in rhs {
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
        self.touched_memory_addresses += rhs.touched_memory_addresses;
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
        writeln!(f, "opcode counts ({} total instructions):", self.total_instruction_count())?;
        for line in sorted_table_lines(&self.opcode_counts) {
            writeln!(f, "  {line}")?;
        }

        writeln!(f, "syscall counts ({} total syscall instructions):", self.total_syscall_count())?;
        for line in sorted_table_lines(&self.syscall_counts) {
            writeln!(f, "  {line}")?;
        }

        Ok(())
    }
}
