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
    pub fn total_instruction_count(&self) -> u64 {
        self.opcode_counts.values().sum()
    }

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
        writeln!(f, "Instruction Counts:")?;
        let mut sorted_instructions = self
            .opcode_counts
            .iter()
            .map(|(opcode, ct)| (opcode.to_string(), *ct))
            .collect::<Vec<_>>();

        // Sort instructions by opcode name.
        sorted_instructions.sort_unstable();
        for (opcode, count) in sorted_instructions {
            writeln!(f, "  {}: {}", opcode, count)?;
        }
        writeln!(f, "Total Instructions: {}", self.total_instruction_count())?;

        writeln!(f, "Syscall Counts:")?;
        let mut sorted_syscalls = self
            .syscall_counts
            .iter()
            .map(|(syscall, ct)| (syscall.to_string(), *ct))
            .collect::<Vec<_>>();

        // Sort syscalls by syscall name.
        sorted_syscalls.sort_unstable();
        for (syscall, count) in sorted_syscalls {
            writeln!(f, "  {}: {}", syscall, count)?;
        }
        writeln!(f, "Total Syscall Count: {}", self.total_syscall_count())?;

        Ok(())
    }
}
