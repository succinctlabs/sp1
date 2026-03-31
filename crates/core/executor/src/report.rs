use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::{Add, AddAssign, Sub, SubAssign},
};

use enum_map::{EnumArray, EnumMap};
use hashbrown::HashMap;

use crate::{
    events::{generate_execution_report, MemInstrEvent, PrecompileEvent, SyscallEvent},
    ITypeRecord, Opcode, SyscallCode,
};

/// This constant is chosen for backwards compatibility with the V4 gas model: with this factor,
/// the gas costs of op-succinct blocks in V6 will approximately match those in V4.
const GAS_NORMALIZATION_FACTOR: u64 = 191;
/// Counts the number of times an APC was invoked along with its success and failure reasons.
/// Note that in theory many reasons can lead to an APC failing, so the sum of the fields is *NOT*
/// necessarily equal to the total number of invocations.
#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct ApcCount {
    /// The number of successful runs of this apc
    pub success: u64,
    /// The number of runs of this apc in which a state bump error occured
    pub state_bump_error: u64,
    /// The number of runs of this apc in which a memory bump error occured
    pub memory_bump_error: u64,
    /// The number of runs of this apc in which a segmentation occurred
    pub segmentation_error: u64,
}

impl AddAssign for ApcCount {
    fn add_assign(&mut self, rhs: Self) {
        self.success += rhs.success;
        self.state_bump_error += rhs.state_bump_error;
        self.memory_bump_error += rhs.memory_bump_error;
        self.segmentation_error += rhs.segmentation_error;
    }
}

impl Add for ApcCount {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl SubAssign for ApcCount {
    fn sub_assign(&mut self, rhs: Self) {
        self.success -= rhs.success;
        self.state_bump_error -= rhs.state_bump_error;
        self.memory_bump_error -= rhs.memory_bump_error;
        self.segmentation_error -= rhs.segmentation_error;
    }
}

impl Sub for ApcCount {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

/// An execution report.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// The opcode counts.
    pub opcode_counts: Box<EnumMap<Opcode, u64>>,
    /// The syscall counts.
    pub syscall_counts: Box<EnumMap<SyscallCode, u64>>,
    /// The apc counts by apc id.
    pub apc_counts: Box<HashMap<u64, ApcCount>>,
    /// The cycle tracker counts.
    pub cycle_tracker: HashMap<String, u64>,
    /// Tracker for the number of `cycle-tracker-report-*` invocations for a specific label.
    pub invocation_tracker: HashMap<String, u64>,
    /// The unique memory address counts.
    pub touched_memory_addresses: u64,
    /// The final exit code of the execution.
    pub exit_code: u64,
    /// The unnormalized gas, if it was calculated. Should not be accessed directly. Use `gas()` instead.
    pub(crate) gas: Option<u64>,
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

    /// The total size expected size (in bytes) of the execution report.
    #[must_use]
    pub fn total_record_size(&self) -> u64 {
        // todo!(n): make this precise.

        // Fix some average bound for each opcode.
        let avg_opcode_record_size = std::mem::size_of::<(MemInstrEvent, ITypeRecord)>();
        let total_opcode_records_size_bytes =
            self.opcode_counts.values().sum::<u64>() * avg_opcode_record_size as u64;

        // Take the maximum size of each precompile + 512 bytes for the vecs
        // todo: can we fix the array sizes in the precompile events?
        let syscall_avg_record_size = std::mem::size_of::<(SyscallEvent, PrecompileEvent)>() + 512;
        let total_syscall_records_size_bytes =
            self.syscall_counts.values().sum::<u64>() * syscall_avg_record_size as u64;

        total_opcode_records_size_bytes + total_syscall_records_size_bytes
    }

    /// Normalize the internal gas so that op-succinct blocks have approximately the same gas
    /// on v4 and v6.
    #[must_use]
    pub fn gas(&self) -> Option<u64> {
        // Using integer arithmetic to avoid f64 precision warnings.
        self.gas.map(|g| g * 10 / GAS_NORMALIZATION_FACTOR)
    }
}

/// Combines two `HashMap`s together. If a key is in both maps, the values are added together.
fn counts_add_assign<K, V>(lhs: &mut EnumMap<K, V>, rhs: EnumMap<K, V>)
where
    K: EnumArray<V>,
    V: AddAssign,
{
    for (k, v) in rhs {
        lhs[k] += v;
    }
}

/// Subtracts one `EnumMap` from another.
fn counts_sub_assign<K, V>(lhs: &mut EnumMap<K, V>, rhs: EnumMap<K, V>)
where
    K: EnumArray<V>,
    V: SubAssign,
{
    for (k, v) in rhs {
        lhs[k] -= v;
    }
}

/// Combines two `HashMap`s together. If a key is in both maps, the values are added together.
fn counts_add_assign_map<K, V>(lhs: &mut HashMap<K, V>, rhs: HashMap<K, V>)
where
    K: std::hash::Hash + PartialEq + Eq,
    V: AddAssign + Default,
{
    for (k, v) in rhs {
        *lhs.entry(k).or_default() += v;
    }
}

/// Subtracts one `HashMap` from another. If a key is in the rhs but not in the lhs, it is treated
/// as zero on the lhs.
fn counts_sub_assign_map<K, V>(lhs: &mut HashMap<K, V>, rhs: HashMap<K, V>)
where
    K: std::hash::Hash + PartialEq + Eq,
    V: SubAssign + Default,
{
    for (k, v) in rhs {
        *lhs.entry(k).or_default() -= v;
    }
}

impl AddAssign for ExecutionReport {
    fn add_assign(&mut self, rhs: Self) {
        counts_add_assign(&mut self.opcode_counts, *rhs.opcode_counts);
        counts_add_assign(&mut self.syscall_counts, *rhs.syscall_counts);
        counts_add_assign_map(&mut self.apc_counts, *rhs.apc_counts);
        self.touched_memory_addresses += rhs.touched_memory_addresses;

        // Merge cycle_tracker and invocation_tracker
        for (label, count) in rhs.cycle_tracker {
            *self.cycle_tracker.entry(label).or_insert(0) += count;
        }
        for (label, count) in rhs.invocation_tracker {
            *self.invocation_tracker.entry(label).or_insert(0) += count;
        }

        // Sum gas costs if both have gas
        self.gas = match (self.gas, rhs.gas) {
            (Some(c1), Some(c2)) => Some(c1 + c2),
            (Some(g), None) | (None, Some(g)) => Some(g),
            (None, None) => None,
        };

        // The exit code value must either be `0` or the final exit code, so taking an `OR` works.
        self.exit_code |= rhs.exit_code;
    }
}

impl Add for ExecutionReport {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl SubAssign for ExecutionReport {
    fn sub_assign(&mut self, rhs: Self) {
        counts_sub_assign(&mut self.opcode_counts, *rhs.opcode_counts);
        counts_sub_assign(&mut self.syscall_counts, *rhs.syscall_counts);
        counts_sub_assign_map(&mut self.apc_counts, *rhs.apc_counts);
        self.touched_memory_addresses -= rhs.touched_memory_addresses;
    }
}

impl Sub for ExecutionReport {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Display for ExecutionReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        if let Some(gas) = self.gas() {
            writeln!(f, "gas: {gas:?}")?;
        }
        writeln!(f, "opcode counts ({} total instructions):", self.total_instruction_count())?;
        for line in generate_execution_report(self.opcode_counts.as_ref()) {
            writeln!(f, "  {line}")?;
        }

        writeln!(f, "syscall counts ({} total syscall instructions):", self.total_syscall_count())?;
        for line in generate_execution_report(self.syscall_counts.as_ref()) {
            writeln!(f, "  {line}")?;
        }

        Ok(())
    }
}
