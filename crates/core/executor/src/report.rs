use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    ops::{Add, AddAssign},
};

use enum_map::{EnumArray, EnumMap};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    events::{generate_execution_report, MemInstrEvent, PrecompileEvent, SyscallEvent},
    ITypeRecord, Opcode, SyscallCode,
};

/// This constant is chosen for backwards compatibility with the V4 gas model: with this factor,
/// the gas costs of op-succinct blocks in V6 will approximately match those in V4.
const GAS_NORMALIZATION_FACTOR: u64 = 191;

/// An execution report.
///
/// The serde format is stable only within a single SP1 version, since `Opcode`/`SyscallCode`
/// gain variants across releases. The serialized `gas` field is the raw value; call
/// [`ExecutionReport::gas`] for the normalized number.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    /// The opcode counts.
    pub opcode_counts: Box<EnumMap<Opcode, u64>>,
    /// The syscall counts.
    pub syscall_counts: Box<EnumMap<SyscallCode, u64>>,
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
    /// A bounded, lossy-UTF-8 tail of the guest program's `fd=2` (stderr) output captured
    /// during execution. A guest panic writes its message and source location to stderr
    /// before halting, so this carries debuggable context beyond a bare non-zero exit code.
    /// `None` when the guest wrote nothing to stderr or on paths that do not capture it.
    /// This is guest-controlled, untrusted text — bounded here, and must be sanitized and
    /// re-bounded before any storage or display.
    #[serde(default)]
    pub stderr_tail: Option<String>,
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

impl AddAssign for ExecutionReport {
    fn add_assign(&mut self, rhs: Self) {
        counts_add_assign(&mut self.opcode_counts, *rhs.opcode_counts);
        counts_add_assign(&mut self.syscall_counts, *rhs.syscall_counts);
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

        // Keep the latest non-empty stderr tail; a guest panic is written in the final
        // chunk before the halt.
        if rhs.stderr_tail.is_some() {
            self.stderr_tail = rhs.stderr_tail;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn populated_report() -> ExecutionReport {
        let mut report = ExecutionReport::default();
        report.opcode_counts[Opcode::ADD] = 7;
        report.opcode_counts[Opcode::SUB] = 3;
        report.syscall_counts[SyscallCode::HALT] = 1;
        report.cycle_tracker.insert("setup".to_string(), 100);
        report.invocation_tracker.insert("setup".to_string(), 2);
        report.touched_memory_addresses = 42;
        report.exit_code = 0;
        report.gas = Some(1_000);
        report
    }

    /// A populated `ExecutionReport` must round-trip through serde's human-readable (JSON) format.
    /// Derived `PartialEq` compares every field, including the `pub(crate)` `gas`.
    #[test]
    fn execution_report_json_round_trip() {
        let report = populated_report();
        let json = serde_json::to_string(&report).expect("serialize");
        let decoded: ExecutionReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(report, decoded);
    }

    /// `enum_map`'s `Serialize`/`Deserialize` takes a separate code path for non-human-readable
    /// formats (a fixed-length tuple rather than a map), and SP1 uses bincode for persistence, so
    /// prove the binary path round-trips too.
    #[test]
    fn execution_report_bincode_round_trip() {
        let report = populated_report();
        let bytes = bincode::serialize(&report).expect("serialize");
        let decoded: ExecutionReport = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(report, decoded);
    }

    /// The `gas` field is `Option<u64>`; the `None` branch (e.g. a report whose gas was never
    /// computed) must also survive the round trip in both formats.
    #[test]
    fn execution_report_default_and_none_gas_round_trip() {
        let report = ExecutionReport::default();
        assert_eq!(report.gas, None);

        let json: ExecutionReport =
            serde_json::from_str(&serde_json::to_string(&report).expect("ser")).expect("de");
        assert_eq!(report, json);

        let bin: ExecutionReport =
            bincode::deserialize(&bincode::serialize(&report).expect("ser")).expect("de");
        assert_eq!(report, bin);
    }
}
