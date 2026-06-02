//! The `HINT_READ` syscall: an arbitrary write of `len_bytes.div_ceil(8)` words starting at `ptr`.
//!
//! - [`HintReadControlChip`] receives the syscall and bookends the per-word state machine.
//! - [`HintReadChip`] performs one word's write per row, advancing the index.

mod control;
mod read;

pub use control::*;
pub use read::*;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sp1_core_executor::{
        events::{HintReadEvent, MemoryWriteRecord, PrecompileEvent, SyscallEvent},
        ExecutionRecord, SyscallCode,
    };
    use sp1_hypercube::{Chip, InteractionKind};

    use super::*;
    use crate::memory::test_util::{
        accumulate_interactions, assert_bus_balanced, assert_constraints_satisfied, full_trace,
    };

    /// A record with one `HINT_READ` event per entry in `word_lens`.
    fn test_record(word_lens: &[usize]) -> ExecutionRecord {
        let clk = 1 << 20;
        let mut record = ExecutionRecord::default();
        let mut ptr = 1 << 16;
        for &len_words in word_lens {
            let memory_records = (0..len_words)
                .map(|i| MemoryWriteRecord {
                    prev_timestamp: 0,
                    prev_value: 0,
                    value: 0xdead_0000 + i as u64,
                    timestamp: clk,
                    prev_page_prot_record: None,
                })
                .collect::<Vec<_>>();
            let len_bytes = (len_words * 8) as u64;
            let event = HintReadEvent { clk, ptr, len_bytes, memory_records };
            let syscall_event = SyscallEvent {
                pc: 0,
                next_pc: 0,
                clk,
                should_send: true,
                syscall_code: SyscallCode::HINT_READ,
                syscall_id: SyscallCode::HINT_READ.syscall_id(),
                arg1: ptr,
                arg2: len_bytes,
                exit_code: 0,
                sig_return_pc_record: None,
                trap_result: None,
                trap_error: None,
            };
            record.add_precompile_event(
                SyscallCode::HINT_READ,
                syscall_event,
                PrecompileEvent::HintRead(event),
            );
            ptr += 1 << 16;
        }
        record
    }

    /// The control chip's bookend states cancel the per-word chip's chain on the `HintRead` bus.
    #[test]
    fn hint_read_bus_balances() {
        let record = test_record(&[3, 1, 7]);
        let ctrl = Chip::new(HintReadControlChip::new());
        let read = Chip::new(HintReadChip::new());

        let mut totals = HashMap::new();
        accumulate_interactions(
            &ctrl,
            &full_trace(&ctrl, &record),
            &[InteractionKind::HintRead],
            &mut totals,
        );
        accumulate_interactions(
            &read,
            &full_trace(&read, &record),
            &[InteractionKind::HintRead],
            &mut totals,
        );
        assert_bus_balanced(&totals);
    }

    /// Both chips' AIR constraints hold on their generated traces.
    #[test]
    fn hint_read_constraints_hold() {
        let record = test_record(&[3, 1, 7]);
        let ctrl = Chip::new(HintReadControlChip::new());
        let read = Chip::new(HintReadChip::new());

        assert_constraints_satisfied(&ctrl, &full_trace(&ctrl, &record));
        assert_constraints_satisfied(&read, &full_trace(&read, &record));
    }
}
