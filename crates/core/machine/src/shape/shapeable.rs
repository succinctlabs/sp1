use hashbrown::HashMap;
use itertools::Itertools;

use sp1_core_executor::{events::PrecompileLocalMemory, ExecutionRecord, RiscvAirId};
use sp1_stark::MachineRecord;

use crate::memory::NUM_LOCAL_MEMORY_ENTRIES_PER_ROW;

#[derive(Debug, Clone, Copy)]
pub enum ShardKind {
    PackedCore,
    Core,
    GlobalMemory,
    Precompile,
}

pub trait Shapeable {
    fn kind(&self) -> ShardKind;
    fn shard(&self) -> u32;
    fn log2_shard_size(&self) -> usize;
    fn debug_stats(&self) -> HashMap<String, usize>;
    fn core_heights(&self) -> Vec<(RiscvAirId, usize)>;
    fn memory_heights(&self) -> Vec<(RiscvAirId, usize)>;
    /// TODO. Returns all precompile events, assuming there is only one kind in `Self`.
    /// The tuple is of the form `(height, (num_memory_local_events, num_global_events))`
    fn precompile_heights(&self) -> impl Iterator<Item = (RiscvAirId, (usize, usize, usize))>;
}

impl Shapeable for ExecutionRecord {
    fn kind(&self) -> ShardKind {
        let contains_global_memory = !self.global_memory_initialize_events.is_empty() ||
            !self.global_memory_finalize_events.is_empty();
        match (self.contains_cpu(), contains_global_memory) {
            (true, true) => ShardKind::PackedCore,
            (true, false) => ShardKind::Core,
            (false, true) => ShardKind::GlobalMemory,
            (false, false) => ShardKind::Precompile,
        }
    }
    fn shard(&self) -> u32 {
        self.public_values.shard
    }

    fn log2_shard_size(&self) -> usize {
        self.cpu_events.len().next_power_of_two().ilog2() as usize
    }

    fn debug_stats(&self) -> HashMap<String, usize> {
        self.stats()
    }

    fn core_heights(&self) -> Vec<(RiscvAirId, usize)> {
        vec![
            (RiscvAirId::Cpu, self.cpu_events.len()),
            (RiscvAirId::DivRem, self.divrem_events.len()),
            (RiscvAirId::AddSub, self.add_events.len() + self.sub_events.len()),
            (RiscvAirId::Bitwise, self.bitwise_events.len()),
            (RiscvAirId::Mul, self.mul_events.len()),
            (RiscvAirId::ShiftRight, self.shift_right_events.len()),
            (RiscvAirId::ShiftLeft, self.shift_left_events.len()),
            (RiscvAirId::Lt, self.lt_events.len()),
            (
                RiscvAirId::MemoryLocal,
                self.get_local_mem_events()
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (RiscvAirId::MemoryInstrs, self.memory_instr_events.len()),
            (RiscvAirId::Auipc, self.auipc_events.len()),
            (RiscvAirId::Branch, self.branch_events.len()),
            (RiscvAirId::Jump, self.jump_events.len()),
            (RiscvAirId::Global, self.global_interaction_events.len()),
            (RiscvAirId::SyscallCore, self.syscall_events.len()),
            (RiscvAirId::SyscallInstrs, self.syscall_events.len()),
        ]
    }

    fn memory_heights(&self) -> Vec<(RiscvAirId, usize)> {
        vec![
            (RiscvAirId::MemoryGlobalInit, self.global_memory_initialize_events.len()),
            (RiscvAirId::MemoryGlobalFinalize, self.global_memory_finalize_events.len()),
            (
                RiscvAirId::Global,
                self.global_memory_finalize_events.len() +
                    self.global_memory_initialize_events.len(),
            ),
        ]
    }

    fn precompile_heights(&self) -> impl Iterator<Item = (RiscvAirId, (usize, usize, usize))> {
        self.precompile_events.events.iter().filter_map(|(code, events)| {
            // Skip empty events.
            (!events.is_empty()).then_some(())?;
            let id = code.as_air_id()?;
            Some((
                id,
                (
                    events.len() * id.rows_per_event(),
                    events.get_local_mem_events().into_iter().count(),
                    self.global_interaction_events.len(),
                ),
            ))
        })
    }
}
