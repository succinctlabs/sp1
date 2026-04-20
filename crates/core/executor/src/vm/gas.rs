use crate::{
    events::{MemoryRecord, NUM_PAGE_PROT_ENTRIES_PER_ROW_EXEC},
    CompressedMemory, ExecutionReport, Instruction, Opcode, RiscvAirId, SyscallCode,
};
use enum_map::EnumMap;
use hashbrown::{HashMap, HashSet};
use std::str::FromStr;

use super::shapes::riscv_air_id_from_opcode_flag;

// Trusted gas estimation calculator
// For a given executor, calculate the total complexity and trace area
// Based off of ShapeChecker
pub struct ReportGenerator {
    pub opcode_counts: EnumMap<Opcode, u64>,
    pub syscall_counts: EnumMap<SyscallCode, u64>,
    pub deferred_syscall_counts: EnumMap<SyscallCode, u64>,
    pub system_chips_counts: EnumMap<RiscvAirId, u64>,

    pub(crate) syscall_sent: bool,
    pub(crate) local_mem_counts: u64,
    /// The number of local page prot accesses during this cycle.
    pub(crate) local_page_prot_counts: u64,
    is_last_read_external: CompressedMemory,
    /// Whether the last page prot access was external, ie: it was read from a deferred precompile.
    is_last_page_prot_access_external: HashMap<u64, bool>,

    trace_cost_lookup: EnumMap<RiscvAirId, u64>,

    /// Running count of page prot entries.
    page_prot_entry_count: u64,
    enable_untrusted_programs: bool,

    shard_start_clk: u64,
    exit_code: u64,
}

impl ReportGenerator {
    pub fn new(shard_start_clk: u64, enable_untrusted_programs: bool) -> Self {
        let costs: HashMap<String, usize> =
            serde_json::from_str(include_str!("../artifacts/rv64im_costs.json")).unwrap();
        let costs: EnumMap<RiscvAirId, u64> =
            costs.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v as u64)).collect();

        Self {
            trace_cost_lookup: costs,
            opcode_counts: EnumMap::default(),
            syscall_counts: EnumMap::default(),
            deferred_syscall_counts: EnumMap::default(),
            system_chips_counts: EnumMap::default(),
            syscall_sent: false,
            local_mem_counts: 0,
            local_page_prot_counts: 0,
            is_last_read_external: CompressedMemory::new(),
            is_last_page_prot_access_external: HashMap::new(),
            page_prot_entry_count: 0,
            enable_untrusted_programs,
            shard_start_clk,
            exit_code: 0,
        }
    }

    /// Set the start clock of the shard.
    #[inline]
    pub fn reset(&mut self, clk: u64) {
        *self = Self::new(clk, self.enable_untrusted_programs);
    }

    pub fn get_costs(&self) -> (u64, u64) {
        (self.sum_total_complexity(), self.sum_total_trace_area())
    }

    /// Generate an `ExecutionReport` from the current state of the `ReportGenerator`
    pub fn generate_report(&self) -> ExecutionReport {
        // Combine syscall_counts and deferred_syscall_counts, converting from row counts
        // back to invocation counts for the report. Internally these fields store
        // rows_per_event * invocations for gas calculation; the report should show
        // actual invocation counts.
        let mut total_syscall_counts = EnumMap::default();
        for (syscall_code, &count) in self.syscall_counts.iter() {
            if count > 0 {
                if let Some(air_id) = syscall_code.as_air_id() {
                    total_syscall_counts[syscall_code] += count / air_id.rows_per_event() as u64;
                }
            }
        }
        for (syscall_code, &count) in self.deferred_syscall_counts.iter() {
            if count > 0 {
                if let Some(air_id) = syscall_code.as_air_id() {
                    total_syscall_counts[syscall_code] += count / air_id.rows_per_event() as u64;
                }
            }
        }

        let (complexity, trace_area) = self.get_costs();
        // Use integer arithmetic to avoid f64 precision warnings
        // 0.3 * trace_area + 0.1 * complexity ≈ (3 * trace_area + complexity) / 10
        let gas = (3 * trace_area + complexity) / 10;

        ExecutionReport {
            opcode_counts: Box::new(self.opcode_counts),
            syscall_counts: Box::new(total_syscall_counts),
            cycle_tracker: HashMap::new(),
            invocation_tracker: HashMap::new(),
            touched_memory_addresses: 0,
            gas: Some(gas),
            exit_code: self.exit_code,
        }
    }

    // Set the exit code which will be returned when the `ExecutionReport` is generated.
    pub fn set_exit_code(&mut self, exit_code: u64) {
        self.exit_code = exit_code;
    }

    /// Helper method to filter out opcode counts with zero values
    fn filtered_opcode_counts(&self) -> impl Iterator<Item = (Opcode, u64)> + '_ {
        self.opcode_counts
            .iter()
            .filter(|(_, &count)| count > 0)
            .map(|(opcode, &count)| (opcode, count))
    }

    fn sum_total_complexity(&self) -> u64 {
        self.filtered_opcode_counts()
            .map(|(opcode, count)| {
                get_complexity_mapping()
                    [riscv_air_id_from_opcode_flag(opcode, self.enable_untrusted_programs)]
                    * count
            })
            .sum::<u64>()
            + self
                .syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) =
                        syscall_code.as_air_id_flag(self.enable_untrusted_programs)
                    {
                        get_complexity_mapping()[syscall_air_id] * count
                    } else {
                        0
                    }
                })
                .sum::<u64>()
            + self
                .deferred_syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) =
                        syscall_code.as_air_id_flag(self.enable_untrusted_programs)
                    {
                        get_complexity_mapping()[syscall_air_id] * count
                    } else {
                        0
                    }
                })
                .sum::<u64>()
            + self
                .system_chips_counts
                .iter()
                .map(|(riscv_air_id, count)| get_complexity_mapping()[riscv_air_id] * count)
                .sum::<u64>()
    }

    fn sum_total_trace_area(&self) -> u64 {
        self.filtered_opcode_counts()
            .map(|(opcode, count)| {
                self.trace_cost_lookup
                    [riscv_air_id_from_opcode_flag(opcode, self.enable_untrusted_programs)]
                    * count
            })
            .sum::<u64>()
            + self
                .syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) =
                        syscall_code.as_air_id_flag(self.enable_untrusted_programs)
                    {
                        self.trace_cost_lookup[syscall_air_id] * count
                    } else {
                        0
                    }
                })
                .sum::<u64>()
            + self
                .deferred_syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) =
                        syscall_code.as_air_id_flag(self.enable_untrusted_programs)
                    {
                        self.trace_cost_lookup[syscall_air_id] * count
                    } else {
                        0
                    }
                })
                .sum::<u64>()
            + self
                .system_chips_counts
                .iter()
                .map(|(riscv_air_id, count)| self.trace_cost_lookup[riscv_air_id] * count)
                .sum::<u64>()
    }

    #[inline]
    pub fn handle_mem_event(&mut self, addr: u64, clk: u64) {
        // Round down to the nearest 8-byte aligned address.
        let addr = if addr > 31 { addr & !0b111 } else { addr };

        let is_external = self.syscall_sent;

        let is_first_read_this_shard = self.shard_start_clk > clk;

        let is_last_read_external = self.is_last_read_external.insert(addr, is_external);

        self.local_mem_counts +=
            (is_first_read_this_shard || (is_last_read_external && !is_external)) as u64;
    }

    #[inline]
    pub fn local_mem_syscall_rr(&mut self) {
        self.local_mem_counts += self.syscall_sent as u64;
    }

    #[inline]
    pub fn handle_page_prot_event(&mut self, page_idx: u64, clk: u64) {
        let is_external = self.syscall_sent;
        let is_first_read_this_shard = self.shard_start_clk > clk;
        let is_last_page_prot_access_external =
            self.is_last_page_prot_access_external.insert(page_idx, is_external).unwrap_or(false);

        self.local_page_prot_counts += (is_first_read_this_shard
            || (is_last_page_prot_access_external && !is_external))
            as u64;
    }

    #[inline]
    pub fn handle_page_prot_check(&mut self) {
        self.page_prot_entry_count += 1;
        self.system_chips_counts[RiscvAirId::PageProt] =
            self.page_prot_entry_count.div_ceil(NUM_PAGE_PROT_ENTRIES_PER_ROW_EXEC as u64);
    }

    #[inline]
    pub fn handle_trap_exec_event(&mut self) {
        self.system_chips_counts[RiscvAirId::TrapExec] += 1;
    }

    #[inline]
    pub fn handle_trap_mem_event(&mut self) {
        self.system_chips_counts[RiscvAirId::TrapMem] += 1;
    }

    #[inline]
    pub fn handle_trap_events(&mut self, bump_clk_high: bool) {
        self.update_system_chip_counts(bump_clk_high, bump_clk_high);
    }

    #[inline]
    pub fn handle_untrusted_instruction(&mut self) {
        self.system_chips_counts[RiscvAirId::InstructionFetch] += 1;
    }

    #[inline]
    pub fn handle_retained_syscall(&mut self, syscall_code: SyscallCode) {
        if let Some(syscall_air_id) = syscall_code.as_air_id() {
            let rows_per_event = syscall_air_id.rows_per_event() as u64;

            self.syscall_counts[syscall_code] += rows_per_event;
        }
    }

    #[inline]
    pub fn get_syscall_sent(&self) -> bool {
        self.syscall_sent
    }

    #[inline]
    pub fn set_syscall_sent(&mut self, syscall_sent: bool) {
        self.syscall_sent = syscall_sent;
    }

    #[inline]
    pub fn add_global_init_and_finalize_counts(
        &mut self,
        final_registers: &[MemoryRecord; 32],
        mut touched_addresses: HashSet<u64>,
        hint_init_events_addrs: &HashSet<u64>,
        memory_image_addrs: &[u64],
    ) {
        touched_addresses.extend(memory_image_addrs);

        // Add init for registers
        self.system_chips_counts[RiscvAirId::MemoryGlobalInit] += 32;

        // Add finalize for registers
        self.system_chips_counts[RiscvAirId::MemoryGlobalFinalize] +=
            final_registers.iter().enumerate().filter(|(_, e)| e.timestamp != 0).count() as u64;

        // Add memory init events
        self.system_chips_counts[RiscvAirId::MemoryGlobalInit] +=
            hint_init_events_addrs.len() as u64;

        let memory_init_events = touched_addresses
            .iter()
            .filter(|addr| !memory_image_addrs.contains(*addr))
            .filter(|addr| !hint_init_events_addrs.contains(*addr));
        self.system_chips_counts[RiscvAirId::MemoryGlobalInit] += memory_init_events.count() as u64;

        touched_addresses.extend(hint_init_events_addrs.clone());
        self.system_chips_counts[RiscvAirId::MemoryGlobalFinalize] +=
            touched_addresses.len() as u64;
    }

    /// Increment the trace area for the given instruction.
    ///
    /// # Arguments
    ///
    /// * `instruction`: The instruction that is being handled.
    /// * `bump_clk_high`: Whether the clk's top 24 bits incremented during this cycle.
    /// * `is_load_x0`: Whether the instruction is a load of x0, if so the riscv air id is `LoadX0`.
    /// * `needs_state_bump`: Whether this cycle induced a state bump.
    #[inline]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn handle_instruction(
        &mut self,
        instruction: &Instruction,
        bump_clk_high: bool,
        _is_load_x0: bool,
        needs_state_bump: bool,
    ) {
        self.opcode_counts[instruction.opcode] += 1;
        self.update_system_chip_counts(bump_clk_high, needs_state_bump);
    }

    /// Update system chip counts based on the current cycle's state.
    fn update_system_chip_counts(&mut self, bump_clk_high: bool, needs_state_bump: bool) {
        let touched_addresses: u64 = std::mem::take(&mut self.local_mem_counts);
        let syscall_sent = std::mem::take(&mut self.syscall_sent);

        let bump_clk_high_num_events = 32 * bump_clk_high as u64;
        self.system_chips_counts[RiscvAirId::MemoryBump] += bump_clk_high_num_events;
        self.system_chips_counts[RiscvAirId::MemoryLocal] += touched_addresses;
        self.system_chips_counts[RiscvAirId::StateBump] += needs_state_bump as u64;
        self.system_chips_counts[RiscvAirId::Global] += 2 * touched_addresses + syscall_sent as u64;
        self.system_chips_counts[RiscvAirId::SyscallCore] += syscall_sent as u64;
    }

    /// Update system chip counts based on the current cycle's page count state.
    pub fn update_page_chip_counts(&mut self) {
        let touched_pages: u64 = std::mem::take(&mut self.local_page_prot_counts);
        self.system_chips_counts[RiscvAirId::Global] += 2 * touched_pages;
        self.system_chips_counts[RiscvAirId::PageProtLocal] += touched_pages;
    }

    #[inline]
    pub fn syscall_sent(&mut self, syscall_code: SyscallCode) {
        self.syscall_sent = true;
        if let Some(syscall_air_id) = syscall_code.as_air_id() {
            let rows_per_event = syscall_air_id.rows_per_event() as u64;

            self.deferred_syscall_counts[syscall_code] += rows_per_event;
        }
    }
}

/// Returns a mapping of `RiscvAirId` to their associated complexity codes.
/// This provides the complexity cost for each AIR component in the system.
#[must_use]
pub fn get_complexity_mapping() -> EnumMap<RiscvAirId, u64> {
    #[cfg(not(feature = "mprotect"))]
    let json = include_str!("../artifacts/rv64im_complexity.json");
    #[cfg(feature = "mprotect")]
    let json = include_str!("../artifacts/rv64im_complexity_mprotect.json");

    let complexity: HashMap<String, u64> = serde_json::from_str(json).unwrap();
    complexity.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v)).collect()
}
