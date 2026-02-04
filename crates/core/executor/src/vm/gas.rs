use crate::{
    events::MemoryRecord, vm::shapes::riscv_air_id_from_opcode, CompressedMemory, ExecutionReport,
    Instruction, Opcode, RiscvAirId, SyscallCode,
};
use enum_map::EnumMap;
use hashbrown::{HashMap, HashSet};
use std::str::FromStr;

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
    is_last_read_external: CompressedMemory,

    trace_cost_lookup: EnumMap<RiscvAirId, u64>,

    shard_start_clk: u64,
    exit_code: u64,
}

impl ReportGenerator {
    pub fn new(shard_start_clk: u64) -> Self {
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
            is_last_read_external: CompressedMemory::new(),
            shard_start_clk,
            exit_code: 0,
        }
    }

    /// Set the start clock of the shard.
    #[inline]
    pub fn reset(&mut self, clk: u64) {
        *self = Self::new(clk);
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
                get_complexity_mapping()[riscv_air_id_from_opcode(opcode)] * count
            })
            .sum::<u64>()
            + self
                .syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
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
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
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
            .map(|(opcode, count)| self.trace_cost_lookup[riscv_air_id_from_opcode(opcode)] * count)
            .sum::<u64>()
            + self
                .syscall_counts
                .iter()
                .map(|(syscall_code, count)| {
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
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
                    if let Some(syscall_air_id) = syscall_code.as_air_id() {
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
    pub fn handle_retained_syscall(&mut self, syscall_code: SyscallCode) {
        if let Some(syscall_air_id) = syscall_code.as_air_id() {
            let rows_per_event = syscall_air_id.rows_per_event() as u64;

            self.syscall_counts[syscall_code] += rows_per_event;
        }
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
    /// * `syscall_sent`: Whether a syscall was sent during this cycle.
    /// * `bump_clk_high`: Whether the clk's top 24 bits incremented during this cycle.
    /// * `is_load_x0`: Whether the instruction is a load of x0, if so the riscv air id is `LoadX0`.
    ///
    /// # Returns
    ///
    /// Whether the shard limit has been reached.
    #[inline]
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn handle_instruction(
        &mut self,
        instruction: &Instruction,
        bump_clk_high: bool,
        _is_load_x0: bool,
        needs_state_bump: bool,
    ) {
        let touched_addresses: u64 = std::mem::take(&mut self.local_mem_counts);
        let syscall_sent = std::mem::take(&mut self.syscall_sent);

        // Increment for opcode
        self.opcode_counts[instruction.opcode] += 1;

        // Increment system chips
        // Increment by if bump_clk_high is needed
        let bump_clk_high_num_events = 32 * bump_clk_high as u64;
        self.system_chips_counts[RiscvAirId::MemoryBump] += bump_clk_high_num_events;
        self.system_chips_counts[RiscvAirId::MemoryLocal] += touched_addresses;
        self.system_chips_counts[RiscvAirId::StateBump] += needs_state_bump as u64;
        self.system_chips_counts[RiscvAirId::Global] += 2 * touched_addresses + syscall_sent as u64;

        // Increment if the syscall is retained
        self.system_chips_counts[RiscvAirId::SyscallCore] += syscall_sent as u64;
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
    let mut mapping = EnumMap::<RiscvAirId, u64>::default();

    // Core program and system components
    mapping[RiscvAirId::Program] = 0;
    mapping[RiscvAirId::SyscallCore] = 2;
    mapping[RiscvAirId::SyscallPrecompile] = 2;

    // SHA components
    mapping[RiscvAirId::ShaExtend] = 80;
    mapping[RiscvAirId::ShaExtendControl] = 21;
    mapping[RiscvAirId::ShaCompress] = 300;
    mapping[RiscvAirId::ShaCompressControl] = 21;

    // Elliptic curve operations
    mapping[RiscvAirId::EdAddAssign] = 792;
    mapping[RiscvAirId::EdDecompress] = 755;

    // Secp256k1 operations
    mapping[RiscvAirId::Secp256k1Decompress] = 691;
    mapping[RiscvAirId::Secp256k1AddAssign] = 918;
    mapping[RiscvAirId::Secp256k1DoubleAssign] = 904;

    // Secp256r1 operations
    mapping[RiscvAirId::Secp256r1Decompress] = 691;
    mapping[RiscvAirId::Secp256r1AddAssign] = 918;
    mapping[RiscvAirId::Secp256r1DoubleAssign] = 904;

    // Keccak operations
    mapping[RiscvAirId::KeccakPermute] = 2859;
    mapping[RiscvAirId::KeccakPermuteControl] = 331;

    // Bn254 operations
    mapping[RiscvAirId::Bn254AddAssign] = 918;
    mapping[RiscvAirId::Bn254DoubleAssign] = 904;

    // BLS12-381 operations
    mapping[RiscvAirId::Bls12381AddAssign] = 1374;
    mapping[RiscvAirId::Bls12381DoubleAssign] = 1356;
    mapping[RiscvAirId::Bls12381Decompress] = 1237;

    // Uint256 operations
    mapping[RiscvAirId::Uint256MulMod] = 253;
    mapping[RiscvAirId::Uint256Ops] = 297;
    mapping[RiscvAirId::U256XU2048Mul] = 1197;

    // Field operations
    mapping[RiscvAirId::Bls12381FpOpAssign] = 317;
    mapping[RiscvAirId::Bls12381Fp2AddSubAssign] = 615;
    mapping[RiscvAirId::Bls12381Fp2MulAssign] = 994;
    mapping[RiscvAirId::Bn254FpOpAssign] = 217;
    mapping[RiscvAirId::Bn254Fp2AddSubAssign] = 415;
    mapping[RiscvAirId::Bn254Fp2MulAssign] = 666;

    // System operations
    mapping[RiscvAirId::Mprotect] = 11;
    mapping[RiscvAirId::Poseidon2] = 497;

    // RISC-V instruction costs
    mapping[RiscvAirId::DivRem] = 347;
    mapping[RiscvAirId::Add] = 15;
    mapping[RiscvAirId::Addi] = 14;
    mapping[RiscvAirId::Addw] = 20;
    mapping[RiscvAirId::Sub] = 15;
    mapping[RiscvAirId::Subw] = 15;
    mapping[RiscvAirId::Bitwise] = 19;
    mapping[RiscvAirId::Mul] = 60;
    mapping[RiscvAirId::ShiftRight] = 77;
    mapping[RiscvAirId::ShiftLeft] = 68;
    mapping[RiscvAirId::Lt] = 41;

    // Memory operations
    mapping[RiscvAirId::LoadByte] = 32;
    mapping[RiscvAirId::LoadHalf] = 33;
    mapping[RiscvAirId::LoadWord] = 33;
    mapping[RiscvAirId::LoadDouble] = 24;
    mapping[RiscvAirId::LoadX0] = 34;
    mapping[RiscvAirId::StoreByte] = 32;
    mapping[RiscvAirId::StoreHalf] = 27;
    mapping[RiscvAirId::StoreWord] = 27;
    mapping[RiscvAirId::StoreDouble] = 23;

    // Control flow
    mapping[RiscvAirId::UType] = 19;
    mapping[RiscvAirId::Branch] = 49;
    mapping[RiscvAirId::Jal] = 24;
    mapping[RiscvAirId::Jalr] = 25;

    // System components
    mapping[RiscvAirId::InstructionDecode] = 160;
    mapping[RiscvAirId::InstructionFetch] = 11;
    mapping[RiscvAirId::SyscallInstrs] = 93;
    mapping[RiscvAirId::MemoryBump] = 5;
    mapping[RiscvAirId::PageProt] = 32;
    mapping[RiscvAirId::PageProtLocal] = 1;
    mapping[RiscvAirId::StateBump] = 8;
    mapping[RiscvAirId::MemoryGlobalInit] = 31;
    mapping[RiscvAirId::MemoryGlobalFinalize] = 31;
    mapping[RiscvAirId::PageProtGlobalInit] = 26;
    mapping[RiscvAirId::PageProtGlobalFinalize] = 25;
    mapping[RiscvAirId::MemoryLocal] = 4;
    mapping[RiscvAirId::Global] = 216;

    // Memory types
    mapping[RiscvAirId::Byte] = 0;
    mapping[RiscvAirId::Range] = 0;

    mapping
}
