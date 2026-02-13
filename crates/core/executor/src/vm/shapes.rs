use enum_map::EnumMap;
use hashbrown::HashMap;

use crate::{
    vm::memory::CompressedMemory, Instruction, Opcode, RiscvAirId, ShardingThreshold, SyscallCode,
    BYTE_NUM_ROWS, RANGE_NUM_ROWS,
};
use std::str::FromStr;

/// The maximum trace area from padding with next multiple of 32.
/// The correctness of this value is checked in the test `test_maximum_padding`.
pub const MAXIMUM_PADDING_AREA: u64 = 1 << 18;

/// The maximum trace area from a single cycle.
/// The correctness of this value is checked in the test `test_maximum_cycle`.
pub const MAXIMUM_CYCLE_AREA: u64 = 1 << 18;

/// The maximum trace area from the `syscall_halt` function.
pub const HALT_AREA: u64 = 1 << 18;

/// The maximum height from the `syscall_halt` function.
pub const HALT_HEIGHT: u64 = 1 << 10;

pub struct ShapeChecker {
    program_len: u64,
    trace_area: u64,
    max_height: u64,
    is_commit_on: bool,
    pub(crate) syscall_sent: bool,
    // The start of the most recent shard according to the shape checking logic.
    shard_start_clk: u64,
    /// The maximum trace size and table height to allow.
    sharding_threshold: ShardingThreshold,
    /// The heights (number) of each air id seen.
    heights: EnumMap<RiscvAirId, u64>,
    /// The costs (trace area) of  of each air id seen.
    costs: EnumMap<RiscvAirId, u64>,
    // The number of local memory accesses during this cycle.
    pub(crate) local_mem_counts: u64,
    /// Whether the last read was external, ie: it was read from a deferred precompile.
    is_last_read_external: CompressedMemory,
}

impl ShapeChecker {
    pub fn new(program_len: u64, shard_start_clk: u64, elem_threshold: ShardingThreshold) -> Self {
        let costs: HashMap<String, usize> =
            serde_json::from_str(include_str!("../artifacts/rv64im_costs.json")).unwrap();
        let costs: EnumMap<RiscvAirId, u64> =
            costs.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v as u64)).collect();

        let preprocessed_trace_area = program_len.next_multiple_of(32) * costs[RiscvAirId::Program]
            + BYTE_NUM_ROWS * costs[RiscvAirId::Byte]
            + RANGE_NUM_ROWS * costs[RiscvAirId::Range];

        let ShardingThreshold { element_threshold, height_threshold } = elem_threshold;
        assert!(
            element_threshold >= HALT_AREA && height_threshold >= HALT_HEIGHT,
            "invalid sharding threshold"
        );

        Self {
            program_len,
            trace_area: preprocessed_trace_area + MAXIMUM_PADDING_AREA + MAXIMUM_CYCLE_AREA,
            max_height: 0,
            is_commit_on: false,
            syscall_sent: false,
            shard_start_clk,
            heights: EnumMap::default(),
            sharding_threshold: ShardingThreshold {
                element_threshold: element_threshold - HALT_AREA,
                height_threshold: height_threshold - HALT_HEIGHT,
            },
            costs,
            // Assume that all registers will be touched in each shard.
            local_mem_counts: 32,
            is_last_read_external: CompressedMemory::new(),
        }
    }

    #[inline]
    pub fn handle_mem_event(&mut self, addr: u64, clk: u64) {
        // Round down to the nearest 8-byte aligned address.
        let addr = addr & !0b111;

        let is_external = self.syscall_sent;
        let is_first_read_this_shard = self.shard_start_clk > clk;
        let is_last_read_external = self.is_last_read_external.insert(addr, is_external);

        self.local_mem_counts +=
            (is_first_read_this_shard || (is_last_read_external && !is_external)) as u64;
    }

    #[inline]
    pub fn handle_commit(&mut self) {
        self.is_commit_on = true;
    }

    #[inline]
    pub fn handle_retained_syscall(&mut self, syscall_code: SyscallCode) {
        if let Some(syscall_air_id) = syscall_code.as_air_id() {
            let rows_per_event = syscall_air_id.rows_per_event() as u64;

            self.heights[syscall_air_id] += rows_per_event;

            self.trace_area += rows_per_event * self.costs[syscall_air_id];
            self.max_height = self.max_height.max(self.heights[syscall_air_id]);

            // Currently, all precompiles with `rows_per_event > 1` have the respective control
            // chip.
            if rows_per_event > 1 {
                self.trace_area += self.costs[syscall_air_id
                    .control_air_id()
                    .expect("Controls AIRs are found for each precompile with rows_per_event > 1")];
            }
        }
    }

    #[inline]
    pub fn syscall_sent(&mut self) {
        self.syscall_sent = true;
    }

    /// Set the start clock of the shard.
    #[inline]
    pub fn reset(&mut self, clk: u64) {
        *self = Self::new(self.program_len, clk, self.sharding_threshold);
    }

    /// Check if the shard limit has been reached.
    ///
    /// # Returns
    ///
    /// Whether the shard limit has been reached.
    #[inline]
    pub fn check_shard_limit(&self) -> bool {
        !self.is_commit_on
            && (self.trace_area >= self.sharding_threshold.element_threshold
                || self.max_height >= self.sharding_threshold.height_threshold)
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
    #[allow(clippy::fn_params_excessive_bools)]
    pub fn handle_instruction(
        &mut self,
        instruction: &Instruction,
        bump_clk_high: bool,
        is_load_x0: bool,
        needs_state_bump: bool,
    ) {
        let touched_addresses: u64 = std::mem::take(&mut self.local_mem_counts);
        let syscall_sent = std::mem::take(&mut self.syscall_sent);

        let riscv_air_id = if is_load_x0 {
            RiscvAirId::LoadX0
        } else {
            riscv_air_id_from_opcode(instruction.opcode)
        };

        // Increment the height and trace area for the riscv air id
        self.heights[riscv_air_id] += 1;
        self.max_height = self.max_height.max(self.heights[riscv_air_id]);
        self.trace_area += self.costs[riscv_air_id];

        // Increment for each touched address in memory local
        self.trace_area += touched_addresses * self.costs[RiscvAirId::MemoryLocal];
        self.heights[RiscvAirId::MemoryLocal] += touched_addresses;
        self.max_height = self.max_height.max(self.heights[RiscvAirId::MemoryLocal]);

        // Increment for all the global interactions
        self.trace_area +=
            self.costs[RiscvAirId::Global] * (2 * touched_addresses + syscall_sent as u64);
        self.heights[RiscvAirId::Global] += 2 * touched_addresses + syscall_sent as u64;
        self.max_height = self.max_height.max(self.heights[RiscvAirId::Global]);

        // Increment by if bump_clk_high is needed
        if bump_clk_high {
            let bump_clk_high_num_events = 32;
            self.trace_area += bump_clk_high_num_events * self.costs[RiscvAirId::MemoryBump];
            self.heights[RiscvAirId::MemoryBump] += bump_clk_high_num_events;
            self.max_height = self.max_height.max(self.heights[RiscvAirId::MemoryBump]);
        }

        // Increment if this cycle induced a state bump.
        if needs_state_bump {
            self.trace_area += self.costs[RiscvAirId::StateBump];
            self.heights[RiscvAirId::StateBump] += 1;
            self.max_height = self.max_height.max(self.heights[RiscvAirId::StateBump]);
        }

        if syscall_sent {
            // Increment if the syscall is retained
            self.trace_area += self.costs[RiscvAirId::SyscallCore];
            self.heights[RiscvAirId::SyscallCore] += 1;
            self.max_height = self.max_height.max(self.heights[RiscvAirId::SyscallCore]);
        }
    }
}

#[inline]
pub fn riscv_air_id_from_opcode(opcode: Opcode) -> RiscvAirId {
    match opcode {
        Opcode::ADD => RiscvAirId::Add,
        Opcode::ADDI => RiscvAirId::Addi,
        Opcode::ADDW => RiscvAirId::Addw,
        Opcode::SUB => RiscvAirId::Sub,
        Opcode::SUBW => RiscvAirId::Subw,
        Opcode::XOR | Opcode::OR | Opcode::AND => RiscvAirId::Bitwise,
        Opcode::SLT | Opcode::SLTU => RiscvAirId::Lt,
        Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU | Opcode::MULW => {
            RiscvAirId::Mul
        }
        Opcode::DIV
        | Opcode::DIVU
        | Opcode::REM
        | Opcode::REMU
        | Opcode::DIVW
        | Opcode::DIVUW
        | Opcode::REMW
        | Opcode::REMUW => RiscvAirId::DivRem,
        Opcode::SLL | Opcode::SLLW => RiscvAirId::ShiftLeft,
        Opcode::SRLW | Opcode::SRAW | Opcode::SRL | Opcode::SRA => RiscvAirId::ShiftRight,
        Opcode::LB | Opcode::LBU => RiscvAirId::LoadByte,
        Opcode::LH | Opcode::LHU => RiscvAirId::LoadHalf,
        Opcode::LW | Opcode::LWU => RiscvAirId::LoadWord,
        Opcode::LD => RiscvAirId::LoadDouble,
        Opcode::SB => RiscvAirId::StoreByte,
        Opcode::SH => RiscvAirId::StoreHalf,
        Opcode::SW => RiscvAirId::StoreWord,
        Opcode::SD => RiscvAirId::StoreDouble,
        Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
            RiscvAirId::Branch
        }
        Opcode::AUIPC | Opcode::LUI => RiscvAirId::UType,
        Opcode::JAL => RiscvAirId::Jal,
        Opcode::JALR => RiscvAirId::Jalr,
        Opcode::ECALL => RiscvAirId::SyscallInstrs,
        _ => {
            eprintln!("Unknown opcode: {opcode:?}");
            unreachable!()
        }
    }
}
