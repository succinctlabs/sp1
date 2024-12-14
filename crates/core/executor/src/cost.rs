use enum_map::EnumMap;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;

use crate::{events::NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC, Opcode, RiscvAirId};

const BYTE_NUM_ROWS: u64 = 1 << 16;
const MAX_PROGRAM_SIZE: u64 = 1 << 22;

/// Estimates the LDE area.
#[must_use]
pub fn estimate_riscv_lde_size(
    num_events_per_air: EnumMap<RiscvAirId, u64>,
    costs_per_air: &HashMap<RiscvAirId, u64>,
) -> u64 {
    // Compute the byte chip contribution.
    let mut cells = BYTE_NUM_ROWS * costs_per_air[&RiscvAirId::Byte];

    // Compute the program chip contribution.
    cells += MAX_PROGRAM_SIZE * costs_per_air[&RiscvAirId::Program];

    // Compute the cpu chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Cpu]).next_power_of_two() * costs_per_air[&RiscvAirId::Cpu];

    // Compute the addsub chip contribution.
    cells += (num_events_per_air[RiscvAirId::AddSub]).next_power_of_two()
        * costs_per_air[&RiscvAirId::AddSub];

    // Compute the mul chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Mul]).next_power_of_two() * costs_per_air[&RiscvAirId::Mul];

    // Compute the bitwise chip contribution.
    cells += (num_events_per_air[RiscvAirId::Bitwise]).next_power_of_two()
        * costs_per_air[&RiscvAirId::Bitwise];

    // Compute the shift left chip contribution.
    cells += (num_events_per_air[RiscvAirId::ShiftLeft]).next_power_of_two()
        * costs_per_air[&RiscvAirId::ShiftLeft];

    // Compute the shift right chip contribution.
    cells += (num_events_per_air[RiscvAirId::ShiftRight]).next_power_of_two()
        * costs_per_air[&RiscvAirId::ShiftRight];

    // Compute the divrem chip contribution.
    cells += (num_events_per_air[RiscvAirId::DivRem]).next_power_of_two()
        * costs_per_air[&RiscvAirId::DivRem];

    // Compute the lt chip contribution.
    cells +=
        (num_events_per_air[RiscvAirId::Lt]).next_power_of_two() * costs_per_air[&RiscvAirId::Lt];

    // Compute the memory local chip contribution.
    cells += (num_events_per_air[RiscvAirId::MemoryLocal]).next_power_of_two()
        * costs_per_air[&RiscvAirId::MemoryLocal];

    // Compute the branch chip contribution.
    cells += (num_events_per_air[RiscvAirId::Branch]).next_power_of_two()
        * costs_per_air[&RiscvAirId::Branch];

    // Compute the jump chip contribution.
    cells += (num_events_per_air[RiscvAirId::Jump]).next_power_of_two()
        * costs_per_air[&RiscvAirId::Jump];

    // Compute the auipc chip contribution.
    cells += (num_events_per_air[RiscvAirId::Auipc]).next_power_of_two()
        * costs_per_air[&RiscvAirId::Auipc];

    // Compute the memory instruction chip contribution.
    cells += (num_events_per_air[RiscvAirId::MemoryInstrs]).next_power_of_two()
        * costs_per_air[&RiscvAirId::MemoryInstrs];

    // Compute the syscall instruction chip contribution.
    cells += (num_events_per_air[RiscvAirId::SyscallInstrs]).next_power_of_two()
        * costs_per_air[&RiscvAirId::SyscallInstrs];

    // Compute the syscall core chip contribution.
    cells += (num_events_per_air[RiscvAirId::SyscallCore]).next_power_of_two()
        * costs_per_air[&RiscvAirId::SyscallCore];

    // Compute the global chip contribution.
    cells += (num_events_per_air[RiscvAirId::Global]).next_power_of_two()
        * costs_per_air[&RiscvAirId::Global];

    cells * ((core::mem::size_of::<BabyBear>() << 1) as u64)
}

/// Maps the opcode counts to the number of events in each air.
#[must_use]
pub fn estimate_riscv_event_counts(
    cpu_cycles: u64,
    touched_addresses: u64,
    syscalls_sent: u64,
    opcode_counts: EnumMap<Opcode, u64>,
) -> EnumMap<RiscvAirId, u64> {
    let mut events_counts: EnumMap<RiscvAirId, u64> = EnumMap::default();
    // Compute the number of events in the cpu chip.
    events_counts[RiscvAirId::Cpu] = cpu_cycles;

    // Compute the number of events in the add sub chip.
    events_counts[RiscvAirId::AddSub] = opcode_counts[Opcode::ADD] + opcode_counts[Opcode::SUB];

    // Compute the number of events in the mul chip.
    events_counts[RiscvAirId::Mul] = opcode_counts[Opcode::MUL]
        + opcode_counts[Opcode::MULH]
        + opcode_counts[Opcode::MULHU]
        + opcode_counts[Opcode::MULHSU];

    // Compute the number of events in the bitwise chip.
    events_counts[RiscvAirId::Bitwise] =
        opcode_counts[Opcode::XOR] + opcode_counts[Opcode::OR] + opcode_counts[Opcode::AND];

    // Compute the number of events in the shift left chip.
    events_counts[RiscvAirId::ShiftLeft] = opcode_counts[Opcode::SLL];

    // Compute the number of events in the shift right chip.
    events_counts[RiscvAirId::ShiftRight] = opcode_counts[Opcode::SRL] + opcode_counts[Opcode::SRA];

    // Compute the number of events in the divrem chip.
    events_counts[RiscvAirId::DivRem] = opcode_counts[Opcode::DIV]
        + opcode_counts[Opcode::DIVU]
        + opcode_counts[Opcode::REM]
        + opcode_counts[Opcode::REMU];

    // Compute the number of events in the lt chip.
    events_counts[RiscvAirId::Lt] = opcode_counts[Opcode::SLT] + opcode_counts[Opcode::SLTU];

    // Compute the number of events in the memory local chip.
    events_counts[RiscvAirId::MemoryLocal] =
        touched_addresses.div_ceil(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW_EXEC as u64);

    // Compute the number of events in the branch chip.
    events_counts[RiscvAirId::Branch] = opcode_counts[Opcode::BEQ]
        + opcode_counts[Opcode::BNE]
        + opcode_counts[Opcode::BLT]
        + opcode_counts[Opcode::BGE]
        + opcode_counts[Opcode::BLTU]
        + opcode_counts[Opcode::BGEU];

    // Compute the number of events in the jump chip.
    events_counts[RiscvAirId::Jump] = opcode_counts[Opcode::JAL] + opcode_counts[Opcode::JALR];

    // Compute the number of events in the auipc chip.
    events_counts[RiscvAirId::Auipc] =
        opcode_counts[Opcode::AUIPC] + opcode_counts[Opcode::UNIMP] + opcode_counts[Opcode::EBREAK];

    // Compute the number of events in the memory instruction chip.
    events_counts[RiscvAirId::MemoryInstrs] = opcode_counts[Opcode::LB]
        + opcode_counts[Opcode::LH]
        + opcode_counts[Opcode::LW]
        + opcode_counts[Opcode::LBU]
        + opcode_counts[Opcode::LHU]
        + opcode_counts[Opcode::SB]
        + opcode_counts[Opcode::SH]
        + opcode_counts[Opcode::SW];

    // Compute the number of events in the syscall instruction chip.
    events_counts[RiscvAirId::SyscallInstrs] = opcode_counts[Opcode::ECALL];

    // Compute the number of events in the syscall core chip.
    events_counts[RiscvAirId::SyscallCore] = syscalls_sent;

    // Compute the number of events in the global chip.
    events_counts[RiscvAirId::Global] =
        2 * touched_addresses + events_counts[RiscvAirId::SyscallInstrs];

    // Adjust for divrem dependencies.
    events_counts[RiscvAirId::Mul] += events_counts[RiscvAirId::DivRem];
    events_counts[RiscvAirId::Lt] += events_counts[RiscvAirId::DivRem];

    // We purposefully ignore the additional dependencies for addsub, since this is accounted
    // for in the maximal shapes.
    // events_counts[RiscvAirId::AddSub] += events_counts[RiscvAirId::DivRem];
    // events_counts[RiscvAirId::AddSub] += events_counts[RiscvAirId::MemoryInstrs];
    // events_counts[RiscvAirId::AddSub] += events_counts[RiscvAirId::Branch];
    // events_counts[RiscvAirId::AddSub] += events_counts[RiscvAirId::Jump];
    // events_counts[RiscvAirId::AddSub] += events_counts[RiscvAirId::Auipc];

    events_counts
}

/// Pads the event counts to account for the worst case jump in events across N cycles.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn pad_rv32im_event_counts(
    mut event_counts: EnumMap<RiscvAirId, u64>,
    num_cycles: u64,
) -> EnumMap<RiscvAirId, u64> {
    event_counts.iter_mut().for_each(|(k, v)| match k {
        RiscvAirId::Cpu => *v += num_cycles,
        RiscvAirId::AddSub => *v += 5 * num_cycles,
        RiscvAirId::Mul => *v += 4 * num_cycles,
        RiscvAirId::Bitwise => *v += 3 * num_cycles,
        RiscvAirId::ShiftLeft => *v += num_cycles,
        RiscvAirId::ShiftRight => *v += num_cycles,
        RiscvAirId::DivRem => *v += 4 * num_cycles,
        RiscvAirId::Lt => *v += 2 * num_cycles,
        RiscvAirId::MemoryLocal => *v += 64 * num_cycles,
        RiscvAirId::Branch => *v += 8 * num_cycles,
        RiscvAirId::Jump => *v += 2 * num_cycles,
        RiscvAirId::Auipc => *v += 3 * num_cycles,
        RiscvAirId::MemoryInstrs => *v += 8 * num_cycles,
        RiscvAirId::SyscallInstrs => *v += num_cycles,
        RiscvAirId::SyscallCore => *v += 2 * num_cycles,
        RiscvAirId::Global => *v += 64 * num_cycles,
        _ => (),
    });
    event_counts
}
