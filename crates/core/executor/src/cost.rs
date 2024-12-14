use enum_map::EnumMap;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;

use crate::RiscvAirId;

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
