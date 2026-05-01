use std::{hash::Hash, str::FromStr};

use hashbrown::HashMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Instruction, Opcode, Register, RiscvAirId, SyscallCode};

/// Serialize a `HashMap<u32, V>` as a `Vec<(u32, V)>`.
pub fn serialize_hashmap_as_vec<K: Eq + Hash + Serialize, V: Serialize, S: Serializer>(
    map: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Serialize::serialize(&map.iter().collect::<Vec<_>>(), serializer)
}

/// Deserialize a `Vec<(u32, V)>` as a `HashMap<u32, V>`.
pub fn deserialize_hashmap_as_vec<
    'de,
    K: Eq + Hash + Deserialize<'de>,
    V: Deserialize<'de>,
    D: Deserializer<'de>,
>(
    deserializer: D,
) -> Result<HashMap<K, V>, D::Error> {
    let seq: Vec<(K, V)> = Deserialize::deserialize(deserializer)?;
    Ok(seq.into_iter().collect())
}

/// Returns `true` if the given `opcode` is a signed 64bit operation.
#[must_use]
pub fn is_signed_64bit_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV || opcode == Opcode::REM
}

/// Returns `true` if the given `opcode` is a unsigned 64bit operation.
#[must_use]
pub fn is_unsigned_64bit_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVU || opcode == Opcode::REMU
}

/// Returns `true` if the given `opcode` is a 64bit operation.
#[must_use]
pub fn is_64bit_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIV
        || opcode == Opcode::DIVU
        || opcode == Opcode::REM
        || opcode == Opcode::REMU
}

/// Returns `true` if the given `opcode` is a word operation.
#[must_use]
pub fn is_word_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVW
        || opcode == Opcode::DIVUW
        || opcode == Opcode::REMW
        || opcode == Opcode::REMUW
}

/// Returns `true` if the given `opcode` is a signed word operation.
#[must_use]
pub fn is_signed_word_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVW || opcode == Opcode::REMW
}

/// Returns `true` if the given `opcode` is a unsigned word operation.
#[must_use]
pub fn is_unsigned_word_operation(opcode: Opcode) -> bool {
    opcode == Opcode::DIVUW || opcode == Opcode::REMUW
}

/// Calculate the correct `quotient` and `remainder` for the given `b` and `c` per RISC-V spec.
#[must_use]
pub fn get_quotient_and_remainder(b: u64, c: u64, opcode: Opcode) -> (u64, u64) {
    if c == 0 && is_64bit_operation(opcode) {
        (u64::MAX, b)
    } else if (c as i32 == 0) && is_word_operation(opcode) {
        (u64::MAX, (b as i32) as u64)
    } else if is_signed_64bit_operation(opcode) {
        ((b as i64).wrapping_div(c as i64) as u64, (b as i64).wrapping_rem(c as i64) as u64)
    } else if is_signed_word_operation(opcode) {
        (
            (b as i32).wrapping_div(c as i32) as i64 as u64,
            (b as i32).wrapping_rem(c as i32) as i64 as u64,
        )
    } else if is_unsigned_word_operation(opcode) {
        (
            (b as u32).wrapping_div(c as u32) as i32 as i64 as u64,
            (b as u32).wrapping_rem(c as u32) as i32 as i64 as u64,
        )
    } else {
        (b.wrapping_div(c), b.wrapping_rem(c))
    }
}

/// Calculate the most significant bit of the given 64-bit integer `a`, and returns it as a u8.
#[must_use]
pub const fn get_msb(a: u64) -> u8 {
    ((a >> 63) & 1) as u8
}

/// Load the cost of each air from the predefined JSON.
#[must_use]
pub fn rv64im_costs() -> HashMap<RiscvAirId, usize> {
    let costs: HashMap<String, usize> =
        serde_json::from_str(include_str!("./artifacts/rv64im_costs.json")).unwrap();
    costs.into_iter().map(|(k, v)| (RiscvAirId::from_str(&k).unwrap(), v)).collect()
}

/// Calculate the largest multiple of 32 less than of equal to a given integer `n`.
#[must_use]
pub fn trunc_32(n: usize) -> usize {
    (n / 32) * 32
}

/// The maximum trace area and maximum height increment for a single event of a syscall.
#[must_use]
pub fn cost_and_height_per_syscall(
    syscall_code: SyscallCode,
    costs: &HashMap<RiscvAirId, usize>,
    page_protect: bool,
) -> (usize, usize) {
    let air_id = if page_protect {
        syscall_code.as_air_id_user().unwrap()
    } else {
        syscall_code.as_air_id().unwrap()
    };

    let rows_per_event = air_id.rows_per_event();
    let mut cost_per_syscall = 0;
    let mut max_height_per_syscall = rows_per_event;

    cost_per_syscall += rows_per_event * costs[&air_id];
    if rows_per_event > 1 {
        let control_air_id = air_id.control_air_id(page_protect).unwrap();
        cost_per_syscall += costs[&control_air_id];
    }

    let touched_addresses = syscall_code.touched_addresses();
    cost_per_syscall += touched_addresses * costs[&RiscvAirId::MemoryLocal];
    cost_per_syscall += 2 * touched_addresses * costs[&RiscvAirId::Global];
    cost_per_syscall += costs[&RiscvAirId::SyscallPrecompile];
    cost_per_syscall += costs[&RiscvAirId::Global];
    max_height_per_syscall = max_height_per_syscall.max(2 * touched_addresses + 1);

    if page_protect {
        let touched_pages = syscall_code.touched_pages();
        cost_per_syscall += touched_pages * costs[&RiscvAirId::PageProtLocal];
        cost_per_syscall += 2 * touched_pages * costs[&RiscvAirId::Global];
        max_height_per_syscall =
            max_height_per_syscall.max(2 * touched_addresses + 2 * touched_pages + 1);
    }

    (cost_per_syscall, max_height_per_syscall)
}

/// Add a halt syscall to the end of the instructions vec.
pub fn add_halt(instructions: &mut Vec<Instruction>) {
    instructions.push(Instruction::new(Opcode::ADD, Register::X5 as u8, 0, 0, false, false));
    instructions.push(Instruction::new(Opcode::ADD, Register::X10 as u8, 0, 0, false, false));
    instructions.push(Instruction::new(
        Opcode::ECALL,
        Register::X5 as u8,
        Register::X10 as u64,
        Register::X11 as u64,
        false,
        false,
    ));
}
