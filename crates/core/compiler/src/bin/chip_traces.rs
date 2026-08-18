//! Deterministic per-chip trace dumps for external conformance testing.
//!
//! For every core RISC-V chip this binary constructs a deterministic battery of
//! executor events (or, with `--elf`, obtains real events by executing a guest
//! program), runs the chip's own `MachineAir::generate_trace`, and emits a
//! self-describing JSON dump: the events, the adapter records, and the full padded
//! trace matrix in canonical field values.
//!
//! Downstream verification tooling uses the dumps as its ground truth: a formal
//! model that claims to reproduce a chip's trace generation can be checked
//! cell-for-cell against the real prover's output without linking against it. The
//! output is deterministic byte-for-byte across runs: batteries are seeded by a
//! fixed LCG, no timestamps or environment data are embedded, and event order is
//! construction order.
//!
//! Synthetic batteries respect the populate-path invariants so every dumped row is
//! a valid trace row: `clk ≡ 1 (mod 8)` (the CPU-state encoding), register
//! previous/current timestamps within one 24-bit window (plus one deliberate
//! cross-window memory access per memory chip), memory addresses inside the
//! `[2^16, 2^48)` window the address operation requires, and exact RV64IM operand
//! semantics for every opcode (trace rows must satisfy the chip's own AIR).

use std::sync::Arc;

use clap::Parser;
use slop_algebra::PrimeField32;
use sp1_core_executor::events::{
    AluEvent, BranchEvent, JumpEvent, MemInstrEvent, MemoryReadRecord, MemoryRecordEnum,
    MemoryWriteRecord, UTypeEvent,
};
use sp1_core_executor::{
    ALUTypeRecord, ExecutionRecord, ITypeRecord, JTypeRecord, Opcode, Program, RTypeRecord,
    SP1CoreOpts,
};
use sp1_core_machine::io::SP1Stdin;
use sp1_core_machine::riscv::RiscvAir;
use sp1_core_machine::utils::generate_records;
use sp1_hypercube::air::{MachineAir, PROOF_NONCE_NUM_WORDS};
use sp1_primitives::SP1Field;

type F = SP1Field;

#[derive(Parser, Debug)]
#[command(
    about = "Dump deterministic per-chip traces (events + records + full padded rows) as JSON"
)]
struct Args {
    /// Dump a single chip's synthetic battery to stdout (or into --out).
    #[arg(long)]
    chip: Option<String>,
    /// Dump every supported chip's synthetic battery into --out.
    #[arg(long)]
    all: bool,
    /// List the supported chips and exit.
    #[arg(long)]
    list: bool,
    /// Execute a guest ELF and dump each chip's real-event trace into --out.
    #[arg(long)]
    elf: Option<String>,
    /// Cap the number of events per chip in --elf mode (deterministic prefix).
    #[arg(long, default_value_t = 64)]
    max_rows: usize,
    /// Output directory (required for --all and --elf).
    #[arg(long)]
    out: Option<String>,
}

/// The chips this dumper supports, in a stable order.
const CHIPS: &[&str] = &[
    "Add",
    "Addi",
    "Addw",
    "Sub",
    "Subw",
    "Bitwise",
    "Lt",
    "ShiftLeft",
    "ShiftRight",
    "Jal",
    "Jalr",
    "Branch",
    "UType",
    "LoadByte",
    "LoadHalf",
    "LoadWord",
    "LoadDouble",
    "LoadX0",
    "StoreByte",
    "StoreHalf",
    "StoreWord",
    "StoreDouble",
    "Mul",
    "DivRem",
    "AluX0",
];

// ---------------------------------------------------------------------------
// Deterministic value battery
// ---------------------------------------------------------------------------

/// Numerical-Recipes LCG; two steps are composed per output because an LCG's low
/// bits are weak. The fixed seed keeps regeneration churn-free.
struct Lcg(u64);

impl Lcg {
    const SEED: u64 = 0x5151_5151_2727_2727;

    fn new() -> Self {
        Lcg(Self::SEED)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = self.0;
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (hi & 0xFFFF_FFFF_0000_0000) | (self.0 >> 32)
    }
}

/// 12 hand-listed edge cases plus 32 LCG values.
fn u64_battery() -> Vec<u64> {
    let mut values = vec![
        0,
        1,
        0xFFFF,
        0x1_0000,
        0xFFFF_FFFF,
        u64::MAX,
        0x8000_0000_0000_0000,
        0x7FFF_FFFF_FFFF_FFFF,
        0xFFFF_FFFF_0000_0000,
        0x0000_0000_FFFF_FFFF,
        42,
        1234567890,
    ];
    let mut lcg = Lcg::new();
    values.extend((0..32).map(|_| lcg.next()));
    values
}

// ---------------------------------------------------------------------------
// Timing and register-slot conventions
// ---------------------------------------------------------------------------

/// Per-event timing: `clk ≡ 1 (mod 8)` (CPU-state encoding), strided pc, and the
/// previous access at the previous event's clk (all inside one 24-bit window).
fn timing(i: usize) -> (u64, u64, u64) {
    let clk = 9 + 8 * i as u64;
    let pc = 4096 + 4 * i as u64;
    let prev_ts = if i == 0 { 1 } else { clk - 8 };
    (clk, pc, prev_ts)
}

fn read_slot(value: u64, prev_ts: u64, ts: u64) -> MemoryRecordEnum {
    MemoryRecordEnum::Read(MemoryReadRecord {
        value,
        timestamp: ts,
        prev_timestamp: prev_ts,
        prev_page_prot_record: None,
    })
}

fn write_slot(prev_value: u64, value: u64, prev_ts: u64, ts: u64) -> MemoryRecordEnum {
    MemoryRecordEnum::Write(MemoryWriteRecord {
        prev_timestamp: prev_ts,
        prev_page_prot_record: None,
        prev_value,
        timestamp: ts,
        value,
    })
}

/// Slot timestamps within an event: A/B/C register accesses and the memory access,
/// mirroring the executor's access positions.
fn slot_ts(clk: u64) -> (u64, u64, u64, u64) {
    (clk + 4, clk + 3, clk + 2, clk + 1)
}

// ---------------------------------------------------------------------------
// Exact RV64IM operand semantics
// ---------------------------------------------------------------------------

fn sext32(x: u32) -> u64 {
    x as i32 as i64 as u64
}

/// The destination value of an ALU/M-extension instruction (exact RV64IM).
fn alu_result(op: Opcode, b: u64, c: u64) -> u64 {
    match op {
        Opcode::ADD | Opcode::ADDI => b.wrapping_add(c),
        Opcode::SUB => b.wrapping_sub(c),
        Opcode::XOR => b ^ c,
        Opcode::OR => b | c,
        Opcode::AND => b & c,
        Opcode::SLL => b.wrapping_shl((c & 63) as u32),
        Opcode::SRL => b.wrapping_shr((c & 63) as u32),
        Opcode::SRA => ((b as i64) >> (c & 63)) as u64,
        Opcode::SLT => ((b as i64) < (c as i64)) as u64,
        Opcode::SLTU => (b < c) as u64,
        Opcode::MUL => b.wrapping_mul(c),
        Opcode::MULH => (((b as i64 as i128).wrapping_mul(c as i64 as i128)) >> 64) as u64,
        Opcode::MULHU => (((b as u128).wrapping_mul(c as u128)) >> 64) as u64,
        Opcode::MULHSU => (((b as i64 as i128).wrapping_mul(c as i128)) >> 64) as u64,
        Opcode::DIV => {
            let (b, c) = (b as i64, c as i64);
            if c == 0 {
                u64::MAX
            } else {
                b.wrapping_div(c) as u64
            }
        }
        Opcode::DIVU => b.checked_div(c).unwrap_or(u64::MAX),
        Opcode::REM => {
            let (b, c) = (b as i64, c as i64);
            if c == 0 {
                b as u64
            } else {
                b.wrapping_rem(c) as u64
            }
        }
        Opcode::REMU => {
            if c == 0 {
                b
            } else {
                b % c
            }
        }
        Opcode::ADDW => sext32(b.wrapping_add(c) as u32),
        Opcode::SUBW => sext32(b.wrapping_sub(c) as u32),
        Opcode::SLLW => sext32((b as u32).wrapping_shl((c & 31) as u32)),
        Opcode::SRLW => sext32((b as u32).wrapping_shr((c & 31) as u32)),
        Opcode::SRAW => sext32((((b as u32) as i32) >> (c & 31)) as u32),
        Opcode::MULW => sext32(b.wrapping_mul(c) as u32),
        Opcode::DIVW => {
            let (b, c) = (b as u32 as i32, c as u32 as i32);
            if c == 0 {
                u64::MAX
            } else {
                sext32(b.wrapping_div(c) as u32)
            }
        }
        Opcode::DIVUW => {
            let (b, c) = (b as u32, c as u32);
            b.checked_div(c).map(sext32).unwrap_or(u64::MAX)
        }
        Opcode::REMW => {
            let (b, c) = (b as u32 as i32, c as u32 as i32);
            if c == 0 {
                sext32(b as u32)
            } else {
                sext32(b.wrapping_rem(c) as u32)
            }
        }
        Opcode::REMUW => {
            let (b, c) = (b as u32, c as u32);
            if c == 0 {
                sext32(b)
            } else {
                sext32(b % c)
            }
        }
        _ => panic!("alu_result: unsupported opcode {op:?}"),
    }
}

// ---------------------------------------------------------------------------
// Record builders (register indices 5/6/7 for rd/rs1/rs2 by convention)
// ---------------------------------------------------------------------------

fn rtype(i: usize, a: u64, b: u64, c: u64) -> RTypeRecord {
    let (clk, _, prev) = timing(i);
    let (ts_a, ts_b, ts_c, _) = slot_ts(clk);
    RTypeRecord {
        op_a: 5,
        a: write_slot(0, a, prev, ts_a),
        op_b: 6,
        b: read_slot(b, prev, ts_b),
        op_c: 7,
        c: read_slot(c, prev, ts_c),
        is_untrusted: false,
    }
}

/// Immediate-or-register third operand. `op_a_write = None` models a pure read of
/// the `a` slot (branches, stores); `Some((prev, value))` a write.
#[allow(clippy::too_many_arguments)]
fn itype(i: usize, op_a: u8, a_slot: MemoryRecordEnum, b: u64, imm: u64) -> ITypeRecord {
    let (clk, _, prev) = timing(i);
    let (_, ts_b, _, _) = slot_ts(clk);
    let _ = clk;
    ITypeRecord {
        op_a,
        a: a_slot,
        op_b: 6,
        b: read_slot(b, prev, ts_b),
        op_c: imm,
        is_untrusted: false,
    }
}

fn itype_write_a(i: usize, a: u64, b: u64, imm: u64) -> ITypeRecord {
    let (clk, _, prev) = timing(i);
    let (ts_a, _, _, _) = slot_ts(clk);
    itype(i, 5, write_slot(0, a, prev, ts_a), b, imm)
}

fn itype_read_a(i: usize, a: u64, b: u64, imm: u64) -> ITypeRecord {
    let (clk, _, prev) = timing(i);
    let (ts_a, _, _, _) = slot_ts(clk);
    itype(i, 5, read_slot(a, prev, ts_a), b, imm)
}

fn itype_x0(i: usize, b: u64, imm: u64) -> ITypeRecord {
    let (clk, _, prev) = timing(i);
    let (ts_a, _, _, _) = slot_ts(clk);
    itype(i, 0, write_slot(0, 0, prev, ts_a), b, imm)
}

fn jtype(i: usize, op_a: u8, a: u64, b_imm: u64, c_imm: u64) -> JTypeRecord {
    let (clk, _, prev) = timing(i);
    let (ts_a, _, _, _) = slot_ts(clk);
    JTypeRecord {
        op_a,
        a: write_slot(0, a, prev, ts_a),
        op_b: b_imm,
        op_c: c_imm,
        is_untrusted: false,
    }
}

fn alutype(i: usize, op_a: u8, a: u64, b: u64, c: u64, imm: bool) -> ALUTypeRecord {
    let (clk, _, prev) = timing(i);
    let (ts_a, ts_b, ts_c, _) = slot_ts(clk);
    ALUTypeRecord {
        op_a,
        a: write_slot(0, a, prev, ts_a),
        op_b: 6,
        b: read_slot(b, prev, ts_b),
        // On register rows `op_c` is the register index; on immediate rows it is
        // the immediate value itself.
        op_c: if imm { c } else { 7 },
        c: if imm { None } else { Some(read_slot(c, prev, ts_c)) },
        is_imm: imm,
        is_untrusted: false,
    }
}

// ---------------------------------------------------------------------------
// JSON serialization
// ---------------------------------------------------------------------------

fn mem_record_json(rec: &MemoryRecordEnum) -> serde_json::Value {
    match rec {
        MemoryRecordEnum::Read(r) => serde_json::json!({
            "kind": "read", "value": r.value,
            "timestamp": r.timestamp, "prevTimestamp": r.prev_timestamp,
        }),
        MemoryRecordEnum::Write(w) => serde_json::json!({
            "kind": "write", "value": w.value, "prevValue": w.prev_value,
            "timestamp": w.timestamp, "prevTimestamp": w.prev_timestamp,
        }),
    }
}

fn opcode_json(op: Opcode) -> serde_json::Value {
    serde_json::json!({ "name": format!("{op:?}"), "discriminant": op as u32 })
}

fn rtype_json(r: &RTypeRecord) -> serde_json::Value {
    serde_json::json!({
        "type": "RType", "opA": r.op_a, "opB": r.op_b, "opC": r.op_c,
        "isUntrusted": r.is_untrusted,
        "slots": { "a": mem_record_json(&r.a), "b": mem_record_json(&r.b),
                   "c": mem_record_json(&r.c) },
    })
}

fn itype_json(r: &ITypeRecord) -> serde_json::Value {
    serde_json::json!({
        "type": "IType", "opA": r.op_a, "opB": r.op_b, "opC": r.op_c,
        "isUntrusted": r.is_untrusted,
        "slots": { "a": mem_record_json(&r.a), "b": mem_record_json(&r.b) },
    })
}

fn jtype_json(r: &JTypeRecord) -> serde_json::Value {
    serde_json::json!({
        "type": "JType", "opA": r.op_a, "opB": r.op_b, "opC": r.op_c,
        "isUntrusted": r.is_untrusted,
        "slots": { "a": mem_record_json(&r.a) },
    })
}

fn alutype_json(r: &ALUTypeRecord) -> serde_json::Value {
    let mut slots = serde_json::Map::new();
    slots.insert("a".into(), mem_record_json(&r.a));
    slots.insert("b".into(), mem_record_json(&r.b));
    if let Some(c) = &r.c {
        slots.insert("c".into(), mem_record_json(c));
    }
    serde_json::json!({
        "type": "ALUType", "opA": r.op_a, "opB": r.op_b, "opC": r.op_c,
        "isImm": r.is_imm, "isUntrusted": r.is_untrusted, "slots": slots,
    })
}

fn alu_event_json(e: &AluEvent, record: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "clk": e.clk, "pc": e.pc, "opcode": opcode_json(e.opcode),
        "a": e.a, "b": e.b, "c": e.c, "opA0": e.op_a_0, "record": record,
    })
}

fn mem_event_json(e: &MemInstrEvent, record: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "clk": e.clk, "pc": e.pc, "opcode": opcode_json(e.opcode),
        "a": e.a, "b": e.b, "c": e.c, "opA0": e.op_a_0,
        "memAccess": mem_record_json(&e.mem_access), "record": record,
    })
}

// ---------------------------------------------------------------------------
// Synthetic batteries
// ---------------------------------------------------------------------------

struct ChipDump {
    record: ExecutionRecord,
    events_json: Vec<serde_json::Value>,
}

fn supervisor_program() -> Program {
    use sp1_core_executor::Instruction;
    let mut program =
        Program::new(vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, false)], 0, 0);
    program.enable_untrusted_programs = false;
    program
}

fn new_dump() -> ChipDump {
    let record = ExecutionRecord { program: Arc::new(supervisor_program()), ..Default::default() };
    ChipDump { record, events_json: Vec::new() }
}

/// One event per battery entry, paired with the entry seven positions ahead —
/// the pairing the original trace batteries used, so edge values meet shifted
/// edge values (0 with i64::MAX, MAX with sign boundaries, ...).
fn operand_pairs() -> Vec<(u64, u64)> {
    let battery = u64_battery();
    let n = battery.len();
    battery.iter().enumerate().map(|(i, &b)| (b, battery[(i + 7) % n])).collect()
}

fn build_rtype_alu(opcodes: &[Opcode]) -> Vec<(AluEvent, RTypeRecord)> {
    operand_pairs()
        .iter()
        .enumerate()
        .map(|(i, &(b, c))| {
            let op = opcodes[i % opcodes.len()];
            let (clk, pc, _) = timing(i);
            let a = alu_result(op, b, c);
            (AluEvent::new(clk, pc, op, a, b, c, false), rtype(i, a, b, c))
        })
        .collect()
}

fn build_alutype_alu(opcodes: &[Opcode]) -> Vec<(AluEvent, ALUTypeRecord)> {
    operand_pairs()
        .iter()
        .enumerate()
        .map(|(i, &(b, c))| {
            let op = opcodes[i % opcodes.len()];
            // Decouple the immediate cycle from the opcode cycle so every opcode
            // appears with both a register and an immediate third operand.
            let imm = (i / opcodes.len()) % 2 == 1;
            let (clk, pc, _) = timing(i);
            let a = alu_result(op, b, c);
            (AluEvent::new(clk, pc, op, a, b, c, false), alutype(i, 5, a, b, c, imm))
        })
        .collect()
}

/// DivRem gets the full edge battery: all 8 opcodes, division by zero for each,
/// and the signed-overflow patterns.
fn build_divrem() -> Vec<(AluEvent, RTypeRecord)> {
    let opcodes = [
        Opcode::DIV,
        Opcode::DIVU,
        Opcode::REM,
        Opcode::REMU,
        Opcode::DIVW,
        Opcode::DIVUW,
        Opcode::REMW,
        Opcode::REMUW,
    ];
    let mut events = Vec::new();
    let mut push = |op: Opcode, b: u64, c: u64| {
        let i = events.len();
        let (clk, pc, _) = timing(i);
        let a = alu_result(op, b, c);
        events.push((AluEvent::new(clk, pc, op, a, b, c, false), rtype(i, a, b, c)));
    };
    // Division by zero for every opcode.
    for op in opcodes {
        push(op, 9223372036854775807, 0);
    }
    // Signed overflow: MIN / -1 (64-bit and 32-bit patterns).
    push(Opcode::DIV, 0x8000_0000_0000_0000, u64::MAX);
    push(Opcode::REM, 0x8000_0000_0000_0000, u64::MAX);
    push(Opcode::DIVW, 0x8000_0000, 0xFFFF_FFFF);
    push(Opcode::REMW, 0x8000_0000, 0xFFFF_FFFF);
    // W-variants with nonzero high halves (the computational-value split).
    push(Opcode::DIVW, 0xFFFF_FFFF_0000_0005, 0x1_0000_0003);
    push(Opcode::DIVUW, 0xAAAA_BBBB_0000_0064, 0x7);
    push(Opcode::REMW, 0x1234_5678_FFFF_FFF6, 0x5);
    push(Opcode::REMUW, 0xFFFF_FFFF_FFFF_FFFF, 0x10);
    // The general battery on the remaining slots.
    for (j, &(b, c)) in operand_pairs().iter().take(28).enumerate() {
        push(opcodes[j % 8], b, c);
    }
    events
}

fn build_alu_x0() -> Vec<(AluEvent, ALUTypeRecord)> {
    let ops = [
        Opcode::ADD,
        Opcode::SUB,
        Opcode::XOR,
        Opcode::MUL,
        Opcode::DIVU,
        Opcode::SLL,
        Opcode::SLT,
        Opcode::ADDW,
    ];
    operand_pairs()
        .iter()
        .take(16)
        .enumerate()
        .map(|(i, &(b, c))| {
            let op = ops[i % ops.len()];
            let imm = i % 2 == 1;
            let (clk, pc, _) = timing(i);
            // rd = x0: the architectural result is discarded and reads as zero.
            let mut rec = alutype(i, 0, 0, b, c, imm);
            rec.op_a = 0;
            (AluEvent::new(clk, pc, op, 0, b, c, true), rec)
        })
        .collect()
}

/// Base addresses inside `[2^16, 2^48)`, 8-aligned, plus the addressed
/// double-word content.
fn mem_battery(n: usize) -> Vec<(u64, u64)> {
    let mut lcg = Lcg::new();
    (0..n)
        .map(|k| {
            let base = 0x1_0000 + 0x100 * k as u64 + (lcg.next() % 0x1_0000_0000) * 0x1000;
            let base = base % 0x0000_FFFF_FFFF_0000 + 0x1_0000;
            (base & !7, lcg.next())
        })
        .collect()
}

fn extract_load(op: Opcode, word: u64, offset: u64) -> u64 {
    let bytes = word.to_le_bytes();
    match op {
        Opcode::LB => bytes[offset as usize] as i8 as i64 as u64,
        Opcode::LBU => bytes[offset as usize] as u64,
        Opcode::LH => u16::from_le_bytes([bytes[offset as usize], bytes[offset as usize + 1]])
            as i16 as i64 as u64,
        Opcode::LHU => {
            u16::from_le_bytes([bytes[offset as usize], bytes[offset as usize + 1]]) as u64
        }
        Opcode::LW => sext32((word >> (8 * offset)) as u32),
        Opcode::LWU => ((word >> (8 * offset)) as u32) as u64,
        Opcode::LD => word,
        _ => panic!("extract_load: {op:?}"),
    }
}

fn store_merge(op: Opcode, prev_word: u64, offset: u64, src: u64) -> u64 {
    let width_bytes = match op {
        Opcode::SB => 1,
        Opcode::SH => 2,
        Opcode::SW => 4,
        Opcode::SD => 8,
        _ => panic!("store_merge: {op:?}"),
    };
    if width_bytes == 8 {
        return src;
    }
    let mask = ((1u128 << (8 * width_bytes)) - 1) as u64;
    let shift = 8 * offset;
    (prev_word & !(mask << shift)) | ((src & mask) << shift)
}

struct MemSpec {
    opcodes: &'static [Opcode],
    offsets: &'static [u64],
    store: bool,
    x0: bool,
}

fn build_mem(spec: &MemSpec) -> Vec<(MemInstrEvent, ITypeRecord)> {
    let mut events = Vec::new();
    let bases = mem_battery(48);
    let mut idx = 0;
    for &op in spec.opcodes {
        for &offset in spec.offsets {
            for _rep in 0..3 {
                let i = events.len();
                let (clk, pc, prev) = timing(i);
                let (_, _, _, ts_mem) = slot_ts(clk);
                let (base, word) = bases[idx % bases.len()];
                idx += 1;
                // Split the address into a register base and an immediate so that
                // b + c lands exactly on the aligned address plus the offset.
                let addr = base + offset;
                let imm = 8 + offset;
                let b = addr - imm;
                let (a, mem_access) = if spec.store {
                    let src = word.rotate_left(13);
                    let merged = store_merge(op, word, offset, src);
                    (src, write_slot(word, merged, prev, ts_mem))
                } else {
                    (extract_load(op, word, offset), read_slot(word, prev, ts_mem))
                };
                let a = if spec.x0 { 0 } else { a };
                let record = if spec.store {
                    itype_read_a(i, a, b, imm)
                } else if spec.x0 {
                    itype_x0(i, b, imm)
                } else {
                    itype_write_a(i, a, b, imm)
                };
                events.push((
                    MemInstrEvent {
                        clk,
                        pc,
                        opcode: op,
                        a,
                        b,
                        c: imm,
                        op_a_0: spec.x0,
                        mem_access,
                    },
                    record,
                ));
            }
        }
    }
    // One deliberate cross-window memory access: the memory slot's previous
    // timestamp sits in an earlier 24-bit window than the access.
    {
        let i = events.len();
        let clk = (1u64 << 24) + 9;
        let pc = 4096 + 4 * i as u64;
        let prev_reg = clk - 8;
        let (ts_a, ts_b, _, ts_mem) = slot_ts(clk);
        let op = spec.opcodes[0];
        let (base, word) = bases[0];
        let imm = 8;
        let b = base - imm;
        let (a, mem_access) = if spec.store {
            let src = word.rotate_left(29);
            (src, write_slot(word, store_merge(op, word, 0, src), 5, ts_mem))
        } else {
            (extract_load(op, word, 0), read_slot(word, 5, ts_mem))
        };
        let a = if spec.x0 { 0 } else { a };
        let a_slot = if spec.store {
            read_slot(a, prev_reg, ts_a)
        } else {
            write_slot(0, if spec.x0 { 0 } else { a }, prev_reg, ts_a)
        };
        let record = ITypeRecord {
            op_a: if spec.x0 { 0 } else { 5 },
            a: a_slot,
            op_b: 6,
            b: read_slot(b, prev_reg, ts_b),
            op_c: imm,
            is_untrusted: false,
        };
        events.push((
            MemInstrEvent { clk, pc, opcode: op, a, b, c: imm, op_a_0: spec.x0, mem_access },
            record,
        ));
    }
    events
}

fn build_branch() -> Vec<(BranchEvent, ITypeRecord)> {
    let opcodes = [Opcode::BEQ, Opcode::BNE, Opcode::BLT, Opcode::BGE, Opcode::BLTU, Opcode::BGEU];
    let operand_sets: &[(u64, u64)] = &[
        (5, 5),
        (5, 9),
        (u64::MAX, 1),              // signed -1 vs 1
        (0x8000_0000_0000_0000, 7), // signed MIN vs positive
        (1, u64::MAX),
        (0xFFFF_FFFF_FFFF_FFF0, 0xFFFF_FFFF_FFFF_FFF0),
    ];
    let mut events = Vec::new();
    for &op in &opcodes {
        for (j, &(a, b)) in operand_sets.iter().enumerate() {
            let i = events.len();
            let (clk, pc, prev) = timing(i);
            let (ts_a, ts_b, _, _) = slot_ts(clk);
            // Offsets: forward, plus one wrapping-negative per opcode.
            let c: u64 = if j == 2 { (-16i64) as u64 } else { 16 + 4 * j as u64 };
            let branching = match op {
                Opcode::BEQ => a == b,
                Opcode::BNE => a != b,
                Opcode::BLT => (a as i64) < (b as i64),
                Opcode::BGE => (a as i64) >= (b as i64),
                Opcode::BLTU => a < b,
                Opcode::BGEU => a >= b,
                _ => unreachable!(),
            };
            let next_pc = if branching { pc.wrapping_add(c) } else { pc + 4 };
            let record = ITypeRecord {
                op_a: 5,
                a: read_slot(a, prev, ts_a),
                op_b: 6,
                b: read_slot(b, prev, ts_b),
                op_c: c,
                is_untrusted: false,
            };
            events.push((
                BranchEvent { clk, pc, next_pc, opcode: op, a, b, c, op_a_0: false },
                record,
            ));
        }
    }
    events
}

fn build_jal() -> Vec<(JumpEvent, JTypeRecord)> {
    let offsets: &[u64] = &[8, 64, 4096, (-8i64) as u64, 1 << 20];
    offsets
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let (clk, pc, _) = timing(i);
            let op_a_0 = i == offsets.len() - 1;
            let a = if op_a_0 { 0 } else { pc + 4 };
            let op_a = if op_a_0 { 0 } else { 5 };
            let next_pc = pc.wrapping_add(b);
            (
                JumpEvent { clk, pc, next_pc, opcode: Opcode::JAL, a, b, c: 0, op_a_0 },
                jtype(i, op_a, a, b, 0),
            )
        })
        .collect()
}

fn build_jalr() -> Vec<(JumpEvent, ITypeRecord)> {
    let cases: &[(u64, u64)] = &[
        (0x1_0000, 16),
        (0x2_0000, 4),
        (0x4_0000, (-4i64) as u64),
        (0x1_0004, 1), // odd sum: exercises the genuine lsb clear
        (0x8_0000, 0),
    ];
    cases
        .iter()
        .enumerate()
        .map(|(i, &(b, imm))| {
            let (clk, pc, prev) = timing(i);
            let (ts_a, _, _, _) = slot_ts(clk);
            let op_a_0 = i == cases.len() - 1;
            let a = if op_a_0 { 0 } else { pc + 4 };
            let next_pc = b.wrapping_add(imm) & !1;
            let record = ITypeRecord {
                op_a: if op_a_0 { 0 } else { 5 },
                a: write_slot(0, a, prev, ts_a),
                op_b: 6,
                b: read_slot(b, prev, timing(i).0 + 3),
                op_c: imm,
                is_untrusted: false,
            };
            (JumpEvent { clk, pc, next_pc, opcode: Opcode::JALR, a, b, c: imm, op_a_0 }, record)
        })
        .collect()
}

fn build_utype() -> Vec<(UTypeEvent, JTypeRecord)> {
    let imms: &[u64] = &[0x1000, 0xFFFF_F000, 0x7FFF_F000, 1 << 30];
    let mut events = Vec::new();
    for &op in &[Opcode::LUI, Opcode::AUIPC] {
        for (j, &b) in imms.iter().enumerate() {
            let i = events.len();
            let (clk, pc, _) = timing(i);
            // One rd = x0 event per opcode.
            let op_a_0 = j == imms.len() - 1;
            let value = match op {
                Opcode::LUI => b,
                Opcode::AUIPC => pc.wrapping_add(b),
                _ => unreachable!(),
            };
            let a = if op_a_0 { 0 } else { value };
            let op_a = if op_a_0 { 0 } else { 5 };
            events.push((
                UTypeEvent { clk, pc, opcode: op, a, b, c: 0, op_a_0 },
                jtype(i, op_a, a, b, 0),
            ));
        }
    }
    events
}

// ---------------------------------------------------------------------------
// Chip dispatch
// ---------------------------------------------------------------------------

fn build_chip(chip: &str) -> ChipDump {
    let mut dump = new_dump();
    match chip {
        "Add" => {
            let events = build_rtype_alu(&[Opcode::ADD]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, rtype_json(r))).collect();
            dump.record.add_events = events;
        }
        "Sub" => {
            let events = build_rtype_alu(&[Opcode::SUB]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, rtype_json(r))).collect();
            dump.record.sub_events = events;
        }
        "Subw" => {
            let events = build_rtype_alu(&[Opcode::SUBW]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, rtype_json(r))).collect();
            dump.record.subw_events = events;
        }
        "Mul" => {
            let events = build_rtype_alu(&[
                Opcode::MUL,
                Opcode::MULH,
                Opcode::MULHU,
                Opcode::MULHSU,
                Opcode::MULW,
            ]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, rtype_json(r))).collect();
            dump.record.mul_events = events;
        }
        "DivRem" => {
            let events = build_divrem();
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, rtype_json(r))).collect();
            dump.record.divrem_events = events;
        }
        "Addi" => {
            let events: Vec<(AluEvent, ITypeRecord)> = operand_pairs()
                .iter()
                .enumerate()
                .map(|(i, &(b, c))| {
                    let (clk, pc, _) = timing(i);
                    let a = b.wrapping_add(c);
                    (
                        AluEvent::new(clk, pc, Opcode::ADDI, a, b, c, false),
                        itype_write_a(i, a, b, c),
                    )
                })
                .collect();
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, itype_json(r))).collect();
            dump.record.addi_events = events;
        }
        "Addw" => {
            let events = build_alutype_alu(&[Opcode::ADDW]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, alutype_json(r))).collect();
            dump.record.addw_events = events;
        }
        "Bitwise" => {
            let events = build_alutype_alu(&[Opcode::XOR, Opcode::OR, Opcode::AND]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, alutype_json(r))).collect();
            dump.record.bitwise_events = events;
        }
        "Lt" => {
            let events = build_alutype_alu(&[Opcode::SLT, Opcode::SLTU]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, alutype_json(r))).collect();
            dump.record.lt_events = events;
        }
        "ShiftLeft" => {
            let events = build_alutype_alu(&[Opcode::SLL, Opcode::SLLW]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, alutype_json(r))).collect();
            dump.record.shift_left_events = events;
        }
        "ShiftRight" => {
            let events = build_alutype_alu(&[Opcode::SRL, Opcode::SRA, Opcode::SRLW, Opcode::SRAW]);
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, alutype_json(r))).collect();
            dump.record.shift_right_events = events;
        }
        "AluX0" => {
            let events = build_alu_x0();
            dump.events_json =
                events.iter().map(|(e, r)| alu_event_json(e, alutype_json(r))).collect();
            dump.record.alu_x0_events = events;
        }
        "Branch" => {
            let events = build_branch();
            dump.events_json = events
                .iter()
                .map(|(e, r)| {
                    serde_json::json!({
                        "clk": e.clk, "pc": e.pc, "nextPc": e.next_pc,
                        "opcode": opcode_json(e.opcode),
                        "a": e.a, "b": e.b, "c": e.c, "opA0": e.op_a_0,
                        "record": itype_json(r),
                    })
                })
                .collect();
            dump.record.branch_events = events;
        }
        "Jal" => {
            let events = build_jal();
            dump.events_json = events
                .iter()
                .map(|(e, r)| {
                    serde_json::json!({
                        "clk": e.clk, "pc": e.pc, "nextPc": e.next_pc,
                        "opcode": opcode_json(e.opcode),
                        "a": e.a, "b": e.b, "c": e.c, "opA0": e.op_a_0,
                        "record": jtype_json(r),
                    })
                })
                .collect();
            dump.record.jal_events = events;
        }
        "Jalr" => {
            let events = build_jalr();
            dump.events_json = events
                .iter()
                .map(|(e, r)| {
                    serde_json::json!({
                        "clk": e.clk, "pc": e.pc, "nextPc": e.next_pc,
                        "opcode": opcode_json(e.opcode),
                        "a": e.a, "b": e.b, "c": e.c, "opA0": e.op_a_0,
                        "record": itype_json(r),
                    })
                })
                .collect();
            dump.record.jalr_events = events;
        }
        "UType" => {
            let events = build_utype();
            dump.events_json = events
                .iter()
                .map(|(e, r)| {
                    serde_json::json!({
                        "clk": e.clk, "pc": e.pc, "opcode": opcode_json(e.opcode),
                        "a": e.a, "b": e.b, "c": e.c, "opA0": e.op_a_0,
                        "record": jtype_json(r),
                    })
                })
                .collect();
            dump.record.utype_events = events;
        }
        "LoadByte" => {
            let spec = MemSpec {
                opcodes: &[Opcode::LB, Opcode::LBU],
                offsets: &[0, 1, 2, 3, 4, 5, 6, 7],
                store: false,
                x0: false,
            };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_load_byte_events = events;
        }
        "LoadHalf" => {
            let spec = MemSpec {
                opcodes: &[Opcode::LH, Opcode::LHU],
                offsets: &[0, 2, 4, 6],
                store: false,
                x0: false,
            };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_load_half_events = events;
        }
        "LoadWord" => {
            let spec = MemSpec {
                opcodes: &[Opcode::LW, Opcode::LWU],
                offsets: &[0, 4],
                store: false,
                x0: false,
            };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_load_word_events = events;
        }
        "LoadDouble" => {
            let spec = MemSpec { opcodes: &[Opcode::LD], offsets: &[0], store: false, x0: false };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_load_double_events = events;
        }
        "LoadX0" => {
            let spec = MemSpec {
                opcodes: &[Opcode::LW, Opcode::LB, Opcode::LD, Opcode::LHU],
                offsets: &[0],
                store: false,
                x0: true,
            };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_load_x0_events = events;
        }
        "StoreByte" => {
            let spec = MemSpec {
                opcodes: &[Opcode::SB],
                offsets: &[0, 1, 2, 3, 4, 5, 6, 7],
                store: true,
                x0: false,
            };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_store_byte_events = events;
        }
        "StoreHalf" => {
            let spec =
                MemSpec { opcodes: &[Opcode::SH], offsets: &[0, 2, 4, 6], store: true, x0: false };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_store_half_events = events;
        }
        "StoreWord" => {
            let spec = MemSpec { opcodes: &[Opcode::SW], offsets: &[0, 4], store: true, x0: false };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_store_word_events = events;
        }
        "StoreDouble" => {
            let spec = MemSpec { opcodes: &[Opcode::SD], offsets: &[0], store: true, x0: false };
            let events = build_mem(&spec);
            dump.events_json =
                events.iter().map(|(e, r)| mem_event_json(e, itype_json(r))).collect();
            dump.record.memory_store_double_events = events;
        }
        other => {
            eprintln!("Error: chip '{other}' not supported. Supported chips:");
            for c in CHIPS {
                eprintln!("  {c}");
            }
            std::process::exit(1);
        }
    }
    dump
}

// ---------------------------------------------------------------------------
// Trace generation and emission
// ---------------------------------------------------------------------------

fn dump_json(
    chip_name: &str,
    mode: &str,
    record: &ExecutionRecord,
    events_json: Vec<serde_json::Value>,
) -> serde_json::Value {
    let machine = RiscvAir::<F>::machine();
    let chip =
        machine.chips().iter().find(|c| c.name() == chip_name).cloned().unwrap_or_else(|| {
            eprintln!("Error: chip '{chip_name}' not found in the machine");
            std::process::exit(1);
        });
    let trace = chip.generate_trace(record, &mut ExecutionRecord::default());
    let width = trace.width;
    let values = &trace.values;
    assert!(values.len() % width == 0, "{chip_name}: ragged trace");
    let height = values.len() / width;
    assert!(
        height >= events_json.len(),
        "{chip_name}: trace height {height} below event count {}",
        events_json.len()
    );
    let rows: Vec<Vec<u32>> = (0..height)
        .map(|r| values[r * width..(r + 1) * width].iter().map(F::as_canonical_u32).collect())
        .collect();
    serde_json::json!({
        "schemaVersion": 1,
        "chip": chip_name,
        "mode": mode,
        "width": width,
        "height": height,
        "events": events_json,
        "rows": rows,
    })
}

#[allow(clippy::print_stdout)]
fn emit(out: &Option<String>, chip: &str, value: &serde_json::Value) {
    let text = format!("{}\n", serde_json::to_string_pretty(value).unwrap());
    match out {
        Some(dir) => {
            std::fs::create_dir_all(dir).unwrap();
            let path = format!("{dir}/{chip}.dump.json");
            std::fs::write(&path, text).unwrap();
            eprintln!("{chip}: wrote {path}");
        }
        None => println!("{text}"),
    }
}

fn run_synthetic(chip: &str, out: &Option<String>) {
    let dump = build_chip(chip);
    let value = dump_json(chip, "synthetic", &dump.record, dump.events_json);
    emit(out, chip, &value);
}

/// Execute a guest ELF and dump each chip's real-event trace. Events across shards
/// are concatenated per chip and truncated to a deterministic prefix.
fn run_elf(path: &str, max_rows: usize, out: &Option<String>) {
    let program = Program::from_elf(path).unwrap_or_else(|e| {
        eprintln!("Error: failed to load ELF {path}: {e}");
        std::process::exit(1);
    });
    let (records, _cycles) = generate_records::<F>(
        Arc::new(program),
        SP1Stdin::new(),
        SP1CoreOpts::default(),
        [0u32; PROOF_NONCE_NUM_WORDS],
    )
    .unwrap_or_else(|e| {
        eprintln!("Error: execution failed: {e:?}");
        std::process::exit(1);
    });

    macro_rules! collect {
        ($name:literal, $field:ident, $json:expr) => {{
            let mut merged = new_dump();
            for r in &records {
                merged.record.$field.extend(r.$field.iter().cloned());
            }
            merged.record.$field.truncate(max_rows);
            if !merged.record.$field.is_empty() {
                merged.events_json = merged.record.$field.iter().map($json).collect();
                let value = dump_json($name, "elf", &merged.record, merged.events_json);
                emit(out, $name, &value);
            } else {
                eprintln!("{}: no events in this program, skipped", $name);
            }
        }};
    }

    collect!("Add", add_events, |(e, r)| alu_event_json(e, rtype_json(r)));
    collect!("Addi", addi_events, |(e, r)| alu_event_json(e, itype_json(r)));
    collect!("Addw", addw_events, |(e, r)| alu_event_json(e, alutype_json(r)));
    collect!("Sub", sub_events, |(e, r)| alu_event_json(e, rtype_json(r)));
    collect!("Subw", subw_events, |(e, r)| alu_event_json(e, rtype_json(r)));
    collect!("Bitwise", bitwise_events, |(e, r)| alu_event_json(e, alutype_json(r)));
    collect!("Lt", lt_events, |(e, r)| alu_event_json(e, alutype_json(r)));
    collect!("ShiftLeft", shift_left_events, |(e, r)| alu_event_json(e, alutype_json(r)));
    collect!("ShiftRight", shift_right_events, |(e, r)| alu_event_json(e, alutype_json(r)));
    collect!("Mul", mul_events, |(e, r)| alu_event_json(e, rtype_json(r)));
    collect!("DivRem", divrem_events, |(e, r)| alu_event_json(e, rtype_json(r)));
    collect!("AluX0", alu_x0_events, |(e, r)| alu_event_json(e, alutype_json(r)));
    collect!("LoadByte", memory_load_byte_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("LoadHalf", memory_load_half_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("LoadWord", memory_load_word_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("LoadDouble", memory_load_double_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("LoadX0", memory_load_x0_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("StoreByte", memory_store_byte_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("StoreHalf", memory_store_half_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("StoreWord", memory_store_word_events, |(e, r)| mem_event_json(e, itype_json(r)));
    collect!("StoreDouble", memory_store_double_events, |(e, r)| mem_event_json(e, itype_json(r)));
}

#[allow(clippy::print_stdout)]
fn main() {
    let args = Args::parse();
    if args.list {
        for c in CHIPS {
            println!("{c}");
        }
        return;
    }
    if let Some(path) = &args.elf {
        if args.out.is_none() {
            eprintln!("Error: --elf requires --out");
            std::process::exit(2);
        }
        run_elf(path, args.max_rows, &args.out);
        return;
    }
    if args.all {
        if args.out.is_none() {
            eprintln!("Error: --all requires --out");
            std::process::exit(2);
        }
        for chip in CHIPS {
            run_synthetic(chip, &args.out);
        }
        return;
    }
    if let Some(chip) = &args.chip {
        run_synthetic(chip, &args.out);
        return;
    }
    eprintln!("Error: one of --chip, --all, --elf, or --list is required");
    std::process::exit(2);
}
