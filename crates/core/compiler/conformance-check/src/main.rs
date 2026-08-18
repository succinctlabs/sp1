//! Conformance of SP1's trace generation against the formally verified witness
//! generators exported from sp1-lean.
//!
//! For every core chip: run the real `MachineAir::generate_trace` over the
//! deterministic synthetic event battery, recover each event row's native inputs
//! from the trace row itself through the vendored symbolic row map, derive the
//! prover hints from the actual events, re-run the chip's exported witness
//! programs with the wire-format reference interpreter, and require:
//!
//!   * the reconstructed full row equals the prover's row **cell-for-cell**, and
//!   * every exported AIR constraint evaluates to zero on it.
//!
//! The vendored artifacts live in `testdata/lean-witgen/` (synced byte-identically
//! from sp1-lean's committed `export/witgen/` by its `vendor_witgen_artifacts.sh`;
//! `provenance.json` names the producing revisions). A red run means SP1's trace
//! generation drifted from the verified generators (the common case after a chip
//! change — re-sync or reconcile), stale artifacts, or a wire-format regression;
//! the failure message names the chip, row, and column.
//!
//! **Deliberately opt-in, with zero CI footprint.** This package is its own
//! workspace (not a member of SP1's), so no `cargo build` or
//! `cargo test --workspace` run in the SP1 tree ever builds or executes it — nor
//! the vendored `witgen-interp` it depends on. The check runs only when invoked
//! explicitly:
//!
//! ```text
//! cargo run --release \
//!     --manifest-path crates/core/compiler/conformance-check/Cargo.toml
//! ```
//!
//! (sp1-lean drives it with `scripts/run_sp1_conformance.sh`, which also shares
//! the workspace target dir so the dependency tree is built once). Promoting the
//! check into CI is a deliberate later step, once the artifact-sync story is
//! hardened; exit code 1 on any mismatch keeps it script- and CI-ready either way.
//!
//! A real-execution (`--elf`) variant is deliberate follow-up: the synthetic
//! batteries already cover every opcode family with populate-path invariants
//! intact, and `conformance::run_elf` covers all 25 chip families for ad-hoc
//! real-program dumps.

use serde_json::Value;
use sp1_constraint_compiler::conformance::{build_chip, generate_rows, CHIPS};
use sp1_core_executor::{ExecutionRecord, Opcode};
use witgen_interp::check::{check_row, derive_inputs, first_mismatch};
use witgen_interp::eval::Tables;
use witgen_interp::field::{Field, KoalaBear};
use witgen_interp::wire::{parse_program, parse_row_map};

type F = KoalaBear;

/// The six chips whose `is_real` input (native input cell 0) is not a bare column
/// of the Rust row; it is `1` on event rows and `0` on padding rows.
const IS_REAL_HINTED: &[&str] = &["Bitwise", "Branch", "Lt", "Mul", "ShiftLeft", "ShiftRight"];

/// The chips whose padding rows SP1 derives by running populate on a nonzero
/// template; all other chips zero-fill.
const DERIVED_PAD: &[&str] = &["ShiftLeft", "ShiftRight", "DivRem"];

fn read_json(name: &str) -> Value {
    let path = format!("{}/../testdata/lean-witgen/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e} (run sp1-lean's vendor_witgen_artifacts.sh)"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{path}: parse error: {e}"))
}

/// `(opcode, a, b)` of every event in battery order — the data the hint builders
/// need — plus, implicitly, the event count (rows beyond it are padding).
fn alu<R>(v: &[(sp1_core_executor::events::AluEvent, R)]) -> Vec<(Opcode, u64, u64)> {
    v.iter().map(|(e, _)| (e.opcode, e.a, e.b)).collect()
}

fn mem<R>(v: &[(sp1_core_executor::events::MemInstrEvent, R)]) -> Vec<(Opcode, u64, u64)> {
    v.iter().map(|(e, _)| (e.opcode, e.a, e.b)).collect()
}

fn jump<R>(v: &[(sp1_core_executor::events::JumpEvent, R)]) -> Vec<(Opcode, u64, u64)> {
    v.iter().map(|(e, _)| (e.opcode, e.a, e.b)).collect()
}

fn event_ops(chip: &str, record: &ExecutionRecord) -> Vec<(Opcode, u64, u64)> {
    match chip {
        "Add" => alu(&record.add_events),
        "Addi" => alu(&record.addi_events),
        "Addw" => alu(&record.addw_events),
        "Sub" => alu(&record.sub_events),
        "Subw" => alu(&record.subw_events),
        "Bitwise" => alu(&record.bitwise_events),
        "Lt" => alu(&record.lt_events),
        "ShiftLeft" => alu(&record.shift_left_events),
        "ShiftRight" => alu(&record.shift_right_events),
        "Mul" => alu(&record.mul_events),
        "DivRem" => alu(&record.divrem_events),
        "AluX0" => alu(&record.alu_x0_events),
        "Branch" => record.branch_events.iter().map(|(e, _)| (e.opcode, e.a, e.b)).collect(),
        "Jal" => jump(&record.jal_events),
        "Jalr" => jump(&record.jalr_events),
        "UType" => record.utype_events.iter().map(|(e, _)| (e.opcode, e.a, e.b)).collect(),
        "LoadByte" => mem(&record.memory_load_byte_events),
        "LoadHalf" => mem(&record.memory_load_half_events),
        "LoadWord" => mem(&record.memory_load_word_events),
        "LoadDouble" => mem(&record.memory_load_double_events),
        "LoadX0" => mem(&record.memory_load_x0_events),
        "StoreByte" => mem(&record.memory_store_byte_events),
        "StoreHalf" => mem(&record.memory_store_half_events),
        "StoreWord" => mem(&record.memory_store_word_events),
        "StoreDouble" => mem(&record.memory_store_double_events),
        other => panic!("no event accessor for chip {other}"),
    }
}

fn one_hot(table: &str, ops: &[Opcode], op: Opcode) -> Tables<F> {
    let row: Vec<F> = ops.iter().map(|&o| F::from_u64(u64::from(o == op))).collect();
    let mut t = Tables::default();
    t.map.insert((table.to_string(), row.len()), vec![row]);
    t
}

/// SP1's branch-taken derivation, mirroring `branch/trace.rs` exactly.
fn branch_taken(op: Opcode, a: u64, b: u64) -> bool {
    let a_eq_b = a == b;
    let signed = matches!(op, Opcode::BLT | Opcode::BGE);
    let a_lt_b = if signed { (a as i64) < (b as i64) } else { a < b };
    match op {
        Opcode::BEQ => a_eq_b,
        Opcode::BNE => !a_eq_b,
        Opcode::BLT | Opcode::BLTU => a_lt_b,
        Opcode::BGE | Opcode::BGEU => !a_lt_b,
        _ => unreachable!("branch_taken on non-branch opcode {op:?}"),
    }
}

/// The per-event hint tables, derived from the real event (the same tables the
/// exported payloads' `hintGet`s declare; every read is at row 0). Chips without
/// hint tables read the empty default. The DivRem one-hot deliberately omits DIVU:
/// the all-zero default *is* the `is_divu` template, exactly as on padding rows.
fn hints_for(chip: &str, op: Opcode, a: u64, b: u64) -> Tables<F> {
    use Opcode::*;
    match chip {
        "Mul" => one_hot("mul_flags", &[MUL, MULH, MULHU, MULHSU, MULW], op),
        "DivRem" => one_hot("div_rem_flags", &[DIV, REM, REMU, DIVW, REMW, DIVUW, REMUW], op),
        "Bitwise" => one_hot("bitwise_flags", &[XOR, OR, AND], op),
        "Lt" => one_hot("lt_flags", &[SLT, SLTU], op),
        "ShiftLeft" => one_hot("shift_left_flags", &[SLL, SLLW], op),
        "ShiftRight" => one_hot("shift_right_flags", &[SRL, SRA, SRLW, SRAW], op),
        "Branch" => {
            let mut t = one_hot("branch_flags", &[BEQ, BNE, BLT, BGE, BLTU, BGEU], op);
            let taken = F::from_u64(u64::from(branch_taken(op, a, b)));
            t.map.insert(("branch_branching".to_string(), 1), vec![vec![taken]]);
            t
        }
        _ => Tables::default(),
    }
}

/// Recover one trace row's inputs through the row map, re-run the exported
/// witness programs, and require full-row equality + constraints = 0.
#[allow(clippy::too_many_arguments)]
fn check_one(
    chip: &str,
    program: &witgen_interp::wire::Program,
    row_map: &witgen_interp::wire::RowMap,
    input_width: usize,
    is_real_hinted: bool,
    rows: &[Vec<u32>],
    row_i: usize,
    is_real: u64,
    hints: &Tables<F>,
    what: &str,
    failures: &mut Vec<String>,
) {
    let row: Vec<F> = rows[row_i].iter().map(|&v| F::from_u64(u64::from(v))).collect();
    let inputs =
        match derive_inputs(row_map, input_width, &row, is_real_hinted, F::from_u64(is_real)) {
            Ok(i) => i,
            Err(e) => {
                failures.push(format!("{chip} {what} {row_i}: {e}"));
                return;
            }
        };
    let rc = match check_row(program, row_map, &inputs, hints) {
        Ok(rc) => rc,
        Err(e) => {
            failures.push(format!("{chip} {what} {row_i}: {e}"));
            return;
        }
    };
    let got: Vec<u64> = rc.rust_row.iter().map(|x| x.val()).collect();
    let expected: Vec<u64> = rows[row_i].iter().map(|&v| u64::from(v)).collect();
    if let Some((col, g, e)) = first_mismatch(&got, &expected) {
        failures.push(format!(
            "{chip} {what} {row_i}: column {col} reconstructed {g}, prover wrote {e}"
        ));
    }
    for (op_i, v) in &rc.constraint_failures {
        failures
            .push(format!("{chip} {what} {row_i}: constraint operations[{op_i}] evaluates to {v}"));
    }
}

fn check_chip(chip: &str) -> Result<(), String> {
    // The live prover side: the deterministic battery through real generate_trace.
    let dump = build_chip(chip);
    let events = event_ops(chip, &dump.record);
    assert!(!events.is_empty(), "{chip}: empty battery");
    let (width, rows) = generate_rows(chip, &dump.record);
    assert!(rows.len() > events.len(), "{chip}: no padding row");

    // The verified side: the vendored artifacts.
    let payload = read_json(&format!("{chip}.witgen.json"));
    let program = parse_program(&payload).map_err(|e| format!("{chip}: {e}"))?;
    let row_map = parse_row_map(&read_json(&format!("{chip}.rowmap.json")))
        .map_err(|e| format!("{chip}: {e}"))?;
    let manifest = read_json(&format!("{chip}.manifest.json"));
    let input_width = manifest["inputWidth"].as_u64().unwrap() as usize;
    assert_eq!(
        manifest["field"]["modulus"].as_u64().unwrap(),
        F::MODULUS,
        "{chip}: field mismatch"
    );
    assert_eq!(
        manifest["localLength"].as_u64().unwrap() as usize,
        program.local_length,
        "{chip}: manifest localLength != payload"
    );
    assert_eq!(row_map.rust_width, width, "{chip}: row map width != trace width");

    let is_real_hinted = IS_REAL_HINTED.contains(&chip);
    let mut failures = Vec::new();

    // Every event row, gated cell-for-cell.
    for (row_i, &(op, a, b)) in events.iter().enumerate() {
        let hints = hints_for(chip, op, a, b);
        check_one(
            chip,
            &program,
            &row_map,
            input_width,
            is_real_hinted,
            &rows,
            row_i,
            1,
            &hints,
            "event row",
            &mut failures,
        );
    }

    // Padding: one repeated template row; derived-pad chips are gated like event
    // rows (empty hints, is_real = 0), zero-fill chips must have all-zero padding.
    let pad = &rows[events.len()];
    for (row_i, row) in rows.iter().enumerate().skip(events.len()) {
        if row != pad {
            failures.push(format!("{chip}: padding row {row_i} differs from the template"));
        }
    }
    if DERIVED_PAD.contains(&chip) {
        check_one(
            chip,
            &program,
            &row_map,
            input_width,
            is_real_hinted,
            &rows,
            events.len(),
            0,
            &Tables::default(),
            "padding row",
            &mut failures,
        );
    } else if pad.iter().any(|&v| v != 0) {
        failures.push(format!("{chip}: zero-fill padding row is not all-zero"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

#[allow(clippy::print_stdout)]
fn main() {
    let mut failures = Vec::new();
    for chip in CHIPS {
        match check_chip(chip) {
            Ok(()) => println!("{chip}: ok"),
            Err(e) => failures.push(e),
        }
    }
    if !failures.is_empty() {
        eprintln!("{}", failures.join("\n"));
        eprintln!("witgen conformance: FAILED");
        std::process::exit(1);
    }
    println!("witgen conformance: all {} chips reproduce generate_trace", CHIPS.len());
}
