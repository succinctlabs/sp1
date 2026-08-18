//! The differential runner: parse a chip's payload + manifest + fixture, run every
//! fixture row through the evaluator, and compare cell-by-cell against
//! `expectedWitness`. Mismatch reports name the chip, row, cell, and the witness
//! operation that produced the cell.

use crate::check::check_row;
use crate::eval::{OpSpan, Tables};
use crate::field::Field;
use crate::wire::{parse_program, parse_row_map, Op, Program, RowMap};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub struct ChipReport {
    pub chip: String,
    pub rows: usize,
    /// Rows carrying `anchored: true` (SP1-derived), on which constraints were checked.
    pub anchored_rows: usize,
    /// Rows whose full Rust row (`expectedRow`) was reconstructed and compared.
    pub row_checked: usize,
    /// `assert` operations in the payload (each checked = 0 on every anchored row).
    pub constraint_ops: usize,
    /// Total interaction sends (nonzero multiplicity) per channel over anchored rows.
    pub interaction_sends: BTreeMap<String, u64>,
    pub failures: Vec<String>,
}

/// Public JSON reader for sibling modules (the bench path).
pub fn read_json_pub(path: &Path) -> Result<Value, String> {
    read_json(path)
}

/// One pre-parsed fixture row: `(inputs, hints)`.
pub type FixtureRow<F> = (Vec<F>, Tables<F>);

/// The pre-parsed `(inputs, hints)` of every fixture row (the bench path).
pub fn fixture_rows<F: Field>(export_dir: &Path, chip: &str) -> Result<Vec<FixtureRow<F>>, String> {
    let fixture = read_json(
        &export_dir
            .join("testdata")
            .join(format!("{chip}.trace.json")),
    )?;
    let rows = fixture
        .get("rows")
        .and_then(|r| r.as_array())
        .ok_or_else(|| format!("{chip}.trace.json: missing rows"))?;
    let mut out = Vec::with_capacity(rows.len());
    for (row_i, row) in rows.iter().enumerate() {
        let r = row
            .as_object()
            .ok_or_else(|| format!("{chip} row {row_i}: expected object"))?;
        let inputs: Vec<F> = parse_values(
            r.get("inputs")
                .ok_or_else(|| format!("{chip} row {row_i}: missing inputs"))?,
            &format!("{chip} row {row_i} inputs"),
        )?;
        let hints: Tables<F> = parse_hints(
            r.get("hints")
                .ok_or_else(|| format!("{chip} row {row_i}: missing hints"))?,
            &format!("{chip} row {row_i} hints"),
        )?;
        out.push((inputs, hints));
    }
    Ok(out)
}

fn read_json(path: &Path) -> Result<Value, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("{}: parse error: {e}", path.display()))
}

fn num_field(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64()
        .ok_or_else(|| format!("{what}: expected unsigned integer"))
}

fn parse_values<F: Field>(v: &Value, what: &str) -> Result<Vec<F>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| format!("{what}: expected array"))?;
    arr.iter()
        .enumerate()
        .map(|(i, x)| Ok(F::from_u64(num_field(x, &format!("{what}[{i}]"))?)))
        .collect()
}

fn parse_hints<F: Field>(v: &Value, what: &str) -> Result<Tables<F>, String> {
    let mut tables = Tables::default();
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{what}: expected object"))?;
    for (name, entry) in obj {
        let e = entry
            .as_object()
            .ok_or_else(|| format!("{what}.{name}: expected object"))?;
        let width = num_field(
            e.get("width")
                .ok_or_else(|| format!("{what}.{name}: missing width"))?,
            &format!("{what}.{name}.width"),
        )? as usize;
        let rows_v = e
            .get("rows")
            .and_then(|r| r.as_array())
            .ok_or_else(|| format!("{what}.{name}: missing rows array"))?;
        let mut rows = Vec::with_capacity(rows_v.len());
        for (i, row) in rows_v.iter().enumerate() {
            let cells: Vec<F> = parse_values(row, &format!("{what}.{name}.rows[{i}]"))?;
            if cells.len() != width {
                return Err(format!("{what}.{name}.rows[{i}]: width mismatch"));
            }
            rows.push(cells);
        }
        tables.map.insert((name.clone(), width), rows);
    }
    Ok(tables)
}

fn span_of(spans: &[OpSpan], local_cell: usize) -> Option<&OpSpan> {
    spans
        .iter()
        .find(|s| local_cell >= s.start && local_cell < s.start + s.len)
}

/// Run one chip's fixture. `export_dir` holds `witgen/` and `testdata/`.
pub fn run_chip<F: Field>(
    export_dir: &Path,
    chip: &str,
    verbose: bool,
) -> Result<ChipReport, String> {
    let payload = read_json(
        &export_dir
            .join("witgen")
            .join(format!("{chip}.witgen.json")),
    )?;
    let program: Program = parse_program(&payload)?;
    let row_map: RowMap = parse_row_map(&read_json(
        &export_dir
            .join("witgen")
            .join(format!("{chip}.rowmap.json")),
    )?)?;
    let constraint_ops = program
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Assert(_)))
        .count();
    let fixture = read_json(
        &export_dir
            .join("testdata")
            .join(format!("{chip}.trace.json")),
    )?;
    let f = fixture
        .as_object()
        .ok_or_else(|| format!("{chip}.trace.json: expected object"))?;

    let modulus = f
        .get("field")
        .and_then(|x| x.get("modulus"))
        .and_then(|x| x.as_u64())
        .ok_or_else(|| format!("{chip}.trace.json: missing field.modulus"))?;
    if modulus != F::MODULUS {
        return Err(format!(
            "{chip}: fixture field modulus {modulus} != interpreter field {}",
            F::MODULUS
        ));
    }
    let input_width = num_field(
        f.get("inputWidth").ok_or("missing inputWidth")?,
        "inputWidth",
    )? as usize;
    let local_length = num_field(
        f.get("localLength").ok_or("missing localLength")?,
        "localLength",
    )? as usize;
    if local_length != program.local_length {
        return Err(format!(
            "{chip}: fixture localLength {local_length} != payload {}",
            program.local_length
        ));
    }

    let rows = f
        .get("rows")
        .and_then(|r| r.as_array())
        .ok_or_else(|| format!("{chip}.trace.json: missing rows"))?;

    let mut failures = Vec::new();
    let mut anchored_rows = 0usize;
    let mut row_checked = 0usize;
    let mut interaction_sends: BTreeMap<String, u64> = BTreeMap::new();
    for (row_i, row) in rows.iter().enumerate() {
        let r = row
            .as_object()
            .ok_or_else(|| format!("{chip} row {row_i}: expected object"))?;
        let kind = r.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
        let inputs: Vec<F> = parse_values(
            r.get("inputs")
                .ok_or_else(|| format!("{chip} row {row_i}: missing inputs"))?,
            &format!("{chip} row {row_i} inputs"),
        )?;
        if inputs.len() != input_width {
            failures.push(format!(
                "{chip} row {row_i} ({kind}): inputs length mismatch"
            ));
            continue;
        }
        let hints: Tables<F> = parse_hints(
            r.get("hints")
                .ok_or_else(|| format!("{chip} row {row_i}: missing hints"))?,
            &format!("{chip} row {row_i} hints"),
        )?;
        let expected: Vec<u64> = r
            .get("expectedWitness")
            .and_then(|e| e.as_array())
            .ok_or_else(|| format!("{chip} row {row_i}: missing expectedWitness"))?
            .iter()
            .enumerate()
            .map(|(i, x)| num_field(x, &format!("{chip} row {row_i} expectedWitness[{i}]")))
            .collect::<Result<_, _>>()?;

        // The shared per-row core (also used by the SP1-side conformance test):
        // witness generation, full-row reconstruction, constraints, and sends.
        let rc = match check_row(&program, &row_map, &inputs, &hints) {
            Ok(out) => out,
            Err(e) => {
                failures.push(format!("{chip} row {row_i} ({kind}): {e}"));
                continue;
            }
        };
        let got: Vec<u64> = rc.cells[inputs.len()..].iter().map(|x| x.val()).collect();
        if verbose {
            for s in &rc.spans {
                let vals: Vec<u64> =
                    got[s.start - inputs.len()..s.start - inputs.len() + s.len].to_vec();
                println!(
                    "  {chip} row {row_i} op #{}: {} cells {:?}",
                    s.op_index, s.len, vals
                );
            }
        }
        if got.len() != expected.len() {
            failures.push(format!(
                "{chip} row {row_i} ({kind}): produced {} cells, expected {}",
                got.len(),
                expected.len()
            ));
            continue;
        }
        for (cell, (g, e)) in got.iter().zip(expected.iter()).enumerate() {
            if g != e {
                let origin = span_of(&rc.spans, cell + inputs.len())
                    .map(|s| {
                        format!(
                            "witness op #{}, local cell {}",
                            s.op_index,
                            cell + inputs.len() - s.start
                        )
                    })
                    .unwrap_or_else(|| "?".to_string());
                failures.push(format!(
                    "{chip} row {row_i} ({kind}): cell {cell} expected {e} got {g} ({origin})"
                ));
            }
        }

        // Full-row comparison against SP1's dumped row where the fixture carries it.
        if let Some(er) = r.get("expectedRow").and_then(|e| e.as_array()) {
            let expected_row: Vec<u64> = er
                .iter()
                .enumerate()
                .map(|(i, x)| num_field(x, &format!("{chip} row {row_i} expectedRow[{i}]")))
                .collect::<Result<_, _>>()?;
            if expected_row.len() != row_map.rust_width {
                failures.push(format!(
                    "{chip} row {row_i} ({kind}): expectedRow length {} != rustWidth {}",
                    expected_row.len(),
                    row_map.rust_width
                ));
            } else {
                row_checked += 1;
                for (col, (g, e)) in rc
                    .rust_row
                    .iter()
                    .map(|x| x.val())
                    .zip(expected_row.iter())
                    .enumerate()
                {
                    if g != *e {
                        failures.push(format!(
                            "{chip} row {row_i} ({kind}): rust row column {col} expected {e} got {g}"
                        ));
                    }
                }
            }
        }

        // On SP1-anchored rows the constraints must hold; sends are counted there.
        let anchored = r.get("anchored").and_then(|a| a.as_bool()).unwrap_or(false);
        if anchored {
            anchored_rows += 1;
            for (op_i, v) in &rc.constraint_failures {
                failures.push(format!(
                    "{chip} row {row_i} ({kind}): constraint operations[{op_i}] evaluates to {v} (expected 0)"
                ));
            }
            for channel in &rc.sends {
                *interaction_sends.entry(channel.clone()).or_insert(0) += 1;
            }
        }
    }
    Ok(ChipReport {
        chip: chip.to_string(),
        rows: rows.len(),
        anchored_rows,
        row_checked,
        constraint_ops,
        interaction_sends,
        failures,
    })
}

/// Enumerate the fixtures in `export_dir/testdata`, optionally filtered to one chip.
pub fn chips_in(export_dir: &Path, chip: Option<&str>) -> Result<Vec<String>, String> {
    let td = export_dir.join("testdata");
    let mut chips = Vec::new();
    for entry in std::fs::read_dir(&td).map_err(|e| format!("{}: {e}", td.display()))? {
        let name = entry.map_err(|e| e.to_string())?.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".trace.json") {
            if chip.is_none_or(|c| c == stem) {
                chips.push(stem.to_string());
            }
        }
    }
    chips.sort();
    if chips.is_empty() {
        return Err(match chip {
            Some(c) => format!("no fixture for chip `{c}` under {}", td.display()),
            None => format!("no fixtures under {}", td.display()),
        });
    }
    Ok(chips)
}
