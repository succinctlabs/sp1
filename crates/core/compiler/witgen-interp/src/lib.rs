//! Reference interpreter for the Lean-exported witness-generation IR.
//!
//! Consumes the `version: 1` wire format documented in `docs/witgen-wire-format.md`
//! (normative source: the Clean pin's `Clean/Circuit/WitnessExport.lean`), and runs
//! the differential fixtures under `export/testdata/`. Deliberately self-contained:
//! the crate depends only on the wire format — no prover types, no Lean toolchain.
//!
//! Witness generation is completeness-side: a wrong interpreter (or a wrong exported
//! program) makes a prover fail, never a false proof verify — this crate is a
//! conformance oracle, not a trusted component.

pub mod check;
pub mod eval;
pub mod field;
pub mod fixtures;
pub mod wire;

use field::KoalaBear;
use std::path::Path;

/// Run the differential battery. Returns `(rows checked, failure messages)`.
pub fn run_all(
    export_dir: &Path,
    chip: Option<&str>,
    verbose: bool,
) -> Result<(usize, Vec<String>), String> {
    let chips = fixtures::chips_in(export_dir, chip)?;
    let mut rows = 0;
    let mut failures = Vec::new();
    for chip in &chips {
        let report = fixtures::run_chip::<KoalaBear>(export_dir, chip, verbose)?;
        let status = if report.failures.is_empty() {
            "ok"
        } else {
            "FAIL"
        };
        let sends: Vec<String> = report
            .interaction_sends
            .iter()
            .map(|(ch, n)| format!("{ch}:{n}"))
            .collect();
        let detail = if report.anchored_rows > 0 {
            format!(
                " ({} anchored: {} rows reconstructed, {} constraints=0/row, sends {})",
                report.anchored_rows,
                report.row_checked,
                report.constraint_ops,
                sends.join(" ")
            )
        } else {
            String::new()
        };
        println!("{}: {} rows {status}{detail}", report.chip, report.rows);
        rows += report.rows;
        failures.extend(report.failures);
    }
    Ok((rows, failures))
}

/// Throughput measurement over one chip's fixture rows: the full product path
/// (witness generation + full-row reconstruction) repeated `iters` times, cycling the
/// fixture rows. Returns rows/second.
pub fn bench(export_dir: &Path, chip: &str, iters: usize) -> Result<f64, String> {
    use eval::Tables;
    use field::{Field, KoalaBear as F};
    let payload = fixtures::read_json_pub(
        &export_dir
            .join("witgen")
            .join(format!("{chip}.witgen.json")),
    )?;
    let program = wire::parse_program(&payload)?;
    let row_map = wire::parse_row_map(&fixtures::read_json_pub(
        &export_dir
            .join("witgen")
            .join(format!("{chip}.rowmap.json")),
    )?)?;
    let rows = fixtures::fixture_rows::<F>(export_dir, chip)?;
    if rows.is_empty() {
        return Err(format!("{chip}: no fixture rows"));
    }
    let data = Tables::default();
    let mut sink = 0u64;
    let start = std::time::Instant::now();
    for i in 0..iters {
        let (inputs, hints) = &rows[i % rows.len()];
        let (cells, _) = eval::witgen(&program, inputs, hints, &data)?;
        let ctx = eval::Ctx {
            cells: &cells,
            locals: &[],
            idx: 0,
            hints,
            data: &data,
        };
        for e in &row_map.row {
            sink = sink.wrapping_add(eval::eval_expr(ctx, e).val());
        }
    }
    let secs = start.elapsed().as_secs_f64();
    // keep the sink observable so the loop cannot be optimized away
    if sink == u64::MAX {
        println!("(unreachable sink)");
    }
    Ok(iters as f64 / secs)
}
