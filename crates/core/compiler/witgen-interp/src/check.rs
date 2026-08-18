//! The pure per-row checking core: given a chip's wire-format program and symbolic
//! row map plus one row's inputs and hints, run witness generation, reconstruct the
//! full Rust trace row, and evaluate every constraint and interaction multiplicity.
//!
//! This is the single implementation shared by the fixture differential in this repo
//! (`fixtures::run_chip`) and by an SP1-side conformance test running against live
//! `generate_trace` rows — the two callers differ only in where the inputs come from
//! (fixture JSON vs. `derive_inputs` on a real trace row) and in what they compare
//! the outputs against.
//!
//! Hint-context convention: witness generation reads the real `hints` (hint tables
//! are `FExpr`-sort reads inside witness code), but the row map and the
//! assert/interact expressions are `Expression`-sort — that sort has no hint or data
//! nodes, so they are evaluated against empty tables. This matches the Lean gate
//! (`rowValsOf` evaluates the row map hint-free) and is observably identical either
//! way; the empty tables just make the independence structural.

use crate::eval::{eval_expr, witgen, Ctx, OpSpan, Tables};
use crate::field::Field;
use crate::wire::{Expr, Op, Program, RowMap};

/// Outcome of checking one row.
pub struct RowCheck<F> {
    /// The completed cell array: the inputs followed by every generated witness cell.
    pub cells: Vec<F>,
    /// Spans blaming each generated cell on its producing witness operation.
    pub spans: Vec<OpSpan>,
    /// The full Rust trace row: every row-map column evaluated over `cells`.
    pub rust_row: Vec<F>,
    /// `(operations index, nonzero value)` for every `assert` that fails to be 0.
    pub constraint_failures: Vec<(usize, u64)>,
    /// The channel of every interaction with nonzero multiplicity, in op order.
    pub sends: Vec<String>,
}

/// Run one row end-to-end: witness generation over `inputs`/`hints`, then the row
/// map, constraints, and interaction multiplicities over the completed cells.
pub fn check_row<F: Field>(
    program: &Program,
    row_map: &RowMap,
    inputs: &[F],
    hints: &Tables<F>,
) -> Result<RowCheck<F>, String> {
    let data = Tables::default();
    let (cells, spans) = witgen(program, inputs, hints, &data)?;

    // Expression-sort evaluation is hint/data-free by construction (see module doc).
    let empty = Tables::default();
    let ctx = Ctx {
        cells: &cells,
        locals: &[],
        idx: 0,
        hints: &empty,
        data: &empty,
    };
    let rust_row: Vec<F> = row_map.row.iter().map(|e| eval_expr(ctx, e)).collect();

    let mut constraint_failures = Vec::new();
    let mut sends = Vec::new();
    for (op_i, op) in program.ops.iter().enumerate() {
        match op {
            Op::Assert(e) => {
                let v = eval_expr(ctx, e).val();
                if v != 0 {
                    constraint_failures.push((op_i, v));
                }
            }
            Op::Interact {
                channel,
                multiplicity,
                ..
            } if eval_expr(ctx, multiplicity).val() != 0 => {
                sends.push(channel.clone());
            }
            _ => {}
        }
    }

    Ok(RowCheck {
        cells,
        spans,
        rust_row,
        constraint_failures,
        sends,
    })
}

/// Input recovery from a full Rust trace row through the symbolic row map.
///
/// Every native input cell `i < input_width` must appear as a bare `var i` column of
/// the row map — the property the Lean exporter's gate verifies for all 25 SP1 chips —
/// except input cell 0 when `is_real_hinted` is set (the six flag-hinted chips:
/// Bitwise, Branch, Lt, Mul, ShiftLeft, ShiftRight), which is filled with `is_real`
/// instead (`1` on event rows, `0` on padding rows). Fails closed on any other
/// unmapped input cell, so row-map drift breaks the caller loudly instead of
/// producing wrong inputs.
pub fn derive_inputs<F: Field>(
    row_map: &RowMap,
    input_width: usize,
    row: &[F],
    is_real_hinted: bool,
    is_real: F,
) -> Result<Vec<F>, String> {
    if row.len() != row_map.rust_width {
        return Err(format!(
            "trace row has {} columns, row map expects {}",
            row.len(),
            row_map.rust_width
        ));
    }
    // First bare-var column per input index.
    let mut col_of = vec![None; input_width];
    for (col, e) in row_map.row.iter().enumerate() {
        if let Expr::Var(i) = e {
            if *i < input_width && col_of[*i].is_none() {
                col_of[*i] = Some(col);
            }
        }
    }
    (0..input_width)
        .map(|i| match col_of[i] {
            Some(col) => Ok(row[col]),
            None if i == 0 && is_real_hinted => Ok(is_real),
            None => Err(format!(
                "input cell {i} is not a bare row-map column (row map drifted)"
            )),
        })
        .collect()
}

/// First differing position of two equal-length canonical-value slices, as
/// `(index, got, expected)`.
pub fn first_mismatch(got: &[u64], expected: &[u64]) -> Option<(usize, u64, u64)> {
    got.iter()
        .zip(expected.iter())
        .enumerate()
        .find(|(_, (g, e))| g != e)
        .map(|(i, (g, e))| (i, *g, *e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::KoalaBear;
    use crate::wire::RowMap;

    fn rm(cols: Vec<Expr>) -> RowMap {
        RowMap {
            rust_width: cols.len(),
            row: cols,
        }
    }

    #[test]
    fn derive_inputs_recovers_bare_vars() {
        // Row layout: [var 1, var 0, var 2] over 3 inputs.
        let map = rm(vec![Expr::Var(1), Expr::Var(0), Expr::Var(2)]);
        let row: Vec<KoalaBear> = [10u64, 20, 30]
            .iter()
            .map(|&v| KoalaBear::from_u64(v))
            .collect();
        let inputs = derive_inputs(&map, 3, &row, false, KoalaBear::from_u64(1)).unwrap();
        let vals: Vec<u64> = inputs.iter().map(|x| x.val()).collect();
        assert_eq!(vals, vec![20, 10, 30]);
    }

    #[test]
    fn derive_inputs_is_real_rule() {
        // Input 0 (is_real) has no bare column; inputs 1..3 map to columns.
        let map = rm(vec![Expr::Var(1), Expr::Var(2)]);
        let row: Vec<KoalaBear> = [7u64, 8].iter().map(|&v| KoalaBear::from_u64(v)).collect();
        let inputs = derive_inputs(&map, 3, &row, true, KoalaBear::from_u64(1)).unwrap();
        let vals: Vec<u64> = inputs.iter().map(|x| x.val()).collect();
        assert_eq!(vals, vec![1, 7, 8]);
        // Without the allowlist flag the same map fails closed.
        assert!(derive_inputs(&map, 3, &row, false, KoalaBear::from_u64(1))
            .unwrap_err()
            .contains("input cell 0"));
    }

    #[test]
    fn derive_inputs_fails_closed_on_gap() {
        // Input 1 unmapped and not coverable by the is_real rule.
        let map = rm(vec![Expr::Var(0), Expr::Var(2)]);
        let row: Vec<KoalaBear> = [1u64, 2].iter().map(|&v| KoalaBear::from_u64(v)).collect();
        let err = derive_inputs(&map, 3, &row, true, KoalaBear::from_u64(1)).unwrap_err();
        assert!(err.contains("input cell 1"), "{err}");
    }

    #[test]
    fn derive_inputs_checks_width() {
        let map = rm(vec![Expr::Var(0)]);
        let row: Vec<KoalaBear> = vec![];
        assert!(derive_inputs(&map, 1, &row, false, KoalaBear::from_u64(0)).is_err());
    }

    #[test]
    fn first_mismatch_reports_earliest() {
        assert_eq!(first_mismatch(&[1, 2, 3], &[1, 9, 9]), Some((1, 2, 9)));
        assert_eq!(first_mismatch(&[1, 2], &[1, 2]), None);
    }
}
