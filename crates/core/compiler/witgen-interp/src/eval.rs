//! The evaluator — a transcription of the Lean reference loop (`Circuit.witgen` /
//! `witgenStep` in `Clean/Circuit/WitnessGeneration.lean`) with the wire format's
//! totality conventions:
//!
//! - out-of-range cell reads → 0; `localVar` sort-mismatch or out-of-range → 0;
//! - `listGet` out-of-range → 0; missing hint/data table or row → the all-zero vector;
//! - field `0⁻¹ = 0`; u64 `x / 0 = 0` and `x % 0 = x`; shift amounts masked mod 64;
//! - `mapRange` binds `idx` (0 outside); `envRange` reads **absolute** cell indices;
//! - `bitsOf` is field-level (its width may exceed 64).

use crate::field::Field;
use crate::wire::{BExpr, Expr, FExpr, Op, Program, Step, U64Expr, VExpr};
use std::collections::HashMap;

/// A step-local value — the `F ⊕ UInt64` of the Lean model.
#[derive(Copy, Clone, Debug)]
pub enum Local<F> {
    F(F),
    U64(u64),
}

/// A `(table, width) → rows` map (`ProverHint` / `ProverData`).
#[derive(Clone, Debug)]
pub struct Tables<F> {
    pub map: HashMap<(String, usize), Vec<Vec<F>>>,
}

impl<F> Default for Tables<F> {
    fn default() -> Self {
        Tables {
            map: HashMap::new(),
        }
    }
}

impl<F: Field> Tables<F> {
    /// The read semantics: missing table, out-of-range row, or out-of-range column
    /// all read as 0.
    pub fn get(&self, table: &str, width: usize, row: u64, col: usize) -> F {
        self.map
            .get(&(table.to_string(), width))
            .and_then(|rows| rows.get(row as usize))
            .and_then(|r| r.get(col))
            .copied()
            .unwrap_or_else(F::zero)
    }
}

/// The evaluation context (the Lean `Ctx`): the growing cell array, the current
/// witness op's locals, the innermost `mapRange` index, and the prover tables.
#[derive(Copy, Clone)]
pub struct Ctx<'a, F> {
    pub cells: &'a [F],
    pub locals: &'a [Local<F>],
    pub idx: u64,
    pub hints: &'a Tables<F>,
    pub data: &'a Tables<F>,
}

impl<'a, F: Field> Ctx<'a, F> {
    fn cell(&self, i: usize) -> F {
        self.cells.get(i).copied().unwrap_or_else(F::zero)
    }

    fn with_idx(self, idx: u64) -> Self {
        Ctx { idx, ..self }
    }
}

pub fn eval_expr<F: Field>(ctx: Ctx<F>, e: &Expr) -> F {
    match e {
        Expr::Var(i) => ctx.cell(*i),
        Expr::Const(c) => F::from_u64(*c),
        Expr::Add(x, y) => eval_expr(ctx, x).add(eval_expr(ctx, y)),
        Expr::Mul(x, y) => eval_expr(ctx, x).mul(eval_expr(ctx, y)),
    }
}

pub fn eval_f<F: Field>(ctx: Ctx<F>, e: &FExpr) -> F {
    match e {
        FExpr::Expr(e) => eval_expr(ctx, e),
        FExpr::Const(c) => F::from_u64(*c),
        FExpr::LocalVar(i) => match ctx.locals.get(*i) {
            Some(Local::F(x)) => *x,
            _ => F::zero(),
        },
        FExpr::Add(x, y) => eval_f(ctx, x).add(eval_f(ctx, y)),
        FExpr::Mul(x, y) => eval_f(ctx, x).mul(eval_f(ctx, y)),
        FExpr::Inv(x) => eval_f(ctx, x).inv(),
        FExpr::OfU64(n) => F::from_u64(eval_u64(ctx, n)),
        FExpr::Ite(c, t, e) => {
            if eval_b(ctx, c) {
                eval_f(ctx, t)
            } else {
                eval_f(ctx, e)
            }
        }
        FExpr::ListGet(items, i) => {
            let i = eval_u64(ctx, i) as usize;
            items.get(i).map(|x| eval_f(ctx, x)).unwrap_or_else(F::zero)
        }
        FExpr::DataGet {
            table,
            width,
            row,
            col,
        } => {
            let row = eval_u64(ctx, row);
            ctx.data.get(table, *width, row, *col)
        }
        FExpr::HintGet {
            table,
            width,
            row,
            col,
        } => {
            let row = eval_u64(ctx, row);
            ctx.hints.get(table, *width, row, *col)
        }
    }
}

pub fn eval_u64<F: Field>(ctx: Ctx<F>, e: &U64Expr) -> u64 {
    match e {
        U64Expr::Const(n) => *n,
        // `val` truncates the canonical value to 64 bits (a no-op for fields
        // narrower than 2^64, i.e. every prime this crate targets).
        U64Expr::Val(x) => eval_f(ctx, x).val(),
        U64Expr::Idx => ctx.idx,
        U64Expr::LocalVar(i) => match ctx.locals.get(*i) {
            Some(Local::U64(n)) => *n,
            _ => 0,
        },
        U64Expr::Add(x, y) => eval_u64(ctx, x).wrapping_add(eval_u64(ctx, y)),
        U64Expr::Mul(x, y) => eval_u64(ctx, x).wrapping_mul(eval_u64(ctx, y)),
        // Lean's Nat-backed UInt64 semantics: x / 0 = 0, x % 0 = x.
        U64Expr::Div(x, y) => {
            let (x, y) = (eval_u64(ctx, x), eval_u64(ctx, y));
            x.checked_div(y).unwrap_or(0)
        }
        U64Expr::Mod(x, y) => {
            let (x, y) = (eval_u64(ctx, x), eval_u64(ctx, y));
            if y == 0 {
                x
            } else {
                x % y
            }
        }
        U64Expr::And(x, y) => eval_u64(ctx, x) & eval_u64(ctx, y),
        U64Expr::Or(x, y) => eval_u64(ctx, x) | eval_u64(ctx, y),
        U64Expr::Xor(x, y) => eval_u64(ctx, x) ^ eval_u64(ctx, y),
        // Shift amounts are masked mod 64 (wrapping_shl/shr mask; the u64→u32 cast
        // preserves the amount mod 64 since 64 divides 2^32).
        U64Expr::ShiftLeft(x, y) => eval_u64(ctx, x).wrapping_shl(eval_u64(ctx, y) as u32),
        U64Expr::ShiftRight(x, y) => eval_u64(ctx, x).wrapping_shr(eval_u64(ctx, y) as u32),
        U64Expr::Ite(c, t, e) => {
            if eval_b(ctx, c) {
                eval_u64(ctx, t)
            } else {
                eval_u64(ctx, e)
            }
        }
    }
}

pub fn eval_b<F: Field>(ctx: Ctx<F>, e: &BExpr) -> bool {
    match e {
        BExpr::True => true,
        BExpr::False => false,
        BExpr::Eq(x, y) => eval_f(ctx, x) == eval_f(ctx, y),
        BExpr::U64Eq(x, y) => eval_u64(ctx, x) == eval_u64(ctx, y),
        BExpr::U64Lt(x, y) => eval_u64(ctx, x) < eval_u64(ctx, y),
        BExpr::Lt(x, y) => eval_f(ctx, x).val() < eval_f(ctx, y).val(),
        BExpr::Bit(x, i) => {
            let v = eval_f(ctx, x).val();
            if *i >= 64 {
                false
            } else {
                (v >> i) & 1 == 1
            }
        }
        BExpr::Not(b) => !eval_b(ctx, b),
        BExpr::And(x, y) => eval_b(ctx, x) && eval_b(ctx, y),
    }
}

pub fn eval_v<F: Field>(ctx: Ctx<F>, e: &VExpr, out: &mut Vec<F>) {
    match e {
        VExpr::Elements(es) => {
            for x in es {
                out.push(eval_f(ctx, x));
            }
        }
        VExpr::MapRange { n, body } => {
            for i in 0..*n {
                out.push(eval_f(ctx.with_idx(i as u64), body));
            }
        }
        VExpr::EnvRange { n, offset } => {
            for i in 0..*n {
                out.push(ctx.cell(offset + i));
            }
        }
        VExpr::BitsOf { n, arg } => {
            let v = eval_f(ctx, arg).val();
            for i in 0..*n {
                let bit = if i >= 64 { 0 } else { (v >> i) & 1 };
                out.push(F::from_u64(bit));
            }
        }
        VExpr::Append(a, b) => {
            eval_v(ctx, a, out);
            eval_v(ctx, b, out);
        }
    }
}

/// Which witness op produced which appended cell range (for mismatch reports).
#[derive(Debug, Clone, Copy)]
pub struct OpSpan {
    pub op_index: usize,
    pub start: usize,
    pub len: usize,
}

/// The linear witgen pass: seed with the inputs, fold the operations, append exactly
/// `m` cells per witness op. Returns the full cell array plus the per-op spans.
pub fn witgen<F: Field>(
    program: &Program,
    inputs: &[F],
    hints: &Tables<F>,
    data: &Tables<F>,
) -> Result<(Vec<F>, Vec<OpSpan>), String> {
    let mut cells: Vec<F> = inputs.to_vec();
    let mut spans = Vec::new();
    for (op_index, op) in program.ops.iter().enumerate() {
        let Op::Witness { m, steps, output } = op else {
            continue;
        };
        let mut locals: Vec<Local<F>> = Vec::with_capacity(steps.len());
        for step in steps {
            let ctx = Ctx {
                cells: &cells,
                locals: &locals,
                idx: 0,
                hints,
                data,
            };
            let local = match step {
                Step::Field(e) => Local::F(eval_f(ctx, e)),
                Step::U64(e) => Local::U64(eval_u64(ctx, e)),
            };
            locals.push(local);
        }
        let start = cells.len();
        let mut out = Vec::with_capacity(*m);
        {
            let ctx = Ctx {
                cells: &cells,
                locals: &locals,
                idx: 0,
                hints,
                data,
            };
            eval_v(ctx, output, &mut out);
        }
        if out.len() != *m {
            return Err(format!(
                "operations[{op_index}]: witness declared {m} cells but produced {}",
                out.len()
            ));
        }
        cells.extend_from_slice(&out);
        spans.push(OpSpan {
            op_index,
            start,
            len: *m,
        });
    }
    Ok((cells, spans))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::KoalaBear;

    type F = KoalaBear;

    fn ctx<'a>(
        cells: &'a [F],
        locals: &'a [Local<F>],
        hints: &'a Tables<F>,
        data: &'a Tables<F>,
    ) -> Ctx<'a, F> {
        Ctx {
            cells,
            locals,
            idx: 0,
            hints,
            data,
        }
    }

    fn empty() -> (Vec<F>, Vec<Local<F>>, Tables<F>, Tables<F>) {
        (Vec::new(), Vec::new(), Tables::default(), Tables::default())
    }

    #[test]
    fn div_mod_by_zero() {
        let (c, l, h, d) = empty();
        let x = U64Expr::Const(7);
        let z = U64Expr::Const(0);
        let div = U64Expr::Div(Box::new(x.clone()), Box::new(z.clone()));
        let m = U64Expr::Mod(Box::new(x), Box::new(z));
        assert_eq!(eval_u64(ctx(&c, &l, &h, &d), &div), 0, "x / 0 = 0");
        assert_eq!(eval_u64(ctx(&c, &l, &h, &d), &m), 7, "x % 0 = x");
    }

    #[test]
    fn shift_amount_masked_mod_64() {
        let (c, l, h, d) = empty();
        let e = U64Expr::ShiftLeft(Box::new(U64Expr::Const(1)), Box::new(U64Expr::Const(65)));
        assert_eq!(eval_u64(ctx(&c, &l, &h, &d), &e), 2, "1 <<< 65 = 1 <<< 1");
        let e = U64Expr::ShiftRight(Box::new(U64Expr::Const(8)), Box::new(U64Expr::Const(67)));
        assert_eq!(eval_u64(ctx(&c, &l, &h, &d), &e), 1, "8 >>> 67 = 8 >>> 3");
    }

    #[test]
    fn u64eq_is_equality() {
        let (c, l, h, d) = empty();
        let e = BExpr::U64Eq(Box::new(U64Expr::Const(5)), Box::new(U64Expr::Const(5)));
        assert!(
            eval_b(ctx(&c, &l, &h, &d), &e),
            "the wire tag u64Eq means EQUALITY"
        );
    }

    #[test]
    fn localvar_sort_mismatch_reads_zero() {
        let (c, _, h, d) = empty();
        let locals = vec![Local::U64(42)];
        // a field-sorted read of a u64-sorted local is 0, not a reinterpretation
        assert_eq!(
            eval_f(ctx(&c, &locals, &h, &d), &FExpr::LocalVar(0)).val(),
            0
        );
        // and out of range is 0 in both sorts
        assert_eq!(
            eval_f(ctx(&c, &locals, &h, &d), &FExpr::LocalVar(9)).val(),
            0
        );
        assert_eq!(eval_u64(ctx(&c, &locals, &h, &d), &U64Expr::LocalVar(9)), 0);
    }

    #[test]
    fn listget_out_of_range_reads_zero() {
        let (c, l, h, d) = empty();
        let e = FExpr::ListGet(vec![FExpr::Const(3)], Box::new(U64Expr::Const(7)));
        assert_eq!(eval_f(ctx(&c, &l, &h, &d), &e).val(), 0);
    }

    #[test]
    fn missing_hint_reads_zero() {
        let (c, l, h, d) = empty();
        let e = FExpr::HintGet {
            table: "nope".into(),
            width: 3,
            row: Box::new(U64Expr::Const(0)),
            col: 1,
        };
        assert_eq!(eval_f(ctx(&c, &l, &h, &d), &e).val(), 0);
    }

    #[test]
    fn bits_of_wider_than_64() {
        let (c, l, h, d) = empty();
        let mut out = Vec::new();
        let e = VExpr::BitsOf {
            n: 70,
            arg: Box::new(FExpr::Const(5)),
        };
        eval_v(ctx(&c, &l, &h, &d), &e, &mut out);
        assert_eq!(out.len(), 70);
        assert_eq!(out[0].val(), 1);
        assert_eq!(out[1].val(), 0);
        assert_eq!(out[2].val(), 1);
        assert!(out[3..].iter().all(|x| x.val() == 0));
    }

    #[test]
    fn maprange_binds_idx() {
        let (c, l, h, d) = empty();
        let mut out = Vec::new();
        let e = VExpr::MapRange {
            n: 4,
            body: Box::new(FExpr::OfU64(Box::new(U64Expr::Idx))),
        };
        eval_v(ctx(&c, &l, &h, &d), &e, &mut out);
        assert_eq!(
            out.iter().map(|x| x.val()).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn envrange_is_absolute_and_total() {
        let cells: Vec<F> = [10u64, 11, 12].iter().map(|&v| F::from_u64(v)).collect();
        let (_, l, h, d) = empty();
        let mut out = Vec::new();
        let e = VExpr::EnvRange { n: 3, offset: 2 };
        eval_v(ctx(&cells, &l, &h, &d), &e, &mut out);
        assert_eq!(
            out.iter().map(|x| x.val()).collect::<Vec<_>>(),
            vec![12, 0, 0]
        );
    }

    #[test]
    fn steps_evaluate_left_to_right() {
        // let u0 = 5; let f1 = ofU64 (u0 + 1); output [f1, localVar-mismatch]
        let program = Program {
            local_length: 2,
            ops: vec![Op::Witness {
                m: 2,
                steps: vec![
                    Step::U64(U64Expr::Const(5)),
                    Step::Field(FExpr::OfU64(Box::new(U64Expr::Add(
                        Box::new(U64Expr::LocalVar(0)),
                        Box::new(U64Expr::Const(1)),
                    )))),
                ],
                output: VExpr::Elements(vec![FExpr::LocalVar(1), FExpr::LocalVar(0)]),
            }],
        };
        let (h, d) = (Tables::default(), Tables::default());
        let (cells, spans) = witgen::<F>(&program, &[], &h, &d).unwrap();
        assert_eq!(
            cells.iter().map(|x| x.val()).collect::<Vec<_>>(),
            vec![6, 0]
        );
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].start, spans[0].len), (0, 2));
    }
}
