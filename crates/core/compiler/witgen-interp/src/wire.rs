//! The `version: 1` witgen wire format — types and the sort-directed parser.
//!
//! The wire's `type` tags collide across the four expression sorts (`const`, `add`,
//! `mul`, `ite`, `localVar`, `and` each appear in two or three vocabularies), so
//! deserialization is directed by the parent slot: each parse function knows which
//! sort it expects. Case names follow the **wire tags**, not the Lean constructor
//! names — three of them disagree (`u64Eq` is *equality*, `u64Lt` is the u64 `<`,
//! and `lt` is the field-value `<`), and naming after the wire neutralizes the trap.
//!
//! Errors carry a JSON path (e.g. `operations[12].code.output.elements[3]`).

use serde_json::Value;

/// The circuit-constraint AST (`var` carries an **absolute** cell index).
#[derive(Debug, Clone)]
pub enum Expr {
    Var(usize),
    Const(u64),
    Add(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
}

/// Field-sorted witness expressions.
#[derive(Debug, Clone)]
pub enum FExpr {
    Expr(Expr),
    Const(u64),
    LocalVar(usize),
    Add(Box<FExpr>, Box<FExpr>),
    Mul(Box<FExpr>, Box<FExpr>),
    Inv(Box<FExpr>),
    OfU64(Box<U64Expr>),
    Ite(Box<BExpr>, Box<FExpr>, Box<FExpr>),
    ListGet(Vec<FExpr>, Box<U64Expr>),
    DataGet {
        table: String,
        width: usize,
        row: Box<U64Expr>,
        col: usize,
    },
    HintGet {
        table: String,
        width: usize,
        row: Box<U64Expr>,
        col: usize,
    },
}

/// u64-sorted expressions — everything wraps mod 2^64.
#[derive(Debug, Clone)]
pub enum U64Expr {
    Const(u64),
    Val(Box<FExpr>),
    Idx,
    LocalVar(usize),
    Add(Box<U64Expr>, Box<U64Expr>),
    Mul(Box<U64Expr>, Box<U64Expr>),
    Div(Box<U64Expr>, Box<U64Expr>),
    Mod(Box<U64Expr>, Box<U64Expr>),
    And(Box<U64Expr>, Box<U64Expr>),
    Or(Box<U64Expr>, Box<U64Expr>),
    Xor(Box<U64Expr>, Box<U64Expr>),
    ShiftLeft(Box<U64Expr>, Box<U64Expr>),
    ShiftRight(Box<U64Expr>, Box<U64Expr>),
    Ite(Box<BExpr>, Box<U64Expr>, Box<U64Expr>),
}

/// Conditions. Wire-tag names (see the module doc for the Lean-name disagreements).
#[derive(Debug, Clone)]
pub enum BExpr {
    True,
    False,
    /// Field equality (wire tag `eq`).
    Eq(Box<FExpr>, Box<FExpr>),
    /// u64 **equality** (wire tag `u64Eq`; the Lean constructor is named `neq`).
    U64Eq(Box<U64Expr>, Box<U64Expr>),
    /// u64 `<` (wire tag `u64Lt`).
    U64Lt(Box<U64Expr>, Box<U64Expr>),
    /// Field-canonical-value `<` (wire tag `lt`).
    Lt(Box<FExpr>, Box<FExpr>),
    /// Bit `bit` of the canonical value of `arg` is set.
    Bit(Box<FExpr>, u64),
    Not(Box<BExpr>),
    And(Box<BExpr>, Box<BExpr>),
}

/// Vector-shaped witness output.
#[derive(Debug, Clone)]
pub enum VExpr {
    Elements(Vec<FExpr>),
    MapRange { n: usize, body: Box<FExpr> },
    EnvRange { n: usize, offset: usize },
    BitsOf { n: usize, arg: Box<FExpr> },
    Append(Box<VExpr>, Box<VExpr>),
}

/// A scalar let-step, referenced positionally by `localVar` of the matching sort.
#[derive(Debug, Clone)]
pub enum Step {
    Field(FExpr),
    U64(U64Expr),
}

/// One flattened operation. `Witness` drives witness generation; `Assert` (the
/// constraint `expr = 0`) and `Interact` are carried with their bodies so a consumer
/// can check constraints and derive bus/lookup multiplicities from the same artifact.
#[derive(Debug, Clone)]
pub enum Op {
    Witness {
        m: usize,
        steps: Vec<Step>,
        output: VExpr,
    },
    Assert(Expr),
    Lookup,
    Interact {
        channel: String,
        multiplicity: Expr,
        message: Vec<Expr>,
    },
}

/// A parsed `<Chip>.witgen.json` payload.
#[derive(Debug, Clone)]
pub struct Program {
    pub local_length: usize,
    pub ops: Vec<Op>,
}

pub type PResult<T> = Result<T, String>;

fn obj<'a>(v: &'a Value, path: &str) -> PResult<&'a serde_json::Map<String, Value>> {
    v.as_object()
        .ok_or_else(|| format!("{path}: expected object"))
}

fn get<'a>(m: &'a serde_json::Map<String, Value>, key: &str, path: &str) -> PResult<&'a Value> {
    m.get(key)
        .ok_or_else(|| format!("{path}: missing key `{key}`"))
}

fn num(v: &Value, path: &str) -> PResult<u64> {
    v.as_u64()
        .ok_or_else(|| format!("{path}: expected unsigned integer"))
}

fn idx(v: &Value, path: &str) -> PResult<usize> {
    Ok(num(v, path)? as usize)
}

fn tag<'a>(m: &'a serde_json::Map<String, Value>, path: &str) -> PResult<&'a str> {
    get(m, "type", path)?
        .as_str()
        .ok_or_else(|| format!("{path}.type: expected string"))
}

pub fn parse_expr(v: &Value, path: &str) -> PResult<Expr> {
    let m = obj(v, path)?;
    match tag(m, path)? {
        "var" => Ok(Expr::Var(idx(
            get(m, "index", path)?,
            &format!("{path}.index"),
        )?)),
        "const" => Ok(Expr::Const(num(
            get(m, "value", path)?,
            &format!("{path}.value"),
        )?)),
        "add" => Ok(Expr::Add(
            Box::new(parse_expr(get(m, "lhs", path)?, &format!("{path}.lhs"))?),
            Box::new(parse_expr(get(m, "rhs", path)?, &format!("{path}.rhs"))?),
        )),
        "mul" => Ok(Expr::Mul(
            Box::new(parse_expr(get(m, "lhs", path)?, &format!("{path}.lhs"))?),
            Box::new(parse_expr(get(m, "rhs", path)?, &format!("{path}.rhs"))?),
        )),
        t => Err(format!("{path}: unknown Expression tag `{t}`")),
    }
}

pub fn parse_fexpr(v: &Value, path: &str) -> PResult<FExpr> {
    let m = obj(v, path)?;
    let bin = |k: &str| -> PResult<Box<FExpr>> {
        Ok(Box::new(parse_fexpr(
            get(m, k, path)?,
            &format!("{path}.{k}"),
        )?))
    };
    match tag(m, path)? {
        "expr" => Ok(FExpr::Expr(parse_expr(
            get(m, "expr", path)?,
            &format!("{path}.expr"),
        )?)),
        "const" => Ok(FExpr::Const(num(
            get(m, "value", path)?,
            &format!("{path}.value"),
        )?)),
        "localVar" => Ok(FExpr::LocalVar(idx(
            get(m, "index", path)?,
            &format!("{path}.index"),
        )?)),
        "add" => Ok(FExpr::Add(bin("lhs")?, bin("rhs")?)),
        "mul" => Ok(FExpr::Mul(bin("lhs")?, bin("rhs")?)),
        "inv" => Ok(FExpr::Inv(bin("arg")?)),
        "ofU64" => Ok(FExpr::OfU64(Box::new(parse_u64expr(
            get(m, "arg", path)?,
            &format!("{path}.arg"),
        )?))),
        "ite" => Ok(FExpr::Ite(
            Box::new(parse_bexpr(get(m, "cond", path)?, &format!("{path}.cond"))?),
            bin("then")?,
            bin("else")?,
        )),
        "listGet" => {
            let items_v = get(m, "items", path)?
                .as_array()
                .ok_or_else(|| format!("{path}.items: expected array"))?;
            let mut items = Vec::with_capacity(items_v.len());
            for (i, it) in items_v.iter().enumerate() {
                items.push(parse_fexpr(it, &format!("{path}.items[{i}]"))?);
            }
            Ok(FExpr::ListGet(
                items,
                Box::new(parse_u64expr(
                    get(m, "index", path)?,
                    &format!("{path}.index"),
                )?),
            ))
        }
        t @ ("dataGet" | "hintGet") => {
            let table = get(m, "table", path)?
                .as_str()
                .ok_or_else(|| format!("{path}.table: expected string"))?
                .to_string();
            let width = idx(get(m, "width", path)?, &format!("{path}.width"))?;
            let row = Box::new(parse_u64expr(get(m, "row", path)?, &format!("{path}.row"))?);
            let col = idx(get(m, "col", path)?, &format!("{path}.col"))?;
            if t == "dataGet" {
                Ok(FExpr::DataGet {
                    table,
                    width,
                    row,
                    col,
                })
            } else {
                Ok(FExpr::HintGet {
                    table,
                    width,
                    row,
                    col,
                })
            }
        }
        t => Err(format!("{path}: unknown FExpr tag `{t}`")),
    }
}

pub fn parse_u64expr(v: &Value, path: &str) -> PResult<U64Expr> {
    let m = obj(v, path)?;
    let bin = |k: &str| -> PResult<Box<U64Expr>> {
        Ok(Box::new(parse_u64expr(
            get(m, k, path)?,
            &format!("{path}.{k}"),
        )?))
    };
    match tag(m, path)? {
        "const" => Ok(U64Expr::Const(num(
            get(m, "value", path)?,
            &format!("{path}.value"),
        )?)),
        "val" => Ok(U64Expr::Val(Box::new(parse_fexpr(
            get(m, "arg", path)?,
            &format!("{path}.arg"),
        )?))),
        "idx" => Ok(U64Expr::Idx),
        "localVar" => Ok(U64Expr::LocalVar(idx(
            get(m, "index", path)?,
            &format!("{path}.index"),
        )?)),
        "add" => Ok(U64Expr::Add(bin("lhs")?, bin("rhs")?)),
        "mul" => Ok(U64Expr::Mul(bin("lhs")?, bin("rhs")?)),
        "div" => Ok(U64Expr::Div(bin("lhs")?, bin("rhs")?)),
        "mod" => Ok(U64Expr::Mod(bin("lhs")?, bin("rhs")?)),
        "and" => Ok(U64Expr::And(bin("lhs")?, bin("rhs")?)),
        "or" => Ok(U64Expr::Or(bin("lhs")?, bin("rhs")?)),
        "xor" => Ok(U64Expr::Xor(bin("lhs")?, bin("rhs")?)),
        "shiftLeft" => Ok(U64Expr::ShiftLeft(bin("lhs")?, bin("rhs")?)),
        "shiftRight" => Ok(U64Expr::ShiftRight(bin("lhs")?, bin("rhs")?)),
        "ite" => Ok(U64Expr::Ite(
            Box::new(parse_bexpr(get(m, "cond", path)?, &format!("{path}.cond"))?),
            bin("then")?,
            bin("else")?,
        )),
        t => Err(format!("{path}: unknown U64Expr tag `{t}`")),
    }
}

pub fn parse_bexpr(v: &Value, path: &str) -> PResult<BExpr> {
    let m = obj(v, path)?;
    let f = |k: &str| -> PResult<Box<FExpr>> {
        Ok(Box::new(parse_fexpr(
            get(m, k, path)?,
            &format!("{path}.{k}"),
        )?))
    };
    let u = |k: &str| -> PResult<Box<U64Expr>> {
        Ok(Box::new(parse_u64expr(
            get(m, k, path)?,
            &format!("{path}.{k}"),
        )?))
    };
    match tag(m, path)? {
        "true" => Ok(BExpr::True),
        "false" => Ok(BExpr::False),
        "eq" => Ok(BExpr::Eq(f("lhs")?, f("rhs")?)),
        "u64Eq" => Ok(BExpr::U64Eq(u("lhs")?, u("rhs")?)),
        "u64Lt" => Ok(BExpr::U64Lt(u("lhs")?, u("rhs")?)),
        "lt" => Ok(BExpr::Lt(f("lhs")?, f("rhs")?)),
        "bit" => Ok(BExpr::Bit(
            f("arg")?,
            num(get(m, "bit", path)?, &format!("{path}.bit"))?,
        )),
        "not" => Ok(BExpr::Not(Box::new(parse_bexpr(
            get(m, "arg", path)?,
            &format!("{path}.arg"),
        )?))),
        "and" => Ok(BExpr::And(
            Box::new(parse_bexpr(get(m, "lhs", path)?, &format!("{path}.lhs"))?),
            Box::new(parse_bexpr(get(m, "rhs", path)?, &format!("{path}.rhs"))?),
        )),
        t => Err(format!("{path}: unknown BExpr tag `{t}`")),
    }
}

pub fn parse_vexpr(v: &Value, path: &str) -> PResult<VExpr> {
    let m = obj(v, path)?;
    match tag(m, path)? {
        "elements" => {
            let es = get(m, "elements", path)?
                .as_array()
                .ok_or_else(|| format!("{path}.elements: expected array"))?;
            let mut out = Vec::with_capacity(es.len());
            for (i, e) in es.iter().enumerate() {
                out.push(parse_fexpr(e, &format!("{path}.elements[{i}]"))?);
            }
            Ok(VExpr::Elements(out))
        }
        "mapRange" => Ok(VExpr::MapRange {
            n: idx(get(m, "n", path)?, &format!("{path}.n"))?,
            body: Box::new(parse_fexpr(get(m, "body", path)?, &format!("{path}.body"))?),
        }),
        "envRange" => Ok(VExpr::EnvRange {
            n: idx(get(m, "n", path)?, &format!("{path}.n"))?,
            offset: idx(get(m, "offset", path)?, &format!("{path}.offset"))?,
        }),
        "bitsOf" => Ok(VExpr::BitsOf {
            n: idx(get(m, "n", path)?, &format!("{path}.n"))?,
            arg: Box::new(parse_fexpr(get(m, "arg", path)?, &format!("{path}.arg"))?),
        }),
        "append" => Ok(VExpr::Append(
            Box::new(parse_vexpr(get(m, "left", path)?, &format!("{path}.left"))?),
            Box::new(parse_vexpr(
                get(m, "right", path)?,
                &format!("{path}.right"),
            )?),
        )),
        t => Err(format!("{path}: unknown VExpr tag `{t}`")),
    }
}

pub fn parse_step(v: &Value, path: &str) -> PResult<Step> {
    let m = obj(v, path)?;
    let sort = get(m, "sort", path)?
        .as_str()
        .ok_or_else(|| format!("{path}.sort: expected string"))?;
    let value = get(m, "value", path)?;
    match sort {
        "field" => Ok(Step::Field(parse_fexpr(value, &format!("{path}.value"))?)),
        "u64" => Ok(Step::U64(parse_u64expr(value, &format!("{path}.value"))?)),
        s => Err(format!("{path}.sort: unknown sort `{s}`")),
    }
}

pub fn parse_program(v: &Value) -> PResult<Program> {
    let m = obj(v, "$")?;
    let version = num(get(m, "version", "$")?, "$.version")?;
    if version != 1 {
        return Err(format!("$.version: unsupported wire version {version}"));
    }
    let local_length = idx(get(m, "localLength", "$")?, "$.localLength")?;
    let ops_v = get(m, "operations", "$")?
        .as_array()
        .ok_or_else(|| "$.operations: expected array".to_string())?;
    let mut ops = Vec::with_capacity(ops_v.len());
    for (i, op) in ops_v.iter().enumerate() {
        let path = format!("operations[{i}]");
        let om = obj(op, &path)?;
        if let Some(mv) = om.get("witness") {
            let m_cells = idx(mv, &format!("{path}.witness"))?;
            let code = obj(get(om, "code", &path)?, &format!("{path}.code"))?;
            let steps_v = get(code, "steps", &format!("{path}.code"))?
                .as_array()
                .ok_or_else(|| format!("{path}.code.steps: expected array"))?;
            let mut steps = Vec::with_capacity(steps_v.len());
            for (j, s) in steps_v.iter().enumerate() {
                steps.push(parse_step(s, &format!("{path}.code.steps[{j}]"))?);
            }
            let output = parse_vexpr(
                get(code, "output", &format!("{path}.code"))?,
                &format!("{path}.code.output"),
            )?;
            ops.push(Op::Witness {
                m: m_cells,
                steps,
                output,
            });
        } else if let Some(av) = om.get("assert") {
            ops.push(Op::Assert(parse_expr(av, &format!("{path}.assert"))?));
        } else if om.contains_key("lookup") {
            ops.push(Op::Lookup);
        } else if let Some(iv) = om.get("interact") {
            let im = obj(iv, &format!("{path}.interact"))?;
            let channel = get(im, "channel", &format!("{path}.interact"))?
                .as_str()
                .ok_or_else(|| format!("{path}.interact.channel: expected string"))?
                .to_string();
            let multiplicity = parse_expr(
                get(im, "multiplicity", &format!("{path}.interact"))?,
                &format!("{path}.interact.multiplicity"),
            )?;
            let msg_v = get(im, "message", &format!("{path}.interact"))?
                .as_array()
                .ok_or_else(|| format!("{path}.interact.message: expected array"))?;
            let mut message = Vec::with_capacity(msg_v.len());
            for (j, e) in msg_v.iter().enumerate() {
                message.push(parse_expr(e, &format!("{path}.interact.message[{j}]"))?);
            }
            ops.push(Op::Interact {
                channel,
                multiplicity,
                message,
            });
        } else {
            return Err(format!("{path}: unknown operation form"));
        }
    }
    Ok(Program { local_length, ops })
}

/// A parsed `<Chip>.rowmap.json`: the complete symbolic Rust row (the circuit output
/// pushed through the audited native→Rust layout map), one `Expression` per column.
#[derive(Debug, Clone)]
pub struct RowMap {
    pub rust_width: usize,
    pub row: Vec<Expr>,
}

pub fn parse_row_map(v: &Value) -> PResult<RowMap> {
    let m = obj(v, "$")?;
    let version = num(get(m, "wireVersion", "$")?, "$.wireVersion")?;
    if version != 1 {
        return Err(format!("$.wireVersion: unsupported wire version {version}"));
    }
    let rust_width = idx(get(m, "rustWidth", "$")?, "$.rustWidth")?;
    let row_v = get(m, "row", "$")?
        .as_array()
        .ok_or_else(|| "$.row: expected array".to_string())?;
    if row_v.len() != rust_width {
        return Err(format!(
            "$.row: length {} != rustWidth {rust_width}",
            row_v.len()
        ));
    }
    let mut row = Vec::with_capacity(row_v.len());
    for (i, e) in row_v.iter().enumerate() {
        row.push(parse_expr(e, &format!("row[{i}]"))?);
    }
    Ok(RowMap { rust_width, row })
}
