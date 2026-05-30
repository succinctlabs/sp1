use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap, HashSet},
};

use clap::{Parser, ValueEnum};
use slop_air::Air;
use slop_algebra::extension::BinomialExtensionField;
use sp1_core_machine::{
    alu::{add_sub::add::AddCols, add_sub::sub::SubCols, bitwise::BitwiseCols},
    riscv::RiscvAir,
    SupervisorMode,
};
use sp1_hypercube::{
    air::MachineAir,
    ir::{ConstraintCompiler, ExprExtRef, ExprRef, Func, IrVar, Shape},
};
use sp1_primitives::SP1Field;

type F = SP1Field;
/// Extension field matching the constraint compiler's internal `ExprExt` (see `ir::expr_impl`).
/// Only used to name the `Shape` type when composing a chip's column struct below; chip column
/// leaves are all base-field, so the extension parameter is never inspected.
type EF = BinomialExtensionField<SP1Field, 4>;

/// Compose a chip's column-struct [`Shape`] (with `Main(i)` leaves) from its concrete column
/// type, reusing the `Into<Shape>` impls the nested operation column types already derive
/// (`CPUState`, `RTypeReader`, `AddOperation`), plus `From<ExprRef>` for the scalar `is_real`.
///
/// We compose here in the compiler crate rather than `#[derive(IntoShape)]` on `AddCols<T, M>`
/// because that derive needs a single generic parameter and cannot reason about the
/// associated-type field `adapter_cols : M::AdapterCols<T>`. For `SupervisorMode` those adapter
/// columns are `EmptyCols` (zero columns), so the field is simply omitted.
fn add_cols_shape(cols: &AddCols<ExprRef<F>, SupervisorMode>) -> Shape<ExprRef<F>, ExprExtRef<EF>> {
    Shape::Struct(
        "AddCols".to_string(),
        vec![
            ("state".to_string(), Box::new(cols.state.into())),
            ("adapter".to_string(), Box::new(cols.adapter.into())),
            ("add_operation".to_string(), Box::new(cols.add_operation.into())),
            ("is_real".to_string(), Box::new(cols.is_real.into())),
        ],
    )
}

/// Compose `SubCols`'s column-struct [`Shape`]. Structurally identical to [`add_cols_shape`]
/// (same `state`/`adapter`/`is_real`), with the operation field renamed `sub_operation`.
fn sub_cols_shape(cols: &SubCols<ExprRef<F>, SupervisorMode>) -> Shape<ExprRef<F>, ExprExtRef<EF>> {
    Shape::Struct(
        "SubCols".to_string(),
        vec![
            ("state".to_string(), Box::new(cols.state.into())),
            ("adapter".to_string(), Box::new(cols.adapter.into())),
            ("sub_operation".to_string(), Box::new(cols.sub_operation.into())),
            ("is_real".to_string(), Box::new(cols.is_real.into())),
        ],
    )
}

/// Compose `BitwiseCols`'s column-struct [`Shape`]. Like [`add_cols_shape`] but with the
/// `ALUTypeReader` adapter, the (nested) `BitwiseU16Operation` operation columns, and three
/// boolean opcode selectors (`is_xor`/`is_or`/`is_and`) in place of a single `is_real`.
fn bitwise_cols_shape(
    cols: &BitwiseCols<ExprRef<F>, SupervisorMode>,
) -> Shape<ExprRef<F>, ExprExtRef<EF>> {
    Shape::Struct(
        "BitwiseCols".to_string(),
        vec![
            ("state".to_string(), Box::new(cols.state.into())),
            ("adapter".to_string(), Box::new(cols.adapter.into())),
            ("bitwise_operation".to_string(), Box::new(cols.bitwise_operation.into())),
            ("is_xor".to_string(), Box::new(cols.is_xor.into())),
            ("is_or".to_string(), Box::new(cols.is_or.into())),
            ("is_and".to_string(), Box::new(cols.is_and.into())),
        ],
    )
}

/// Build the `Main(idx) → field path` map for a chip's column shape (e.g. `Main(28)` →
/// `cols.add_operation.value[0]`). Local analogue of `Shape::map_input`, matching `IrVar::Main`
/// rather than `InputArg`; lives here so no code outside the constraint-extractor package
/// changes.
fn map_main(
    shape: &Shape<ExprRef<F>, ExprExtRef<EF>>,
    prefix: &str,
    out: &mut HashMap<usize, String>,
) {
    match shape {
        Shape::Expr(ExprRef::IrVar(IrVar::Main(idx))) => {
            out.insert(*idx, prefix.to_string());
        }
        Shape::Word(vals) => {
            for (i, val) in vals.iter().enumerate() {
                if let ExprRef::IrVar(IrVar::Main(idx)) = val {
                    out.insert(*idx, format!("{prefix}[{i}]"));
                }
            }
        }
        Shape::Array(vals) => {
            for (i, val) in vals.iter().enumerate() {
                map_main(val, &format!("{prefix}[{i}]"), out);
            }
        }
        Shape::Struct(_, fields) => {
            for (name, field) in fields {
                map_main(field, &format!("{prefix}.{name}"), out);
            }
        }
        _ => {}
    }
}

/// Local analogue of `Shape::collect_lean_struct_defs` that skips struct names provided
/// externally (a chip reusing an already-extracted operation's struct via `import`): such a
/// struct is neither emitted nor recursed into. `to_lean_type` still renders the field type as
/// `(<name> F)`, so the containing struct references it by name.
fn collect_struct_defs_skip(
    shape: &Shape<ExprRef<F>, ExprExtRef<EF>>,
    out: &mut Vec<(String, String)>,
    skip: &HashSet<String>,
) {
    match shape {
        Shape::Struct(name, fields) => {
            if skip.contains(name) {
                return;
            }
            for (_, field) in fields {
                collect_struct_defs_skip(field, out, skip);
            }
            if out.iter().any(|(n, _)| n == name) {
                return;
            }
            let mut def = format!("structure {name} (F : Type) where\n");
            for (field_name, field) in fields {
                def.push_str(&format!("  {field_name} : {}\n", field.to_lean_type()));
            }
            def.push_str("deriving ProvableStruct\n");
            out.push((name.clone(), def));
        }
        Shape::Array(elems) => {
            for e in elems {
                collect_struct_defs_skip(e, out, skip);
            }
        }
        _ => {}
    }
}

/// Rename a `c`-parameter leaf path to `cc` (matching the signature's `c → cc` rename). Only the
/// exact `c` token — alone, or followed by `[` (array index) or `.` (field) — is renamed, so
/// `cols.…` is left untouched.
fn rename_c_to_cc(path: String) -> String {
    if path == "c" {
        "cc".to_string()
    } else if let Some(rest) = path.strip_prefix("c[") {
        format!("cc[{rest}")
    } else if let Some(rest) = path.strip_prefix("c.") {
        format!("cc.{rest}")
    } else {
        path
    }
}

/// Substitute every `Main[idx]` token in an emitted Lean line with its mapped field path.
/// The trailing `]` makes each `Main[i]` token unambiguous (`Main[3]` is not a substring of
/// `Main[32]`), so order-independent string replacement is safe.
fn apply_main_mapping(line: &str, mapping: &HashMap<usize, String>) -> String {
    let mut out = line.to_string();
    for (idx, path) in mapping {
        out = out.replace(&format!("Main[{idx}]"), path);
    }
    out
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Lean,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long, help = "Chip name to compile")]
    pub chip: Option<String>,

    #[arg(long, help = "Operation name to compile")]
    pub operation: Option<String>,

    #[arg(long, default_value = "target/constraints/")]
    pub out_dir: String,

    #[arg(long, value_enum, default_value = "text", help = "Output format")]
    pub format: OutputFormat,

    #[arg(
        long = "reuse-struct",
        help = "Struct name(s) reused from an already-extracted module (provided by `import` \
                rather than re-emitted). Repeatable. Affects both chip and operation Lean \
                extraction (a skipped struct is neither emitted nor recursed into)."
    )]
    pub reuse_struct: Vec<String>,
}

#[allow(clippy::print_stdout)]
fn main() {
    let args = Args::parse();
    let _out_dir = args.out_dir;

    // Validate arguments and dispatch
    match (&args.chip, &args.operation) {
        (Some(chip_name), Some(operation_name)) => {
            // Both specified: compile a specific operation as registered by the given chip.
            compile_operation(chip_name, operation_name, &args.format, &args.reuse_struct);
        }
        (Some(chip_name), None) => {
            // Only chip specified: compile entire chip
            compile_chip(chip_name, &args.format, &args.reuse_struct);
        }
        (None, Some(operation_name)) => {
            // Only operation specified: extract it without naming a chip, by unioning the
            // operation modules registered across every `RiscvAir` chip.
            compile_operation_standalone(operation_name, &args.format, &args.reuse_struct);
        }
        (None, None) => {
            eprintln!("Error: Must specify --chip (and optionally --operation)");
            std::process::exit(1);
        }
    }
}

#[allow(clippy::print_stdout)]
#[allow(clippy::uninlined_format_args)]
fn compile_chip(chip_name: &str, output_format: &OutputFormat, reuse_struct: &[String]) {
    let machine = RiscvAir::<F>::machine();
    let chip =
        machine.chips().iter().find(|c| c.name() == chip_name).cloned().unwrap_or_else(|| {
            eprintln!("Error: Chip '{}' not found", chip_name);
            eprintln!("Available chips:");
            for chip in machine.chips() {
                eprintln!("  {}", chip.name());
            }
            std::process::exit(1);
        });
    let air = chip.air.clone();

    let num_public_values = machine.num_pv_elts();
    let mut builder = ConstraintCompiler::new(air.as_ref(), num_public_values);

    air.eval(&mut builder);

    match output_format {
        OutputFormat::Text => {
            let ast = builder.ast();
            let ast_str = ast.to_string_pretty("   ");
            println!("Constraints for chip {chip_name} (main):");
            println!("{ast_str}");

            for func in builder.modules().values() {
                println!("{func}");
            }
        }
        OutputFormat::Lean => {
            // Compose the chip's column-struct shape with `Main(i)` leaves. Building the
            // `(0..width)` `Main` exprs and borrowing them as the typed column struct (via the
            // struct's `AlignedBorrow` impl) flattens to exactly column order, the same
            // invariant `Air::eval` relies on. Dispatch per chip since the column type is only
            // known statically.
            let width = builder.num_cols();
            let main_vars: Vec<ExprRef<F>> = (0..width).map(ExprRef::main).collect();
            let cols_shape: Shape<ExprRef<F>, ExprExtRef<EF>> = match chip_name {
                "Add" => {
                    let cols: &AddCols<ExprRef<F>, SupervisorMode> = main_vars.as_slice().borrow();
                    add_cols_shape(cols)
                }
                "Sub" => {
                    let cols: &SubCols<ExprRef<F>, SupervisorMode> = main_vars.as_slice().borrow();
                    sub_cols_shape(cols)
                }
                "Bitwise" => {
                    let cols: &BitwiseCols<ExprRef<F>, SupervisorMode> =
                        main_vars.as_slice().borrow();
                    bitwise_cols_shape(cols)
                }
                _ => {
                    eprintln!(
                        "Error: Lean chip-struct extraction not implemented for chip '{}'",
                        chip_name
                    );
                    std::process::exit(1);
                }
            };

            let struct_name = match &cols_shape {
                Shape::Struct(name, _) => name.clone(),
                _ => unreachable!("a chip column shape is always a struct"),
            };

            // Map each `Main(idx)` column to its field path within `cols`, then rewrite the
            // emitted (flat `Main[idx]`) constraints into named field accesses.
            let mut mapping = HashMap::new();
            map_main(&cols_shape, "cols", &mut mapping);

            let (steps, constraints, num_calls) =
                builder.ast().to_lean_components(&Default::default());

            println!();
            println!("-- Generated Lean code for chip {}Chip", chip_name);
            println!();

            // Emit the chip's column struct(s), skipping reused (already-extracted) operation
            // structs — those are provided by `import` in the generated module's header.
            let skip: HashSet<String> = reuse_struct.iter().cloned().collect();
            let mut struct_defs: Vec<(String, String)> = Vec::new();
            collect_struct_defs_skip(&cols_shape, &mut struct_defs, &skip);
            for (_, def) in &struct_defs {
                println!("{def}");
            }

            println!("namespace {struct_name}");
            println!();
            println!("@[irreducible] def constraints {{F : Type}} [Field F] [CoeHead F ℕ]");
            println!("  (cols : {})", cols_shape.to_lean_type());
            println!("  : SP1ConstraintList F :=");

            for step in steps {
                println!("  {}", apply_main_mapping(&step, &mapping));
            }

            let calls_constraints: String = (0..num_calls).map(|i| format!("CS{i} ++ ")).collect();
            println!("  {calls_constraints}[");
            for constraint in constraints {
                println!("    {},", apply_main_mapping(&constraint, &mapping));
            }
            println!("  ]");

            println!();
            println!("end {struct_name}");
            println!();
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&builder.ast()).unwrap());
        }
    }
}

#[allow(clippy::print_stdout)]
#[allow(clippy::uninlined_format_args)]
fn compile_operation(
    chip_name: &str,
    operation_name: &str,
    output_format: &OutputFormat,
    reuse_struct: &[String],
) {
    // Step 1: Compile the chip normally to register all operations
    let machine = RiscvAir::<F>::machine();
    let air = machine
        .chips()
        .iter()
        .find(|c| c.name() == chip_name)
        .cloned()
        .unwrap_or_else(|| {
            eprintln!("Error: Chip '{}' not found", chip_name);
            eprintln!("Available chips:");
            for chip in machine.chips() {
                eprintln!("  {}", chip.name());
            }
            std::process::exit(1);
        })
        .air
        .clone();

    let num_public_values = machine.num_pv_elts();
    let mut builder = ConstraintCompiler::new(air.as_ref(), num_public_values);

    // Step 2: Evaluate the chip (this registers all operations in modules)
    air.eval(&mut builder);

    // Step 3: Extract only the requested operation
    let operation = builder.modules().get(operation_name).unwrap_or_else(|| {
        eprintln!("Error: Operation '{}' not found in chip '{}'", operation_name, chip_name);
        eprintln!("Available operations in this chip:");
        for name in builder.modules().keys() {
            eprintln!("  {}", name);
        }
        std::process::exit(1);
    });

    // Step 4: Generate output for just this operation
    emit_operation(operation, operation_name, output_format, reuse_struct);
}

/// Extract a single operation by name **without** naming a chip. Builds the union of operation
/// modules registered across every `RiscvAir` chip (operation module registration is chip
/// independent — see [`all_operation_modules`]), then emits the requested one. This lets callers
/// feed a flat list of operation names rather than `(chip, operation)` pairs.
#[allow(clippy::print_stdout)]
fn compile_operation_standalone(
    operation_name: &str,
    output_format: &OutputFormat,
    reuse_struct: &[String],
) {
    let modules = all_operation_modules();
    let operation = modules.get(operation_name).unwrap_or_else(|| {
        eprintln!("Error: Operation '{operation_name}' not found");
        eprintln!("Available operations:");
        for name in modules.keys() {
            eprintln!("  {name}");
        }
        std::process::exit(1);
    });

    emit_operation(operation, operation_name, output_format, reuse_struct);
}

/// Collect every operation module registered across all `RiscvAir` chips, keyed by operation name.
///
/// An operation's module is synthesized from its input *types* (not a chip's concrete values), so
/// the module a chip registers for a given operation is identical regardless of which chip drives
/// it. We therefore union the modules from each chip's evaluation. `or_insert` keeps the result
/// deterministic: when two operations register under the same name (e.g. `RTypeReader` and
/// `RTypeReaderImmutable` both register `"RTypeReader"`), the first chip in `machine.chips()` order
/// wins.
fn all_operation_modules() -> BTreeMap<String, Func<ExprRef<F>, ExprExtRef<EF>>> {
    let machine = RiscvAir::<F>::machine();
    let num_public_values = machine.num_pv_elts();

    let mut union: BTreeMap<String, Func<ExprRef<F>, ExprExtRef<EF>>> = BTreeMap::new();
    for chip in machine.chips() {
        let air = chip.air.clone();
        let mut builder = ConstraintCompiler::new(air.as_ref(), num_public_values);
        air.eval(&mut builder);
        for (name, func) in builder.modules() {
            union.entry(name.clone()).or_insert_with(|| func.clone());
        }
    }
    union
}

/// Emit a single operation's Lean (or text/json) representation: a self-contained column struct
/// followed by its `constraints` def. Shared by the chip-scoped (`--chip C --operation Op`) and
/// standalone (`--operation Op`) extraction paths.
#[allow(clippy::print_stdout)]
#[allow(clippy::uninlined_format_args)]
fn emit_operation(
    operation: &Func<ExprRef<F>, ExprExtRef<EF>>,
    operation_name: &str,
    output_format: &OutputFormat,
    reuse_struct: &[String],
) {
    match output_format {
        OutputFormat::Text => {
            println!("{}", operation);
        }
        OutputFormat::Lean => {
            // The `c` parameter is emitted as `cc` in the signature (Mathlib pre-defines `c[i]`);
            // rename the matching leaves in the body's input mapping so they agree. Only the exact
            // `c` token (followed by `[`, `.`, or end-of-path) is renamed — never `cols`.
            let input_mapping: HashMap<usize, String> = operation
                .decl
                .input_mapping()
                .into_iter()
                .map(|(k, v)| (k, rename_c_to_cc(v)))
                .collect();
            let (steps, constraints, num_calls) = operation.body.to_lean_components(&input_mapping);

            println!();

            // Emit the operation's column struct(s) (nested structs first) so the generated
            // module is self-contained: struct definition(s) followed by `constraints`. Structs
            // named via `--reuse-struct` are provided by `import` (an operation composing a
            // sub-operation reuses the sub-operation's already-extracted column struct), so they
            // are skipped from emission.
            let skip: HashSet<String> = reuse_struct.iter().cloned().collect();
            let mut struct_defs: Vec<(String, String)> = Vec::new();
            for (_, _, param) in &operation.decl.input {
                param.collect_lean_struct_defs(&mut struct_defs);
            }
            for (name, def) in &struct_defs {
                if !skip.contains(name) {
                    println!("{def}");
                }
            }

            println!("namespace {operation_name}");
            println!();

            // Field-generic, clean-native header. `[CoeHead F ℕ]` backs the `ByteOpcode.ofNat`
            // coercion for dynamic opcodes (e.g. Bitwise); harmless for constant-opcode ops.
            println!("@[irreducible] def constraints {{F : Type}} [Field F] [CoeHead F ℕ]");
            for (param_name, _, param) in &operation.decl.input {
                println!(
                    "  ({} : {})",
                    // In Mathlib, c[i] is pre-defined...
                    if param_name == "c" { "cc" } else { param_name },
                    param.to_lean_type()
                );
            }

            println!("  : {} :=", operation.decl.to_output_lean_type());

            for step in steps {
                println!("  {}", step)
            }

            let calls_constraints: String = (0..num_calls).map(|i| format!("CS{i} ++ ")).collect();
            match operation.decl.output {
                Shape::Unit => {
                    println!("  {calls_constraints}[");
                    for constraint in constraints {
                        println!("    {},", constraint);
                    }
                    println!("  ]");
                }
                _ => {
                    println!(
                        "  ⟨{}, {calls_constraints}[",
                        operation.decl.output.to_lean_constructor(&input_mapping)
                    );
                    for constraint in constraints {
                        println!("    {},", constraint);
                    }
                    println!("  ]⟩");
                }
            }

            println!();
            println!("end {operation_name}");
            println!();
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(operation).unwrap());
        }
    }
}
