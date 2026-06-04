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
    ir::{
        refs_of_shape, BindId, ConstraintCompiler, ExprExtRef, ExprRef, Func, IrVar, LeanBinding,
        LeanComponents, Shape, SubCallTerm,
    },
};
use sp1_primitives::SP1Field;

type F = SP1Field;
/// Extension field matching the constraint compiler's internal `ExprExt` (see `ir::expr_impl`).
/// Only used to name the `Shape` type when composing a chip's column struct below; chip column
/// leaves are all base-field, so the extension parameter is never inspected.
type EF = BinomialExtensionField<SP1Field, 4>;

/// Map a runtime chip name to its concrete column-struct [`Shape`] (with `Main(i)` leaves),
/// reusing the `Into<Shape>` impl each `<Chip>Cols`/`<Chip>Columns` struct **derives**
/// (`#[derive(IntoShape)]`). For the two-parameter `<Chip>Cols<T, M: TrustMode>` column structs
/// that derive skips the mode-typed `adapter_cols : M::AdapterCols<T>` field (`EmptyCols` — zero
/// columns — under the `SupervisorMode` we extract at), exactly as the previous hand-written
/// `*_cols_shape` composers did. The nested operation/adapter column types (`CPUState`,
/// `RTypeReader`, `AddOperation`, …) already derive `IntoShape`, so the whole column tree is built
/// by the derives with no per-chip shape logic here.
///
/// The `chip_cols_shape!` table at the call site is the one declarative spot mapping each chip
/// name to its static column type — the same enumeration `RiscvAir` itself carries. Borrowing the
/// flat `Main(i)` column vector as the typed struct (via its derived `AlignedBorrow`) flattens to
/// column order, the invariant `Air::eval` relies on. Returns `None` for an unlisted chip.
macro_rules! chip_cols_shape {
    ($chip_name:expr, $main_vars:expr, { $($name:literal => $ty:ty),* $(,)? }) => {
        match $chip_name {
            $(
                $name => {
                    let cols: &$ty = $main_vars.as_slice().borrow();
                    Some((*cols).into())
                }
            )*
            _ => None,
        }
    };
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
            // Array-of-struct fields are flattened to `prefix_i` (matching the flattened struct
            // emission in `collect_struct_defs_skip` / `Shape::collect_lean_struct_defs`);
            // array-of-scalar keeps `prefix[i]`.
            let flatten = matches!(vals.first().map(|v| v.as_ref()), Some(Shape::Struct(..)));
            for (i, val) in vals.iter().enumerate() {
                let path = if flatten { format!("{prefix}_{i}") } else { format!("{prefix}[{i}]") };
                map_main(val, &path, out);
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
                // Flatten array-of-struct fields to `field_0 … field_{n-1}` (Clean's
                // `ProvableStruct` can't derive a `Vector (<NestedStruct> F) n` field); paths are
                // flattened to match in `map_main`. Array-of-scalar stays a `Vector`.
                match field.as_ref() {
                    Shape::Array(elems)
                        if matches!(elems.first().map(|e| e.as_ref()), Some(Shape::Struct(..))) =>
                    {
                        for (i, elem) in elems.iter().enumerate() {
                            def.push_str(&format!("  {field_name}_{i} : {}\n", elem.to_lean_type()));
                        }
                    }
                    _ => def.push_str(&format!("  {field_name} : {}\n", field.to_lean_type())),
                }
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

/// Dead-code-eliminate `bindings` for one emitted def: return, in original (topological) order,
/// only the bindings transitively reachable from `roots` via their `deps`. A `CallVal` header is
/// pulled in whenever one of its output leaves is reached. Guarantees the def carries no unused
/// `let` (Lean's `linter.unusedVariables` would otherwise fail the zero-warning build).
fn dce_filter<'a>(bindings: &'a [LeanBinding], roots: &[BindId]) -> Vec<&'a LeanBinding> {
    let by_id: HashMap<BindId, usize> =
        bindings.iter().enumerate().map(|(i, b)| (b.id, i)).collect();
    let mut reachable: HashSet<BindId> = HashSet::new();
    let mut worklist: Vec<BindId> = roots.to_vec();
    while let Some(id) = worklist.pop() {
        if !reachable.insert(id) {
            continue;
        }
        if let Some(&i) = by_id.get(&id) {
            worklist.extend(bindings[i].deps.iter().copied());
        }
    }
    bindings.iter().filter(|b| reachable.contains(&b.id)).collect()
}

/// The roots of an `asserts`/`interactions` def: the bindings read by its own list entries plus
/// those read by its sub-call argument terms.
fn list_roots(own: &[(String, Vec<BindId>)], subs: &[SubCallTerm]) -> Vec<BindId> {
    own.iter()
        .flat_map(|(_, d)| d.iter().copied())
        .chain(subs.iter().flat_map(|s| s.deps.iter().copied()))
        .collect()
}

/// Render the return expression of an `asserts`/`interactions` def: `Sub0.x … ++ Sub1.x … ++ [own…]`
/// (a bare `[own…]` when there are no sub-calls; an empty `[]` list when there are no own entries).
/// `Main[idx]` tokens are left in place for `emit_def` to substitute.
fn build_list_tail(subs: &[SubCallTerm], own: &[(String, Vec<BindId>)]) -> String {
    let mut s = String::new();
    for sub in subs {
        s.push_str(&sub.text);
        s.push_str(" ++ ");
    }
    s.push_str("[\n");
    for (own_str, _) in own {
        s.push_str(&format!("    {own_str},\n"));
    }
    s.push_str("  ]");
    s
}

/// Whether `name` occurs in `haystack` as a whole identifier token (not as a sub-token of a longer
/// identifier — so param `b` is *not* matched inside `cols.b_low_bytes` or `.byte`, but *is* matched
/// in `b[0]`). Used to decide which params a given def actually references.
fn token_present(haystack: &str, name: &str) -> bool {
    let bytes = haystack.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut from = 0;
    while let Some(pos) = haystack[from..].find(name) {
        let start = from + pos;
        let end = start + name.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Emit one `@[irreducible] def <name> {F}[Field F][CoeHead F ℕ] (<params>) : <ret_ty> :=` followed
/// by the DCE'd `let`-chain reachable from `roots`, then `tail`. `main_map` substitutes `Main[idx]`
/// column tokens (empty for operations). A param this def does not reference is rendered `_<name>` —
/// params are shared across the `asserts`/`interactions`/`value` defs and fixed by the call sites,
/// so (unlike `let`s) they can't be dropped; the `_` prefix keeps the zero-warning build.
#[allow(clippy::print_stdout)]
fn emit_def(
    name: &str,
    params: &[(String, String)],
    ret_ty: &str,
    bindings: &[LeanBinding],
    roots: &[BindId],
    tail: &str,
    main_map: &HashMap<usize, String>,
) {
    let kept = dce_filter(bindings, roots);
    let mapped_tail = apply_main_mapping(tail, main_map);
    // The text this def actually emits — to decide which params it references.
    let body: String = kept
        .iter()
        .map(|b| apply_main_mapping(&b.text, main_map))
        .chain(std::iter::once(mapped_tail.clone()))
        .collect::<Vec<_>>()
        .join("\n");

    println!("@[irreducible] def {name} {{F : Type}} [Field F] [CoeHead F ℕ]");
    for (pn, pt) in params {
        if token_present(&body, pn) {
            println!("  ({pn} : {pt})");
        } else {
            println!("  (_{pn} : {pt})");
        }
    }
    println!("  : {ret_ty} :=");
    for b in &kept {
        println!("  let {}", apply_main_mapping(&b.text, main_map));
    }
    println!("  {mapped_tail}");
}

/// Turn a `LeanBinding` text (`E5 : F := E4 * ((65536 : F)⁻¹)`) into a circuit-`main` `let` body:
/// drop the `: F` value annotation (the `main` lets infer `Expression (ZMod p)`) and rewrite the
/// inverse-constant's field token to `ZMod p`.
fn binding_to_let(text: &str) -> String {
    text.replacen(" : F := ", " := ", 1).replace(" : F)⁻¹)", " : ZMod p)⁻¹)")
}

/// Emit `def main (input : Var Inputs (ZMod p)) : Circuit (ZMod p) Unit := do …` for a byte-bus,
/// pure-assertion leaf operation: destructure each referenced `eval` param (`let a := input.a`), the
/// DCE'd `let` chain (the bindings reachable from the own asserts + byte sends), the byte sends
/// (`byteChannel.gatedReceive …`), then each own assert as `<expr> === 0`. The bindings are the same
/// `LeanComponents` the `asserts`/`interactions` defs render from; `binding_to_let` reshapes them.
#[allow(clippy::print_stdout)]
fn emit_main(comps: &LeanComponents, params: &[(String, String)]) {
    let mut roots: Vec<BindId> = Vec::new();
    for (_, d) in &comps.asserts {
        roots.extend(d.iter().copied());
    }
    for (_, d) in &comps.channel_calls {
        roots.extend(d.iter().copied());
    }
    let kept = dce_filter(&comps.bindings, &roots);

    // The text this `main` references, to decide which params to destructure — an unreferenced
    // `let p := input.p` would trip Lean's `linter.unusedVariables`, so a param the body never names
    // is simply not destructured.
    let body: String = kept
        .iter()
        .map(|b| binding_to_let(&b.text))
        .chain(comps.channel_calls.iter().map(|(s, _)| s.clone()))
        .chain(comps.asserts.iter().map(|(s, _)| format!("{s} === 0")))
        .collect::<Vec<_>>()
        .join("\n");

    println!("def main (input : Var Inputs (ZMod p)) : Circuit (ZMod p) Unit := do");
    for (pn, _) in params {
        if token_present(&body, pn) {
            println!("  let {pn} := input.{pn}");
        }
    }
    for b in &kept {
        println!("  let {}", binding_to_let(&b.text));
    }
    for (call, _) in &comps.channel_calls {
        println!("  {call}");
    }
    for (assert, _) in &comps.asserts {
        println!("  {assert} === 0");
    }
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Lean,
    /// The Clean-native circuit form of an operation: its `Inputs` struct (the `eval` params
    /// verbatim, the column struct nested as `cols`), the `main : Var Inputs → Circuit Unit`
    /// do-block (asserts as `=== 0`, byte sends as `byteChannel.gatedReceive`), and the
    /// `ElaboratedCircuit` instance + `@[circuit_norm]` rfl-lemmas. The faithful artifact the
    /// gadget's soundness/completeness run against directly (no separate `asserts`/`interactions`
    /// bridge). Only byte-bus, `Shape::Unit` (pure-assertion) leaf operations are supported.
    LeanCircuit,
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
            // One declarative row per chip: its name → its column struct. Each struct derives
            // `IntoShape`, so the `Shape` (and the whole nested column tree) is built by the
            // derives — no per-chip shape code. Full crate paths keep the import block small.
            type Sup = SupervisorMode;
            use sp1_core_machine as m;
            let cols_shape: Shape<ExprRef<F>, ExprExtRef<EF>> = chip_cols_shape!(
                chip_name, main_vars, {
                    "Add"         => AddCols<ExprRef<F>, Sup>,
                    "Sub"         => SubCols<ExprRef<F>, Sup>,
                    "Bitwise"     => BitwiseCols<ExprRef<F>, Sup>,
                    "Addi"        => m::alu::add_sub::addi::AddiCols<ExprRef<F>, Sup>,
                    "Addw"        => m::alu::add_sub::addw::AddwCols<ExprRef<F>, Sup>,
                    "Subw"        => m::alu::add_sub::subw::SubwCols<ExprRef<F>, Sup>,
                    "Lt"          => m::alu::lt::LtCols<ExprRef<F>, Sup>,
                    "Mul"         => m::alu::mul::MulCols<ExprRef<F>, Sup>,
                    "ShiftLeft"   => m::alu::sll::ShiftLeftCols<ExprRef<F>, Sup>,
                    "ShiftRight"  => m::alu::sr::ShiftRightCols<ExprRef<F>, Sup>,
                    "DivRem"      => m::alu::divrem::DivRemCols<ExprRef<F>, Sup>,
                    "Branch"      => m::control_flow::BranchColumns<ExprRef<F>, Sup>,
                    "Jal"         => m::control_flow::JalColumns<ExprRef<F>, Sup>,
                    "Jalr"        => m::control_flow::JalrColumns<ExprRef<F>, Sup>,
                    "UType"       => m::utype::UTypeColumns<ExprRef<F>, Sup>,
                    "LoadByte"    => m::memory::load::load_byte::LoadByteColumns<ExprRef<F>, Sup>,
                    "LoadHalf"    => m::memory::load::load_half::LoadHalfColumns<ExprRef<F>, Sup>,
                    "LoadWord"    => m::memory::load::load_word::LoadWordColumns<ExprRef<F>, Sup>,
                    "LoadDouble"  => m::memory::load::load_double::LoadDoubleColumns<ExprRef<F>, Sup>,
                    "LoadX0"      => m::memory::load::load_x0::LoadX0Columns<ExprRef<F>, Sup>,
                    "StoreByte"   => m::memory::store::store_byte::StoreByteColumns<ExprRef<F>, Sup>,
                    "StoreHalf"   => m::memory::store::store_half::StoreHalfColumns<ExprRef<F>, Sup>,
                    "StoreWord"   => m::memory::store::store_word::StoreWordColumns<ExprRef<F>, Sup>,
                    "StoreDouble" => m::memory::store::store_double::StoreDoubleColumns<ExprRef<F>, Sup>,
                }
            )
            .unwrap_or_else(|| {
                eprintln!(
                    "Error: Lean chip-struct extraction not implemented for chip '{}'",
                    chip_name
                );
                std::process::exit(1);
            });

            let struct_name = match &cols_shape {
                Shape::Struct(name, _) => name.clone(),
                _ => unreachable!("a chip column shape is always a struct"),
            };

            // Map each `Main(idx)` column to its field path within `cols`, then rewrite the
            // emitted (flat `Main[idx]`) constraints into named field accesses.
            let mut mapping = HashMap::new();
            map_main(&cols_shape, "cols", &mut mapping);

            let comps = builder.ast().to_lean_components(&Default::default());

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

            // A chip body is always `Shape::Unit` → no `value` def, just `asserts`/`interactions`.
            let params = vec![("cols".to_string(), cols_shape.to_lean_type())];

            emit_def(
                "asserts",
                &params,
                "List F",
                &comps.bindings,
                &list_roots(&comps.asserts, &comps.sub_asserts),
                &build_list_tail(&comps.sub_asserts, &comps.asserts),
                &mapping,
            );
            println!();
            emit_def(
                "interactions",
                &params,
                "List (Interaction F)",
                &comps.bindings,
                &list_roots(&comps.interactions, &comps.sub_interactions),
                &build_list_tail(&comps.sub_interactions, &comps.interactions),
                &mapping,
            );

            println!();
            println!("end {struct_name}");
            println!();
        }
        OutputFormat::LeanCircuit => {
            eprintln!(
                "Error: --format lean-circuit is operation-only (chips compose sub-circuits; not \
                 yet supported). Use --operation <Op>."
            );
            std::process::exit(1);
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
            let comps = operation.body.to_lean_components(&input_mapping);

            println!();

            // Emit the operation's column struct(s) (nested structs first) so the generated
            // module is self-contained. Structs named via `--reuse-struct` are provided by `import`
            // (a composing operation reuses the sub-operation's already-extracted column struct),
            // so they are skipped from emission.
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

            // Field-generic, clean-native params shared by the `asserts`/`interactions`/`value`
            // defs. `[CoeHead F ℕ]` (added per def in `emit_def`) backs the `ByteOpcode.ofNat`
            // coercion for dynamic opcodes (e.g. Bitwise). The `c` parameter is renamed to `cc`
            // (Mathlib pre-defines `c[i]`).
            let params: Vec<(String, String)> = operation
                .decl
                .input
                .iter()
                .map(|(pn, _, p)| {
                    (if pn == "c" { "cc".to_string() } else { pn.clone() }, p.to_lean_type())
                })
                .collect();
            let no_map: HashMap<usize, String> = HashMap::new();

            emit_def(
                "asserts",
                &params,
                "List F",
                &comps.bindings,
                &list_roots(&comps.asserts, &comps.sub_asserts),
                &build_list_tail(&comps.sub_asserts, &comps.asserts),
                &no_map,
            );
            println!();
            emit_def(
                "interactions",
                &params,
                "List (Interaction F)",
                &comps.bindings,
                &list_roots(&comps.interactions, &comps.sub_interactions),
                &build_list_tail(&comps.sub_interactions, &comps.interactions),
                &no_map,
            );

            // A value-returning operation also emits `value` (the deterministic output that was the
            // `.1` of the old pair return); `Shape::Unit` operations have none.
            if let Some(value_ty) = operation.decl.value_lean_type() {
                let mut value_roots: Vec<BindId> = Vec::new();
                refs_of_shape(&operation.decl.output, &mut value_roots);
                println!();
                emit_def(
                    "value",
                    &params,
                    &value_ty,
                    &comps.bindings,
                    &value_roots,
                    &operation.decl.output.to_lean_constructor(&input_mapping),
                    &no_map,
                );
            }

            println!();
            println!("end {operation_name}");
            println!();
        }
        OutputFormat::LeanCircuit => {
            // Same input mapping / components / params as `Lean`, rendered as a circuit `main` plus
            // its `Inputs` struct and `ElaboratedCircuit` instance instead of the two-list defs.
            let input_mapping: HashMap<usize, String> = operation
                .decl
                .input_mapping()
                .into_iter()
                .map(|(k, v)| (k, rename_c_to_cc(v)))
                .collect();
            let comps = operation.body.to_lean_components(&input_mapping);

            // Circuit emission is only sound for byte-bus, pure-assertion (`Shape::Unit`) leaves: a
            // value-returning op needs its `populate`/witness `main` (not present in `eval`); a
            // composed op needs subcircuit emission; a State/Memory/Program interaction needs its
            // channel. Bail loudly rather than emit wrong code.
            if !matches!(operation.decl.output, Shape::Unit) {
                eprintln!(
                    "Error: --format lean-circuit: '{operation_name}' returns a value (not \
                     Shape::Unit); only pure-assertion leaves are supported."
                );
                std::process::exit(1);
            }
            if !comps.sub_asserts.is_empty() || !comps.sub_interactions.is_empty() {
                eprintln!(
                    "Error: --format lean-circuit: '{operation_name}' composes sub-operations; \
                     subcircuit emission not yet supported."
                );
                std::process::exit(1);
            }
            if comps.channel_calls.len() != comps.interactions.len() {
                eprintln!(
                    "Error: --format lean-circuit: '{operation_name}' has non-byte interactions \
                     ({} of {} byte); only the byte bus is supported.",
                    comps.channel_calls.len(),
                    comps.interactions.len()
                );
                std::process::exit(1);
            }

            let params: Vec<(String, String)> = operation
                .decl
                .input
                .iter()
                .map(|(pn, _, p)| {
                    (if pn == "c" { "cc".to_string() } else { pn.clone() }, p.to_lean_type())
                })
                .collect();

            println!();
            // `Inputs`: the `eval` params verbatim (the column struct stays nested as `cols`,
            // resolved from the imported `Extracted.<Op>` module).
            println!("structure Inputs (F : Type) where");
            for (pn, pt) in &params {
                println!("  {pn} : {pt}");
            }
            println!("deriving ProvableStruct");
            println!();

            emit_main(&comps, &params);
            println!();

            // `ElaboratedCircuit` + the `@[circuit_norm]` rfl-lemmas; the omitted field obligations
            // close by Clean's default tactics. A pure-assertion leaf has `localLength 0` / `()` output.
            let chan_list = if comps.channel_calls.is_empty() {
                "[]"
            } else {
                "[byteChannel.toRaw]"
            };
            println!("instance elaborated : ElaboratedCircuit (ZMod p) Inputs unit where");
            println!("  name := \"SP1CleanNative.{operation_name}\"");
            println!("  main := main");
            println!("  localLength _ := 0");
            println!("  output _ _ := ()");
            println!("  channelsWithGuarantees := {chan_list}");
            println!("  channelsWithRequirements := {chan_list}");
            println!();
            for which in ["channelsWithGuarantees", "channelsWithRequirements"] {
                println!("set_option linter.unusedSectionVars false in");
                println!("@[circuit_norm] lemma {which}_eq :");
                println!(
                    "    (ElaboratedCircuit.{which} Inputs unit : List (RawChannel (ZMod p)))"
                );
                println!("      = {chan_list} := rfl");
            }
            println!("set_option linter.unusedSectionVars false in");
            println!("@[circuit_norm] lemma localLength_eq (x : Var Inputs (ZMod p)) :");
            println!("    (elaborated (p := p)).localLength x = 0 := rfl");
            println!();
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(operation).unwrap());
        }
    }
}
