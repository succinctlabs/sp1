use clap::{Parser, ValueEnum};
use slop_air::Air;
use sp1_core_machine::riscv::RiscvAirWithoutApcs;
use sp1_hypercube::{
    air::MachineAir,
    ir::{ConstraintCompiler, Shape},
};
use sp1_primitives::SP1Field;

type F = SP1Field;

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
}

#[allow(clippy::print_stdout)]
fn main() {
    let args = Args::parse();
    let _out_dir = args.out_dir;

    // Validate arguments and dispatch
    match (&args.chip, &args.operation) {
        (Some(chip_name), Some(operation_name)) => {
            // Both specified: compile specific operation from chip
            compile_operation(chip_name, operation_name, &args.format);
        }
        (Some(chip_name), None) => {
            // Only chip specified: compile entire chip
            compile_chip(chip_name, &args.format);
        }
        (None, Some(_)) => {
            eprintln!("Error: When using --operation, you must also specify --chip");
            eprintln!("Example: --chip Add --operation AddOperation");
            std::process::exit(1);
        }
        (None, None) => {
            eprintln!("Error: Must specify --chip (and optionally --operation)");
            std::process::exit(1);
        }
    }
}

#[allow(clippy::print_stdout)]
#[allow(clippy::uninlined_format_args)]
fn compile_chip(chip_name: &str, output_format: &OutputFormat) {
    let machine = RiscvAirWithoutApcs::<F>::machine();
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
            let input_mapping = Default::default();
            let (steps, constraints, num_calls) = builder.ast().to_lean_components(&input_mapping);

            println!();
            println!("-- Generated Lean code for chip {}Chip", chip_name);

            println!(
                "@[irreducible] def constraints (Main : Vector (Fin KB) {}) : SP1ConstraintList :=",
                builder.num_cols()
            );

            for step in steps {
                println!("  {}", step)
            }

            let calls_constraints: String = (0..num_calls).map(|i| format!("CS{i} ++ ")).collect();
            println!("  {calls_constraints}[");
            for constraint in constraints {
                println!("    {},", constraint);
            }
            println!("  ]");

            println!();
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&builder.ast()).unwrap());
        }
    }
}

#[allow(clippy::print_stdout)]
#[allow(clippy::uninlined_format_args)]
fn compile_operation(chip_name: &str, operation_name: &str, output_format: &OutputFormat) {
    // Step 1: Compile the chip normally to register all operations
    let machine = RiscvAirWithoutApcs::<F>::machine();
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
    match output_format {
        OutputFormat::Text => {
            println!("{}", operation);
        }
        OutputFormat::Lean => {
            let input_mapping = operation.decl.input_mapping();
            let (steps, constraints, num_calls) = operation.body.to_lean_components(&input_mapping);

            println!();

            println!("@[irreducible] def constraints");
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
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(operation).unwrap());
        }
    }
}
