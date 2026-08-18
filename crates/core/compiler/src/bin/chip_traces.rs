//! Thin CLI over `sp1_constraint_compiler::conformance`: dump deterministic
//! per-chip traces (events + records + full padded rows) as JSON. See the library
//! module for the battery construction, invariants, and the dump schema.

use clap::Parser;
use sp1_constraint_compiler::conformance::{run_elf, run_synthetic, CHIPS};

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
