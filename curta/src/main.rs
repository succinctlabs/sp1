use clap::Parser;
use curta::Args;
use curta_core::runtime::Program;
use curta_core::runtime::Runtime;

use std::{io::Read, path::Path};

fn main() {
    let args = Args::parse();

    // Read elf code from input file, or from stdin if no file is specified
    let mut elf_code = Vec::new();
    let path = Path::new(&args.src_dir)
        .join(&args.program)
        .with_extension("s");
    std::fs::File::open(path)
        .expect("Failed to open input file")
        .read_to_end(&mut elf_code)
        .expect("Failed to read from input file");

    // Parse ELF code.
    let instructions = parse_elf(&elf_code).expect("Failed to assemble code");
    for instruction in instructions.0.iter() {
        println!("{:?}", instruction);
    }
    let program = Program::new(instructions.0, instructions.1, 0);
    let mut runtime = Runtime::new(program);
    println!("initial pc: {:?}", instructions.1);
    runtime.run();

    println!("{:?}", runtime.registers());
}
