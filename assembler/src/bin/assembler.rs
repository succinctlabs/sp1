use clap::{arg, command};
use curta_assembler::parse_elf;
use std::io::Read;


fn main() {
    let matches = command!()
        .arg(arg!(
            -i --input <FILE> "The input ELF file to parse"
        ))
        .get_matches();

    // Read elf code from input file.
    let mut elf_code = Vec::new();
    if let Some(filepath) = matches.get_one::<String>("input") {
        std::fs::File::open(filepath)
            .expect("Failed to open input file")
            .read_to_end(&mut elf_code)
            .expect("Failed to read from input file");
    }

    let instructions = parse_elf(&elf_code).expect("Failed to assemble code");
    for instruction in instructions.iter() {
        println!("{:?}", instruction);
    }
}
