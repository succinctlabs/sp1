use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use clap::Parser;
use curta::Args;
use curta_assembler::{parse_elf};

use curta_core::{
    program::{opcodes::Opcode, Instruction, Operands, ProgramROM, OPERAND_ELEMENTS},
    Runtime,
};
use std::{
    fs::File,
    io::{BufReader, Read, Write},
    path::Path,
};

pub fn load_program_rom(path: &Path) -> Result<ProgramROM<i32>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut instructions = Vec::new();

    while let Ok(opcode) = reader.read_u32::<LittleEndian>() {
        let mut operands_arr = [0i32; OPERAND_ELEMENTS];
        for i in 0..OPERAND_ELEMENTS {
            operands_arr[i] = reader.read_i32::<LittleEndian>()?;
        }
        let operands = Operands(operands_arr);
        instructions.push(Instruction {
            opcode: Opcode::from_u32(opcode),
            operands,
        });
    }

    Ok(ProgramROM(instructions))
}

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
    // I'm not sure if this output makes sense anymore since ELF is already machine code.
    let instructions = parse_elf(&elf_code).expect("Failed to assemble code");

    for instruction in instructions.iter() {
        println!("{:?}", instruction);
    }
    // let path = Path::new(&args.build_dir)
    //     .join(&args.program)
    //     .with_extension("bin");
    // File::create(&path)
    //     .expect("Failed to open output file")
    //     .write_all(&machine_code)
    //     .expect("Failed to write to output file");
    // let rom = load_program_rom(&path).expect("Failed to load program ROM");

    // // Print the program
    // println!("Machine code:");
    // for instruction in rom.0.iter() {
    //     println!("{}", instruction);
    // }

    // // Run the program
    // let mut rt = Runtime::new(rom, 1 << 30, 1 << 24);

    // rt.run().unwrap();
}
