use byteorder::{LittleEndian, ReadBytesExt};
use clap::{arg, command};
use curta_assembler::parse_elf;
use curta_core::program::opcodes::Opcode;
use curta_core::program::{Instruction, Operands, ProgramROM};
use std::fs::File;
use std::io::{self, BufReader, Read, Write};

use anyhow::Result;

const OPERAND_ELEMENTS: usize = 5;

fn load_program_rom(filename: &str) -> Result<ProgramROM<i32>> {
    let file = File::open(filename)?;
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
    // TODO: Do I need an output file?
    let matches = command!()
        .arg(arg!(
            -i --input <FILE> "The input ELF file to parse"
        ))
        .arg(arg!(
            -o --output <FILE> "The machine code output file"
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

    // Write machine code to file, or stdout if no file is specified
    // Although I'm not sure whether this makes sense anymore, ELF code is machine code.
    let _instructions = parse_elf(&elf_code).expect("Failed to parse elf code");
//    if let Some(filepath) = matches.get_one::<String>("output") {
//        File::create(filepath)
//            .expect("Failed to open output file")
//            .write_all(&machine_code)
//            .expect("Failed to write to output file");
//        let rom = load_program_rom(filepath).expect("Failed to load program ROM");
//        for instruction in rom.0.iter() {
//            println!("{}", instruction);
//        }
//    } else {
//        io::stdout()
//            .write_all(&machine_code)
//            .expect("Failed to write to stdout");
//    }
}
