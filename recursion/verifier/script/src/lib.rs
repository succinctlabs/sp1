use sp1_core::runtime::Instruction;
use sp1_core::runtime::Opcode;
use sp1_core::runtime::Program;
use sp1_core::utils::BabyBearBlake3;
use sp1_core::SP1ProofWithIO;

pub fn get_fixture_proof() -> SP1ProofWithIO<BabyBearBlake3> {
    let proof_str = include_str!("./fixtures/fib-proof-with-pis.json");
    println!("cycle-tracker-start: deserialize proof");

    serde_json::from_str(proof_str).expect("loading proof failed")
}

pub fn get_program() -> Program {
    simple_program()
}

#[allow(dead_code)]
fn simple_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
        Instruction::new(Opcode::ADD, 30, 0, 37, false, true),
        Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
    ];
    Program::new(instructions, 0, 0)
}

#[allow(dead_code)]
fn add_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 29, 0, 5, false, true),
        Instruction::new(Opcode::ADD, 30, 0, 8, false, true),
        Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
    ];
    Program::new(instructions, 0, 0)
}
