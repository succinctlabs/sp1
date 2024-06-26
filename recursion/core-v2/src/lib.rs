use sp1_core::stark::MachineRecord;

mod add;

struct Address;

struct BinOp {
    arg1: Address,
    arg2: Address,
    dest: Address,
}

enum Opcode {
    Add(BinOp),
    Mul(BinOp),
}
