#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let lui_value: u64;
    let auipc_value: u64;
    let _pc: u64;

    unsafe {
        core::arch::asm!(
            "lui {lui_value}, 0x80000",
            "auipc {auipc_value}, 0x80000",
            "auipc {pc}, 0",
            "sub {auipc_value}, {auipc_value}, {pc}",
            "addi {auipc_value}, {auipc_value}, 4",
            lui_value = out(reg) lui_value,
            auipc_value = out(reg) auipc_value,
            pc = out(reg) _pc,
            options(nostack),
        );
    }

    let values_are_equal = lui_value == auipc_value;
    sp1_zkvm::io::commit(&lui_value);
    sp1_zkvm::io::commit(&auipc_value);
    sp1_zkvm::io::commit(&values_are_equal);
}
