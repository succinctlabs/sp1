mod air;
pub mod columns;
mod trace;

#[derive(Default)]
pub struct Blake2fCompressChip;

impl Blake2fCompressChip {
    pub const fn new() -> Self {
        Self {}
    }
}

#[cfg(test)]
pub mod tests {

    use sp1_core_executor::{syscalls::SyscallCode, Instruction, Opcode, Program};
    use sp1_stark::CpuProver;
    use test_artifacts::BLAKE2F_COMPRESS_ELF;
    use sp1_core_executor::Executor;
    use sp1_stark::SP1CoreOpts;

    use crate::{
        io::SP1Stdin,
        utils::{run_test, setup_logger},
    };

    #[test]
    fn test_blake2f_compress_program() {
        setup_logger();
        let program = Program::from(BLAKE2F_COMPRESS_ELF).unwrap();
        let mut runtime = Executor::new(program, SP1CoreOpts::default());
        runtime.run().unwrap();
    }
}