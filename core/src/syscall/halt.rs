use crate::runtime::{Register, Syscall, SyscallContext};
use p3_field::PrimeField32;

pub struct SyscallHalt;

impl SyscallHalt {
    pub fn new() -> Self {
        Self
    }
}

impl<F: PrimeField32> Syscall<F> for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext<F>) -> u32 {
        ctx.set_next_pc(0);
        ctx.register_unsafe(Register::X10)
    }
}
