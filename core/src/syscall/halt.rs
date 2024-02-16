use crate::runtime::{Register, Syscall, SyscallContext};

pub struct SyscallHalt;

impl SyscallHalt {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext, _: u32, _: u32) -> Option<u32> {
        ctx.set_next_pc(0);
        Some(ctx.register_unsafe(Register::X10))
    }
}
