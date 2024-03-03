use crate::runtime::{Register, Syscall, SyscallContext};

pub struct SyscallHalt;

impl SyscallHalt {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallHalt {
    fn execute(&self, ctx: &mut SyscallContext) -> u32 {
        let exit_code = ctx.register_unsafe(Register::X10);
        if ctx.rt.panic_on_halt && exit_code != 0 {
            panic!("program halted with non-zero exit code {}", exit_code);
        }
        ctx.set_next_pc(0);
        ctx.register_unsafe(Register::X10)
    }
}
