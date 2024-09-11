use super::{context::SyscallContext, Syscall, SyscallCode};

pub(crate) struct HaltSyscall;

impl Syscall for HaltSyscall {
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        _: SyscallCode,
        exit_code: u32,
        _: u32,
    ) -> Option<u32> {
        ctx.set_next_pc(0);
        ctx.set_exit_code(exit_code);
        None
    }
}
