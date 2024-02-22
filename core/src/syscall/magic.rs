use crate::runtime::{Register, Syscall, SyscallContext};

pub struct SyscallMagicRead;

impl SyscallMagicRead {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallMagicRead {
    fn execute(&self, ctx: &mut SyscallContext) -> u32 {
        // TODO: in the future this will be used for private vs. public inputs.
        let a0 = Register::X10;
        let a1 = Register::X11;
        let _ = ctx.register_unsafe(a0);
        let (ptr, len) = *ctx
            .rt
            .state
            .magic_input_ptrs
            .get(ctx.rt.state.magic_input_read_count)
            .unwrap();
        ctx.rt.state.magic_input_read_count += 1;
        ctx.mw(a1 as u32, len as u32);
        ptr
    }
}
