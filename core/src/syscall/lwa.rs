use std::process::exit;

use crate::runtime::{Register, Syscall, SyscallContext};

pub struct SyscallLWA;

impl Syscall for SyscallLWA {
    fn execute(&self, ctx: &mut SyscallContext) -> u32 {
        // TODO: in the future this will be used for private vs. public inputs.
        let a0 = Register::X10;
        let a1 = Register::X11;
        let _ = ctx.register_unsafe(a0);
        let num_bytes = ctx.register_unsafe(a1) as usize;
        let mut read_bytes = [0u8; 4];
        for i in 0..num_bytes {
            if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {
                tracing::error!(
                    "Not enough input words were passed in. Use --input to pass in more words."
                );
                exit(1);
            }
            read_bytes[i] = ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr];
            ctx.rt.state.input_stream_ptr += 1;
        }
        u32::from_le_bytes(read_bytes)
    }
}
