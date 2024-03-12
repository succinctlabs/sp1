use std::process::exit;

use crate::runtime::{Syscall, SyscallContext};

pub struct SyscallLWA;

impl SyscallLWA {
    pub fn new() -> Self {
        Self
    }
}

impl Syscall for SyscallLWA {
    fn execute(&self, ctx: &mut SyscallContext, arg1: u32, arg2: u32) -> Option<u32> {
        // TODO: in the future arg1 will be used for public/private inputs.
        let _ = arg1;
        let num_bytes = arg2;
        let mut read_bytes = [0u8; 4];
        for i in 0..num_bytes {
            if ctx.rt.state.input_stream_ptr >= ctx.rt.state.input_stream.len() {
                tracing::error!(
                    "Not enough input words were passed in. Use --input to pass in more words."
                );
                exit(1);
            }
            read_bytes[i as usize] = ctx.rt.state.input_stream[ctx.rt.state.input_stream_ptr];
            ctx.rt.state.input_stream_ptr += 1;
        }
        Some(u32::from_le_bytes(read_bytes))
    }
}
