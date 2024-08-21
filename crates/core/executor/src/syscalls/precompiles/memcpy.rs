use std::marker::PhantomData;

use generic_array::ArrayLength;

use crate::events::MemCopyEvent;
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};

pub struct MemCopySyscall<NumWords: ArrayLength, NumBytes: ArrayLength> {
    _marker: PhantomData<(NumWords, NumBytes)>,
}

impl<NumWords: ArrayLength, NumBytes: ArrayLength> MemCopySyscall<NumWords, NumBytes> {
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

impl<NumWords: ArrayLength + Send + Sync, NumBytes: ArrayLength + Send + Sync> Syscall
    for MemCopySyscall<NumWords, NumBytes>
{
    fn execute(&self, ctx: &mut SyscallContext, src: u32, dst: u32) -> Option<u32> {
        let (read, read_bytes) = ctx.mr_slice(src, NumWords::USIZE);
        let write = ctx.mw_slice(dst, &read_bytes);

        let event = MemCopyEvent {
            lookup_id: ctx.syscall_lookup_id,
            shard: ctx.current_shard(),
            channel: ctx.current_channel(),
            clk: ctx.clk,
            src_ptr: src,
            dst_ptr: dst,
            read_records: read,
            write_records: write,
        };
        (match NumWords::USIZE {
            8 => &mut ctx.record_mut().memcpy32_events,
            16 => &mut ctx.record_mut().memcpy64_events,
            _ => panic!("invalid usize {}", NumWords::USIZE),
        })
        .push(event);

        None
    }
}
