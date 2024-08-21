use std::marker::PhantomData;

use generic_array::ArrayLength;
use num::traits::ToBytes;

use crate::events::MemCopyEvent;
use crate::syscalls::{Syscall, SyscallCode, SyscallContext};
use crate::Register;

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
        let a2 = Register::X12;
        let nbytes = ctx.rt.register(a2) as usize;

        // println!("clk before {}", ctx.clk);

        let (read, read_bytes) = ctx.mr_slice(src, nbytes >> 2);
        let write = ctx.mw_slice(dst, &read_bytes);

        // let mut read = Vec::new();
        // let mut write = Vec::new();
        // let mut bytes = Vec::new();

        // for i in 0..nbytes {
        //     // let (r, b) = ctx.mr_byte(src + i as u32);
        //     // read.push(r);
        //     // bytes.push(b);
        //     let b = ctx.byte_unsafe(src + i as u32);
        //     bytes.push(b);
        // }

        // for i in 0..nbytes {
        //     let w = ctx.mw_byte(dst + i as u32, bytes[i]);
        //     write.push(w);
        // }

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

        // println!("clk after {}", ctx.clk);

        None
    }
}
