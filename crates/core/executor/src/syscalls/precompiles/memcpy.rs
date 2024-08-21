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

        // let mut to_read = nbytes;

        // let mut reads = vec![];
        // let mut writes = vec![];
        // let mut src_ptr = src;
        // let mut dst_ptr = dst;

        // let mut begin_bytes = vec![];

        // // Read the word I start in the middle of.
        // if src_ptr % 4 != 0 {
        //     let (read, word) = ctx.mr(src_ptr - src_ptr % 4);
        //     reads.push(read);

        //     let bytes = word.to_le_bytes().as_slice();
        //     for i in 0..src_ptr % 4 {
        //         begin_bytes.push(bytes[i as usize]);
        //     }

        //     to_read -= (src_ptr % 4) as usize;
        //     src_ptr += 4 - (src_ptr % 4);
        // }
        // // Read as much as I can in 4-byte chunks.

        // let (mut read, main_bytes) = ctx.mr_slice(src_ptr, to_read >> 2);
        // to_read -= (to_read >> 2) << 2;
        // src_ptr += (to_read as u32 >> 2) << 2;
        // reads.append(&mut read);

        // // Read anything that's left.
        // let mut end_bytes = vec![];
        // if src_ptr % 4 != 0 && nbytes >= 0 {
        //     let (read, word) = ctx.mr(src_ptr - src_ptr % 4);
        //     reads.push(read);
        //     let bytes = word.to_le_bytes().as_slice();
        //     for i in 0..src_ptr % 4 {
        //         end_bytes.push(bytes[3 - i as usize]);
        //     }
        // }

        // Write

        let (read, read_bytes) = ctx.mr_slice(src, nbytes >> 2);
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
