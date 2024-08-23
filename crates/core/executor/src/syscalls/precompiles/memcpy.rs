use std::marker::PhantomData;

use generic_array::ArrayLength;

use crate::events::MemCopyEvent;
use crate::syscalls::{Syscall, SyscallContext};
use crate::Register;

pub struct MemCopySyscall<NumWords: ArrayLength, NumBytes: ArrayLength> {
    _marker: PhantomData<(NumWords, NumBytes)>,
}

impl<NumWords: ArrayLength, NumBytes: ArrayLength> MemCopySyscall<NumWords, NumBytes> {
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }
}

#[inline]
fn floor_align(x: u32) -> u32 {
    (x >> 2) << 2
}
#[inline]
fn ceil_align(x: u32) -> u32 {
    floor_align(x + 3)
}

impl<NumWords: ArrayLength + Send + Sync, NumBytes: ArrayLength + Send + Sync> Syscall
    for MemCopySyscall<NumWords, NumBytes>
{
    // TODO check if im in unconstrained mode. if so, fix up memory access records.
    fn execute(&self, ctx: &mut SyscallContext, src: u32, dst: u32) -> Option<u32> {
        let a2 = Register::X12;
        let nbytes = ctx.rt.register(a2);
        // println!("start execute {src} {dst} {nbytes}");
        // From the assembly wrapper, dst must already be word aligned.

        // First, round up nbytes to the nearest word, and read that from src.

        let upper_bound = ceil_align(src + nbytes);
        let num_words = (upper_bound - floor_align(src)) / 4;
        let (mut reads, words) = ctx.mr_slice(floor_align(src), num_words as usize);

        let mut read_bytes = Vec::new();

        for word in words {
            // Convert u32 to little-endian bytes
            let bytes = word.to_le_bytes();
            // Extend the output vector with these bytes
            read_bytes.extend_from_slice(&bytes);
        }

        let start_idx = (src % 4) as usize;
        let end_addr = src + nbytes;
        let end_idx = read_bytes.len() - (floor_align(end_addr + 3) - end_addr) as usize;
        let read_bytes = read_bytes[start_idx..end_idx].to_vec();
        assert_eq!(read_bytes.len(), nbytes as usize);

        // If nbytes isn't a multiple of 4, we need to read an extra word for dest.
        let extra_word = if nbytes % 4 != 0 {
            let extra_word_addr = floor_align(dst + nbytes);
            // If we already read this byte, don't add another read record when we read it again
            if extra_word_addr >= floor_align(src) {
                Some(ctx.word_unsafe(extra_word_addr))
            } else {
                let (extra_read, word) = ctx.mr(extra_word_addr);
                reads.push(extra_read);
                Some(word)
            }
        } else {
            None
        };

        // We might write to the same word we read, so advance the clock.
        ctx.clk += 1;

        // Write as many words as we can to dst.

        let nwords = nbytes >> 2;
        let mut writes = Vec::new();
        for i in 0..nwords as usize {
            let word = u32::from_le_bytes(read_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let write = ctx.mw(dst + (i as u32) * 4, word);
            writes.push(write);
        }

        // If there are some extra bytes we need to write, write them now.

        if let Some(mut word) = extra_word {
            for i in 0..(nbytes % 4) as usize {
                word &= !(0xFF << (i * 8));
                word += (read_bytes[nwords as usize * 4 + i] as u32) << (i * 8);
            }

            let write = ctx.mw(dst + nwords * 4, word);

            writes.push(write);
        }

        // for i in 0..nbytes {
        //     assert_eq!(
        //         ctx.byte_unsafe(src + i),
        //         ctx.byte_unsafe(dst + i),
        //         "memcpy failed at byte {i}, dst word: {:X}",
        //         ctx.word_unsafe(dst - dst % 4),
        //     );
        // }

        let event = MemCopyEvent {
            lookup_id: ctx.syscall_lookup_id,
            shard: ctx.current_shard(),
            channel: ctx.current_channel(),
            clk: ctx.clk,
            src_ptr: src,
            dst_ptr: dst,
            read_records: reads,
            write_records: writes,
        };

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
