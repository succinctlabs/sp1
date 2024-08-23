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
        let a3 = Register::X13;

        let (nbytes_record, nbytes) = ctx.mr(a2 as u32);
        let (src_ptr_offset_record, src_offset) = ctx.mr(a3 as u32);

        assert_eq!(src_offset, src % 4, "src_offset must be src % 4");
        assert_eq!(nbytes % 4, 0, "nbytes must be a multiple of 4");
        // From the assembly wrapper, dst must already be word aligned.
        assert_eq!(dst % 4, 0, "dst must be word aligned");

        // Read all the words we need, which may include some extra bytes.

        let upper_bound = ceil_align(src + nbytes);
        let num_words = (upper_bound - floor_align(src)) / 4;
        let (src_reads, src_words) = ctx.mr_slice(floor_align(src), NumWords::USIZE);

        let mut src_read_bytes = Vec::new();

        for word in src_words.into_iter().take(num_words as usize) {
            // Convert u32 to little-endian bytes
            let bytes = word.to_le_bytes();
            // Extend the output vector with these bytes
            src_read_bytes.extend_from_slice(&bytes);
        }

        // Cut off the excess in read_bytes.
        let start_idx = (src % 4) as usize;
        let end_addr = src + nbytes;
        let end_idx = src_read_bytes.len() - (ceil_align(end_addr) - end_addr) as usize;
        let src_read_bytes = src_read_bytes[start_idx..end_idx].to_vec();
        assert_eq!(src_read_bytes.len(), nbytes as usize);

        // Read words from dest that must remain the same upon copy.
        let (dst_reads, dst_words) = ctx.mr_slice(dst, NumWords::USIZE);

        // We write to the same word we read, so advance the clock.
        ctx.clk += 1;

        // let src_read_words = src_read_bytes
        //     .chunks_exact(4)
        //     .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        //     .collect::<Vec<u32>>();

        // let mut writes = Vec::new();
        // writes.extend(ctx.mw_slice(dst, &src_read_words));

        let nwords = nbytes >> 2;
        let mut writes = Vec::new();
        for i in 0..nwords as usize {
            let word = u32::from_le_bytes(src_read_bytes[i * 4..(i + 1) * 4].try_into().unwrap());
            let write = ctx.mw(dst + (i as u32) * 4, word);
            writes.push(write);
        }

        // writes.extend(ctx.mw_slice(dst + nbytes, &dst_words[(nbytes / 4) as usize..]));

        // assert_eq!(writes.len(), NumWords::USIZE, "wrong number of writes {writes:?}");

        for i in 0..nbytes {
            assert_eq!(
                ctx.byte_unsafe(src + i),
                ctx.byte_unsafe(dst + i),
                "memcpy failed at byte {i}, dst word: {:X}",
                ctx.word_unsafe(dst - dst % 4),
            );
        }

        let event = MemCopyEvent {
            lookup_id: ctx.syscall_lookup_id,
            shard: ctx.current_shard(),
            channel: ctx.current_channel(),
            clk: ctx.clk,
            src_ptr: src,
            dst_ptr: dst,
            nbytes: nbytes as u8,
            nbytes_record,
            src_ptr_offset_record,
            src_read_records: src_reads,
            dst_read_records: dst_reads,
            write_records: writes,
        };

        //ctx.record_mut().memcpy32_events.push(event);

        None
    }

    fn num_extra_cycles(&self) -> u32 {
        1
    }
}
