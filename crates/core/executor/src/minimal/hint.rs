use sp1_jit::SyscallContext;

pub unsafe fn hint_read(ctx: &mut impl SyscallContext, ptr: u64, len: u64) -> Option<u64> {
    panic_if_input_exhausted(ctx);

    // SAFETY: The input stream is not empty, as checked above, so the back is not None
    let vec = unsafe { ctx.input_buffer().pop_front().unwrap_unchecked() };

    ctx.trace_hint(ptr, vec.clone());

    assert_eq!(vec.len() as u64, len, "hint input stream read length mismatch");
    assert_eq!(ptr % 8, 0, "hint read address not aligned to 8 bytes");

    // Chunk the bytes into words.
    let chunks = vec.chunks_exact(8);
    // Get the number of chunks.
    let chunk_count = chunks.len();
    // Get the remainder of the bytes.
    let remainder = chunks.remainder();

    // For each chunk, write the word to the memory.
    for (i, chunk) in chunks.enumerate() {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);

        ctx.mw_hint(ptr + (i * 8) as u64, word);
    }

    // Write the final word to the memory.
    let final_word = {
        let mut buf = [0u8; 8];
        buf[..remainder.len()].copy_from_slice(remainder);
        u64::from_le_bytes(buf)
    };
    ctx.mw_hint(ptr + (chunk_count * 8) as u64, final_word);

    None
}

unsafe fn panic_if_input_exhausted(ctx: &mut impl SyscallContext) {
    if ctx.input_buffer().is_empty() {
        panic!("hint input stream exhausted");
    }
}

#[allow(clippy::unnecessary_wraps)]
pub unsafe fn hint_len(ctx: &mut impl SyscallContext, _op_a: u64, _op_b: u64) -> Option<u64> {
    let input_stream: &mut std::collections::VecDeque<Vec<u8>> = ctx.input_buffer();
    let value = input_stream.front().map_or(u64::MAX, |data| data.len() as u64);

    ctx.trace_value(value);

    Some(value)
}
