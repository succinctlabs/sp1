use sp1_jit::{Interrupt, SyscallContext};

#[allow(clippy::unnecessary_wraps)]
pub unsafe fn hint_read(
    ctx: &mut impl SyscallContext,
    ptr: u64,
    len: u64,
) -> Result<Option<u64>, Interrupt> {
    panic_if_input_exhausted(ctx);

    // Consume `len` bytes from the front of the input buffer with a cursor. The guest
    // splits a logical read into batches of at most `BATCH_HINT_LEN`, so multiple
    // ECALL HINT_READs share one host-pushed Vec.
    let bytes = ctx.consume_hint_bytes(len as usize);

    ctx.trace_hint(ptr, bytes.clone());

    assert_eq!(ptr % 8, 0, "hint read address not aligned to 8 bytes");

    let chunks = bytes.chunks_exact(8);
    let chunk_count = chunks.len();
    let remainder = chunks.remainder();

    for (i, chunk) in chunks.enumerate() {
        let word = u64::from_le_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        ctx.mw_hint(ptr + (i * 8) as u64, word);
    }

    if !remainder.is_empty() {
        let mut buf = [0u8; 8];
        buf[..remainder.len()].copy_from_slice(remainder);
        let final_word = u64::from_le_bytes(buf);
        ctx.mw_hint(ptr + (chunk_count * 8) as u64, final_word);
    }

    Ok(None)
}

unsafe fn panic_if_input_exhausted(ctx: &mut impl SyscallContext) {
    if ctx.hint_remaining_len().is_none() {
        panic!("hint input stream exhausted");
    }
}

#[allow(clippy::unnecessary_wraps)]
pub unsafe fn hint_len(
    ctx: &mut impl SyscallContext,
    _op_a: u64,
    _op_b: u64,
) -> Result<Option<u64>, Interrupt> {
    let value = ctx.hint_remaining_len().map_or(u64::MAX, |n| n as u64);
    // An empty hint gets no HINT_READ from the guest, so consume it here.
    if value == 0 {
        ctx.consume_hint_bytes(0);
    }
    ctx.trace_value(value);
    Ok(Some(value))
}
