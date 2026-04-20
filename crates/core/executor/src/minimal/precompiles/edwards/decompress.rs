use sp1_curves::{
    curve25519_dalek::CompressedEdwardsY,
    edwards::{ed25519::decompress, WORDS_FIELD_ELEMENT},
    COMPRESSED_POINT_BYTES,
};
use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le};

pub unsafe fn edwards_decompress_syscall(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    sign: u64,
) -> Result<Option<u64>, Interrupt> {
    let slice_ptr = arg1;
    assert!(slice_ptr.is_multiple_of(8), "Pointer must be 8-byte aligned.");
    assert!(sign <= 1, "Sign bit must be 0 or 1.");

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(slice_ptr + (COMPRESSED_POINT_BYTES as u64), WORDS_FIELD_ELEMENT)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(slice_ptr, WORDS_FIELD_ELEMENT)?;

    ctx.set_clk(clk);
    let y =
        ctx.mr_slice_without_prot(slice_ptr + (COMPRESSED_POINT_BYTES as u64), WORDS_FIELD_ELEMENT);
    let y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(y);
    ctx.bump_memory_clk();

    // Copy bytes into another array so we can modify the last byte and make CompressedEdwardsY,
    // which we'll use to compute the expected X.
    // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
    let mut compressed_edwards_y: [u8; COMPRESSED_POINT_BYTES] = y_bytes;
    compressed_edwards_y[compressed_edwards_y.len() - 1] &= 0b0111_1111;
    compressed_edwards_y[compressed_edwards_y.len() - 1] |= (sign as u8) << 7;

    // Compute actual decompressed X
    let compressed_y = CompressedEdwardsY(compressed_edwards_y);
    let decompressed = decompress(&compressed_y).expect("curve25519 Decompression failed");

    let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
    decompressed_x_bytes.resize(32, 0u8);
    let decompressed_x_words: [u64; WORDS_FIELD_ELEMENT] = bytes_to_words_le(&decompressed_x_bytes);

    // Write decompressed X into slice
    ctx.mw_slice_without_prot(slice_ptr, &decompressed_x_words);

    Ok(None)
}
