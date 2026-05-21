use num::BigUint;
use sp1_curves::{params::NumWords, AffinePoint, EllipticCurve};
use sp1_jit::{Interrupt, SyscallContext};
use typenum::Unsigned;

/// Create an elliptic curve add event. It takes two pointers to memory locations, reads the points
/// from memory, adds them together, and writes the result back to the first memory location.
/// The generic parameter `N` is the number of u32 words in the point representation. For example,
/// for the secp256k1 curve, `N` would be 16 (64 bytes) because the x and y coordinates are 32 bytes
/// each.
pub(crate) unsafe fn ec_add<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<(), Interrupt> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }
    let q_ptr = arg2;
    if !q_ptr.is_multiple_of(8) {
        panic!();
    }
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(q_ptr, num_words)?;
    ctx.bump_memory_clk();
    ctx.read_write_slice_check(p_ptr, num_words)?;

    ctx.set_clk(clk);
    let p_affine = AffinePoint::<E>::from_words_le(ctx.mr_slice_unsafe(p_ptr, num_words));
    let q_affine = AffinePoint::<E>::from_words_le(ctx.mr_slice_without_prot(q_ptr, num_words));
    let result_affine = p_affine + q_affine;

    let result_words = result_affine.to_words_le();

    // Bump the clock before writing to memory.
    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(p_ptr, &result_words);

    Ok(())
}

/// Create an elliptic curve double event.
///
/// It takes a pointer to a memory location, reads the point from memory, doubles it, and writes the
/// result back to the memory location.
pub(crate) unsafe fn ec_double<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    _: u64,
) -> Result<(), Interrupt> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    ctx.read_write_slice_check(p_ptr, num_words)?;

    let p = ctx.mr_slice_unsafe(p_ptr, num_words);

    let p_affine = AffinePoint::<E>::from_words_le(p);

    let result_affine = E::ec_double(&p_affine);

    let result_words = result_affine.to_words_le();

    ctx.mw_slice_without_prot(p_ptr, &result_words);

    Ok(())
}

/// Create an elliptic curve scalar multiplication event. It takes a pointer to a point and a
/// pointer to a `BigUint` scalar (laid out as little-endian `u64` limbs sized to
/// `E::BaseField::WordsFieldElement`, since the scalar field has approximately the same order
/// as the base field), reads both from memory, multiplies the point by the scalar, and writes
/// the result back to the point's memory location.
pub(crate) unsafe fn ec_mul<E: EllipticCurve>(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<(), Interrupt> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(8) {
        panic!();
    }
    let scalar_ptr = arg2;
    if !scalar_ptr.is_multiple_of(8) {
        panic!();
    }
    // A point is two base-field elements; the scalar lives in a field of approximately the same
    // order as the base field, so we use the same word count for it as well.
    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;
    let scalar_num_words = <E::BaseField as NumWords>::WordsFieldElement::USIZE;

    let clk = ctx.get_current_clk();
    ctx.read_slice_check(p_ptr, num_words)?;
    ctx.bump_memory_clk();
    ctx.read_slice_check(scalar_ptr, scalar_num_words)?;
    ctx.bump_memory_clk();

    ctx.set_clk(clk);
    let p_affine = AffinePoint::<E>::from_words_le(ctx.mr_slice_unsafe(p_ptr, num_words));
    // Scalar is a read-only input the chip's AIR treats like `q` in `ec_add`, so it must use
    // `mr_slice_without_prot` (which advances `mem_value.clk = self.clk`) to keep the memory-bus
    // chain consistent. Using `mr_slice_unsafe` here leaves the memory's per-address clk stale
    // and breaks the global cumulative-sum check across shards.
    let scalar = BigUint::from_slice(
        &ctx.mr_slice_without_prot(scalar_ptr, scalar_num_words)
            .into_iter()
            .flat_map(|&w| [w as u32, (w >> 32) as u32])
            .collect::<Vec<_>>(),
    );
    let result_affine = E::ec_mul(&p_affine, &scalar);

    let result_words = result_affine.to_words_le();

    // Bump the clock before writing to memory.
    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(p_ptr, &result_words);

    Ok(())
}
