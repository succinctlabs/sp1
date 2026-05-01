use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::Permutation;
use sp1_hypercube::inner_perm;
use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::SP1Field;

pub(crate) unsafe fn poseidon2(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    _arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    let ptr = arg1;
    assert!(ptr.is_multiple_of(8));

    ctx.read_write_slice_check(ptr, 8)?;

    // Read 8 u64 words (16 u32 words) from memory
    let input: Vec<u64> = ctx.mr_slice_unsafe(ptr, 8).into_iter().copied().collect();

    // Cast to [u32; 16] array directly (same as syscalls version)
    let input_arr: &[u32; 16] = &*(input.as_ptr().cast::<[u32; 16]>());

    // Apply Poseidon2 permutation
    let perm = inner_perm();
    let output_hash =
        perm.permute(input_arr.map(SP1Field::from_canonical_u32)).map(|x| x.as_canonical_u32());

    // Convert back to u64 array
    let u64_result: Vec<u64> = output_hash
        .chunks_exact(2)
        .map(|pair| (u64::from(pair[1]) << 32) | u64::from(pair[0]))
        .collect();

    assert!(u64_result.len() == 8);

    // Write result back to memory
    ctx.mw_slice_without_prot(ptr, &u64_result);

    Ok(None)
}
