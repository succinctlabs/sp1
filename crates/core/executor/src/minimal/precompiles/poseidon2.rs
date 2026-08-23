use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::Permutation;
use sp1_hypercube::inner_perm;
use sp1_jit::{Interrupt, SyscallContext};
use sp1_primitives::SP1Field;

/// Rejects a state word that does not represent a canonical `SP1Field` element.
///
/// The Poseidon2 AIR range checks all 16 input words against the modulus (see
/// `input_range_checkers` in the chip), so a word `>= P` has no provable execution. The executor
/// must not paper over that: `SP1Field::from_canonical_u32` only range checks under
/// `debug_assert`, so a release build would reduce the word modulo `P`, hash something the guest
/// never wrote, and run on to completion. The disagreement would then surface as a constraint
/// failure inside the Poseidon2 chip during proving, naming neither the syscall nor the guest.
///
/// This is the safety contract on `Poseidon2State::absorb_field_block_unchecked`, which is the
/// only way a guest can put a non-canonical word into the state.
fn assert_canonical(ptr: u64, lane: usize, value: u32) {
    assert!(
        value < SP1Field::ORDER_U32,
        "the guest program passed a non-canonical value to the Poseidon2 precompile: lane {lane} \
         of the state at {ptr:#x} is {value}, which is not less than the SP1Field modulus {}. The \
         Poseidon2 AIR range checks every input word against the modulus, so this execution \
         cannot be proven. Reduce the value modulo the field in the guest before absorbing it; \
         this is the documented safety contract on \
         `Poseidon2State::absorb_field_block_unchecked`.",
        SP1Field::ORDER_U32,
    );
}

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

    // Reject non-canonical words before converting, so the diagnostic does not depend on
    // `from_canonical_u32`'s `debug_assert` being compiled in.
    for (lane, value) in input_arr.iter().enumerate() {
        assert_canonical(ptr, lane, *value);
    }

    // Apply Poseidon2 permutation
    let perm = inner_perm();
    let output_hash =
        perm.permute(input_arr.map(SP1Field::from_canonical_u32)).map(|x| x.as_canonical_u32());

    // Convert back to u64 array
    let u64_result: Vec<u64> = output_hash
        .chunks_exact(2)
        .map(|pair| (u64::from(pair[1]) << 32) | u64::from(pair[0]))
        .collect();

    assert_eq!(u64_result.len(), 8);

    // Write result back to memory
    ctx.mw_slice_without_prot(ptr, &u64_result);

    Ok(None)
}
