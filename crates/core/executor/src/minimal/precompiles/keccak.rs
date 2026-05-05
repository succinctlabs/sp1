use sp1_jit::{Interrupt, SyscallContext};

use tiny_keccak::keccakf;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 32 bits, so it is 50 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

pub unsafe fn keccak_permute(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    let state_ptr = arg1;
    if arg2 != 0 {
        panic!("Expected arg2 to be 0, got {arg2}");
    }

    // We are doing 2 separate checks here, since KeccakPermutePageProtRecords
    // requires separate read records from write records. Maybe we can merge the
    // two later
    let clk = ctx.get_current_clk();
    ctx.read_slice_check(state_ptr, STATE_NUM_WORDS)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(state_ptr, STATE_NUM_WORDS)?;

    ctx.set_clk(clk);
    let mut state: Vec<u64> = Vec::new();

    let state_values = ctx.mr_slice_without_prot(state_ptr, STATE_NUM_WORDS);
    state.extend(state_values);

    let mut state = state.try_into().unwrap();
    keccakf(&mut state);

    // Bump the clock before writing to memory.
    ctx.bump_memory_clk();

    ctx.mw_slice_without_prot(state_ptr, state.as_slice());

    Ok(None)
}
