mod air;
pub mod columns;
pub mod constants;
mod controller;
mod trace;

pub const STATE_SIZE: usize = 25;
pub const BITS_PER_LIMB: usize = 16;

// The permutation state is 25 u64's.  Our word size is 64 bits, so it is 25 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE;

pub struct KeccakPermuteChip;

impl KeccakPermuteChip {
    pub const fn new() -> Self {
        Self {}
    }
}

use std::marker::PhantomData;

use crate::TrustMode;

/// Implements the controller for the KeccakPermuteChip, which receives the syscalls and sends it to
/// the chip.
#[derive(Default)]
pub struct KeccakPermuteControlChip<M: TrustMode> {
    _marker: PhantomData<M>,
}

#[cfg(test)]
mod permute_tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::KECCAK_PERMUTE_ELF;

    use crate::{
        io::SP1Stdin,
        utils::{self},
    };

    #[tokio::test]
    pub async fn test_keccak_permute_program_prove() {
        utils::setup_logger();
        let program = Arc::new(Program::from(&KECCAK_PERMUTE_ELF).unwrap());
        let stdin = SP1Stdin::new();
        utils::run_test(program, stdin).await.unwrap();
    }
}
