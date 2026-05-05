mod air;
mod columns;
mod controller;
mod trace;
pub use columns::*;
/// Implements the SHA extension operation which loops over i = \[16, 63\] and modifies w\[i\] in
/// each iteration. The only input to the syscall is the 8byte-aligned pointer to the w array.
///
/// In the AIR, each SHA extend syscall takes up 48 rows, where each row corresponds to a single
/// iteration of the loop.
#[derive(Default)]
pub struct ShaExtendChip;

use std::marker::PhantomData;

use crate::TrustMode;

/// Implements the controller for the ShaExtendChip.
#[derive(Default)]
pub struct ShaExtendControlChip<M: TrustMode> {
    _marker: PhantomData<M>,
}

impl ShaExtendChip {
    pub const fn new() -> Self {
        Self {}
    }
}

pub fn sha_extend(w: &mut [u32]) {
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

#[cfg(test)]
pub mod extend_tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::{SHA2_ELF, SHA_EXTEND_ELF};

    use crate::{
        io::SP1Stdin,
        utils::{self, run_test},
    };

    #[tokio::test]
    async fn test_sha256_program() {
        utils::setup_logger();
        let program = Arc::new(Program::from(&SHA2_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_sha_extend_program() {
        utils::setup_logger();
        let program = Arc::new(Program::from(&SHA_EXTEND_ELF).unwrap());
        let stdin = SP1Stdin::new();
        run_test(program, stdin).await.unwrap();
    }
}
