pub mod air;

pub use air::Poseidon2Chip;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sp1_core_executor::Program;
    use test_artifacts::POSEIDON2_ELF;

    use crate::{
        io::SP1Stdin,
        utils::{self, run_test},
    };

    /// Proves a guest program that drives the Poseidon2 precompile through both of the hashing
    /// surfaces `sp1-lib` exposes.
    ///
    /// `RiscvAir::Poseidon2` had no test of any kind. No program under `test-artifacts` issued the
    /// POSEIDON2 syscall, so nothing exercised the chip's AIR, its memory access columns, or its
    /// range checks on a real execution, even though every sibling under `precompiles/` is covered
    /// exactly this way.
    ///
    /// Inputs are kept small because what is under test is the constraint system, not the digests.
    /// The digests are checked far more cheaply, and against a host reference, in
    /// `sp1_core_executor::minimal::tests::poseidon2_tests`.
    ///
    /// This covers `RiscvAir::Poseidon2` only. `RiscvAir::Poseidon2User`, the variant used for
    /// untrusted programs, is a separate chip and remains uncovered: reaching it needs a guest
    /// built with the `untrusted_programs` feature, the way `trap-exec` and `trap-load-store` are.
    #[tokio::test]
    pub async fn test_poseidon2_program_prove() {
        utils::setup_logger();
        let program = Arc::new(Program::from(&POSEIDON2_ELF).unwrap());

        let mut stdin = SP1Stdin::new();
        stdin.write(&vec![[0u32; 8], core::array::from_fn::<u32, 8, _>(|i| i as u32)]);
        stdin.write(&vec![Vec::<u8>::new(), vec![7u8; 25]]);

        run_test(program, stdin).await.unwrap();
    }
}
