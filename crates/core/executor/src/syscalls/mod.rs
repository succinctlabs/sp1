//! Syscall definitions & implementations for the [`crate::Executor`].

mod code;
mod commit;
mod context;
mod deferred;
mod halt;
mod hint;
mod precompiles;
mod unconstrained;
mod verify;
mod write;

use std::sync::Arc;

use commit::CommitSyscall;
use deferred::CommitDeferredSyscall;
use halt::HaltSyscall;
use hashbrown::HashMap;

pub use code::*;
pub use context::*;
use hint::{HintLenSyscall, HintReadSyscall};
use precompiles::{
    edwards::{add::EdwardsAddAssignSyscall, decompress::EdwardsDecompressSyscall},
    fptower::{Fp2AddSubSyscall, Fp2MulSyscall, FpOpSyscall},
    keccak256::permute::Keccak256PermuteSyscall,
    sha256::{compress::Sha256CompressSyscall, extend::Sha256ExtendSyscall},
    u256x2048_mul::U256xU2048MulSyscall,
    uint256::Uint256MulSyscall,
    weierstrass::{
        add::WeierstrassAddAssignSyscall, decompress::WeierstrassDecompressSyscall,
        double::WeierstrassDoubleAssignSyscall,
    },
};

use sp1_curves::{
    edwards::ed25519::{Ed25519, Ed25519Parameters},
    weierstrass::{
        bls12_381::{Bls12381, Bls12381BaseField},
        bn254::{Bn254, Bn254BaseField},
        secp256k1::Secp256k1,
        secp256r1::Secp256r1,
    },
};
use unconstrained::{EnterUnconstrainedSyscall, ExitUnconstrainedSyscall};
use verify::VerifySyscall;
use write::WriteSyscall;

use crate::events::FieldOperation;

/// A system call in the SP1 RISC-V zkVM.
///
/// This trait implements methods needed to execute a system call inside the [`crate::Executor`].
pub trait Syscall: Send + Sync {
    /// Executes the syscall.
    ///
    /// Returns the resulting value of register a0. `arg1` and `arg2` are the values in registers
    /// X10 and X11, respectively. While not a hard requirement, the convention is that the return
    /// value is only for system calls such as `HALT`. Most precompiles use `arg1` and `arg2` to
    /// denote the addresses of the input data, and write the result to the memory at `arg1`.
    fn execute(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32>;

    /// The number of extra cycles that the syscall takes to execute.
    ///
    /// Unless this syscall is complex and requires many cycles, this should be zero.
    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

/// Creates the default syscall map.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn default_syscall_map() -> HashMap<SyscallCode, Arc<dyn Syscall>> {
    let mut syscall_map = HashMap::<SyscallCode, Arc<dyn Syscall>>::default();

    // Use an array to store syscall tuples to simplify insertion
    let syscalls: &[(SyscallCode, Arc<dyn Syscall>)] = &[
        (SyscallCode::HALT, Arc::new(HaltSyscall)),
        (SyscallCode::SHA_EXTEND, Arc::new(Sha256ExtendSyscall)),
        (SyscallCode::SHA_COMPRESS, Arc::new(Sha256CompressSyscall)),
        (SyscallCode::ED_ADD, Arc::new(EdwardsAddAssignSyscall::<Ed25519>::new())),
        (SyscallCode::ED_DECOMPRESS, Arc::new(EdwardsDecompressSyscall::<Ed25519Parameters>::new())),
        (SyscallCode::KECCAK_PERMUTE, Arc::new(Keccak256PermuteSyscall)),
        (SyscallCode::SECP256K1_ADD, Arc::new(WeierstrassAddAssignSyscall::<Secp256k1>::new())),
        (SyscallCode::SECP256K1_DOUBLE, Arc::new(WeierstrassDoubleAssignSyscall::<Secp256k1>::new())),
        (SyscallCode::SECP256K1_DECOMPRESS, Arc::new(WeierstrassDecompressSyscall::<Secp256k1>::new())),
        (SyscallCode::SECP256R1_ADD, Arc::new(WeierstrassAddAssignSyscall::<Secp256r1>::new())),
        (SyscallCode::SECP256R1_DOUBLE, Arc::new(WeierstrassDoubleAssignSyscall::<Secp256r1>::new())),
        (SyscallCode::SECP256R1_DECOMPRESS, Arc::new(WeierstrassDecompressSyscall::<Secp256r1>::new())),
        (SyscallCode::BN254_ADD, Arc::new(WeierstrassAddAssignSyscall::<Bn254>::new())),
        (SyscallCode::BN254_DOUBLE, Arc::new(WeierstrassDoubleAssignSyscall::<Bn254>::new())),
        (SyscallCode::BLS12381_ADD, Arc::new(WeierstrassAddAssignSyscall::<Bls12381>::new())),
        (SyscallCode::BLS12381_DOUBLE, Arc::new(WeierstrassDoubleAssignSyscall::<Bls12381>::new())),
        (SyscallCode::UINT256_MUL, Arc::new(Uint256MulSyscall)),
        (SyscallCode::U256XU2048_MUL, Arc::new(U256xU2048MulSyscall)),
        (SyscallCode::BLS12381_FP_ADD, Arc::new(FpOpSyscall::<Bls12381BaseField>::new(FieldOperation::Add))),
        (SyscallCode::BLS12381_FP_SUB, Arc::new(FpOpSyscall::<Bls12381BaseField>::new(FieldOperation::Sub))),
        (SyscallCode::BLS12381_FP_MUL, Arc::new(FpOpSyscall::<Bls12381BaseField>::new(FieldOperation::Mul))),
        (SyscallCode::BLS12381_FP2_ADD, Arc::new(Fp2AddSubSyscall::<Bls12381BaseField>::new(FieldOperation::Add))),
        (SyscallCode::BLS12381_FP2_SUB, Arc::new(Fp2AddSubSyscall::<Bls12381BaseField>::new(FieldOperation::Sub))),
        (SyscallCode::BLS12381_FP2_MUL, Arc::new(Fp2MulSyscall::<Bls12381BaseField>::new())),
        (SyscallCode::BN254_FP_ADD, Arc::new(FpOpSyscall::<Bn254BaseField>::new(FieldOperation::Add))),
        (SyscallCode::BN254_FP_SUB, Arc::new(FpOpSyscall::<Bn254BaseField>::new(FieldOperation::Sub))),
        (SyscallCode::BN254_FP_MUL, Arc::new(FpOpSyscall::<Bn254BaseField>::new(FieldOperation::Mul))),
        (SyscallCode::BN254_FP2_ADD, Arc::new(Fp2AddSubSyscall::<Bn254BaseField>::new(FieldOperation::Add))),
        (SyscallCode::BN254_FP2_SUB, Arc::new(Fp2AddSubSyscall::<Bn254BaseField>::new(FieldOperation::Sub))),
        (SyscallCode::BN254_FP2_MUL, Arc::new(Fp2MulSyscall::<Bn254BaseField>::new())),
        (SyscallCode::ENTER_UNCONSTRAINED, Arc::new(EnterUnconstrainedSyscall)),
        (SyscallCode::EXIT_UNCONSTRAINED, Arc::new(ExitUnconstrainedSyscall)),
        (SyscallCode::WRITE, Arc::new(WriteSyscall)),
        (SyscallCode::COMMIT, Arc::new(CommitSyscall)),
        (SyscallCode::COMMIT_DEFERRED_PROOFS, Arc::new(CommitDeferredSyscall)),
        (SyscallCode::VERIFY_SP1_PROOF, Arc::new(VerifySyscall)),
        (SyscallCode::HINT_LEN, Arc::new(HintLenSyscall)),
        (SyscallCode::HINT_READ, Arc::new(HintReadSyscall)),
        (SyscallCode::BLS12381_DECOMPRESS, Arc::new(WeierstrassDecompressSyscall::<Bls12381>::new())),
    ];

    // Iterate over the array and insert syscalls
    for (code, syscall) in syscalls {
        syscall_map.insert(*code, syscall.clone());
    }

    syscall_map
}
