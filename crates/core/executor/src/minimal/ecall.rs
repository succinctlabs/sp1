use crate::SyscallCode;

use super::{
    debug::{delete_profile_symbols_syscall, dump_elf_syscall, insert_profile_symbols_syscall},
    hint::{hint_len, hint_read},
    precompiles::{
        edwards::{edwards_add, edwards_decompress_syscall},
        fptower::{fp2_addsub_syscall, fp2_mul_syscall, fp_op_syscall},
        keccak::keccak_permute,
        mprotect::{mprotect_flush_syscall, mprotect_syscall},
        poseidon2::poseidon2,
        sha256::{sha256_compress, sha256_extend},
        sig_return::sig_return_syscall,
        uint256::uint256_mul,
        uint256_ops::uint256_ops,
        uint256x2048::u256x2048_mul,
        weierstrass::{
            weierstrass_add_assign_syscall, weierstrass_decompress_syscall,
            weierstrass_double_assign_syscall,
        },
    },
    write::write,
};

use sp1_curves::{
    edwards::ed25519::Ed25519,
    weierstrass::{
        bls12_381::{Bls12381, Bls12381BaseField},
        bn254::{Bn254, Bn254BaseField},
        secp256k1::Secp256k1,
        secp256r1::Secp256r1,
    },
};
use sp1_jit::{Interrupt, RiscRegister, SyscallContext};

// Used by the x86_64 JIT executor. When profiling is enabled, only compiled for tests.
#[cfg(all(
    target_arch = "x86_64",
    target_endian = "little",
    any(not(feature = "profiling"), test)
))]
#[allow(dead_code)]
pub(super) extern "C" fn sp1_ecall_handler(ctx: *mut sp1_jit::JitContext) -> u64 {
    let ctx = unsafe { &mut *ctx };
    let code = SyscallCode::from_u32(ctx.rr(RiscRegister::X5) as u32);

    // Store the clock from when we enter.
    let (pc, clk) = (ctx.pc, ctx.clk);

    let result = ecall_handler(ctx, code).expect("ecall failed with interrupt");

    match code {
        SyscallCode::EXIT_UNCONSTRAINED => {
            // The `exit_unconstrained` resets the pc and clk to the values they were at when
            // the unconstrained block was entered.
            ctx.pc = ctx.pc.wrapping_add(4);
            ctx.clk = ctx.clk.wrapping_add(256);
        }
        SyscallCode::HALT => {
            // Explicity set the PC to one, to indicate that the program has halted.
            ctx.pc = 1;
            ctx.clk = clk.wrapping_add(256);
        }
        SyscallCode::SIG_RETURN => {
            // PC will be updated by sigreturn.
            ctx.clk = clk.wrapping_add(256);
        }
        // In the normal case, we just want to advance to the next instruction.
        _ => {
            ctx.pc = pc.wrapping_add(4);
            ctx.clk = clk.wrapping_add(256);
        }
    }

    result
}

pub fn ecall_handler(ctx: &mut impl SyscallContext, code: SyscallCode) -> Result<u64, Interrupt> {
    let arg1 = ctx.rr(RiscRegister::X10);
    let arg2 = ctx.rr(RiscRegister::X11);

    // Unconstrained mode is not allowed for any syscall other than WRITE and HALT.
    if ctx.is_unconstrained()
        && (code != SyscallCode::WRITE && code != SyscallCode::EXIT_UNCONSTRAINED)
    {
        panic!("Unconstrained mode is not allowed for this syscall: {code:?}");
    }

    match code {
        SyscallCode::SHA_EXTEND => unsafe { sha256_extend(ctx, arg1, arg2) },
        SyscallCode::SHA_COMPRESS => unsafe { sha256_compress(ctx, arg1, arg2) },
        SyscallCode::KECCAK_PERMUTE => unsafe { keccak_permute(ctx, arg1, arg2) },
        SyscallCode::SECP256K1_ADD => unsafe {
            weierstrass_add_assign_syscall::<Secp256k1>(ctx, arg1, arg2)
        },
        SyscallCode::SECP256K1_DOUBLE => unsafe {
            weierstrass_double_assign_syscall::<Secp256k1>(ctx, arg1, arg2)
        },
        SyscallCode::SECP256K1_DECOMPRESS => {
            weierstrass_decompress_syscall::<Secp256k1>(ctx, arg1, arg2)
        }
        SyscallCode::SECP256R1_ADD => unsafe {
            weierstrass_add_assign_syscall::<Secp256r1>(ctx, arg1, arg2)
        },
        SyscallCode::SECP256R1_DOUBLE => unsafe {
            weierstrass_double_assign_syscall::<Secp256r1>(ctx, arg1, arg2)
        },
        SyscallCode::SECP256R1_DECOMPRESS => {
            weierstrass_decompress_syscall::<Secp256r1>(ctx, arg1, arg2)
        }
        SyscallCode::BLS12381_ADD => unsafe {
            weierstrass_add_assign_syscall::<Bls12381>(ctx, arg1, arg2)
        },
        SyscallCode::BLS12381_DOUBLE => unsafe {
            weierstrass_double_assign_syscall::<Bls12381>(ctx, arg1, arg2)
        },
        SyscallCode::BLS12381_DECOMPRESS => {
            weierstrass_decompress_syscall::<Bls12381>(ctx, arg1, arg2)
        }
        SyscallCode::BN254_ADD => unsafe {
            weierstrass_add_assign_syscall::<Bn254>(ctx, arg1, arg2)
        },
        SyscallCode::BN254_DOUBLE => unsafe {
            weierstrass_double_assign_syscall::<Bn254>(ctx, arg1, arg2)
        },
        SyscallCode::ED_ADD => unsafe { edwards_add::<Ed25519>(ctx, arg1, arg2) },
        SyscallCode::ED_DECOMPRESS => unsafe { edwards_decompress_syscall(ctx, arg1, arg2) },
        SyscallCode::BLS12381_FP_ADD
        | SyscallCode::BLS12381_FP_SUB
        | SyscallCode::BLS12381_FP_MUL => unsafe {
            fp_op_syscall::<Bls12381BaseField>(ctx, arg1, arg2, code.fp_op_map())
        },
        SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => unsafe {
            fp2_addsub_syscall::<Bls12381BaseField>(ctx, arg1, arg2, code.fp_op_map())
        },
        SyscallCode::BLS12381_FP2_MUL => unsafe {
            fp2_mul_syscall::<Bls12381BaseField>(ctx, arg1, arg2)
        },
        SyscallCode::BN254_FP_ADD
        | SyscallCode::BN254_FP_SUB
        | SyscallCode::BN254_FP_MUL => unsafe {
            fp_op_syscall::<Bn254BaseField>(ctx, arg1, arg2, code.fp_op_map())
        },
        SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => unsafe {
            fp2_addsub_syscall::<Bn254BaseField>(ctx, arg1, arg2, code.fp_op_map())
        },
        SyscallCode::BN254_FP2_MUL => unsafe {
            fp2_mul_syscall::<Bn254BaseField>(ctx, arg1, arg2)
        },
        SyscallCode::UINT256_MUL => unsafe { uint256_mul(ctx, arg1, arg2) },
        SyscallCode::U256XU2048_MUL => unsafe { u256x2048_mul(ctx, arg1, arg2) },
        SyscallCode::ENTER_UNCONSTRAINED => {
            ctx.enter_unconstrained().expect("Failed to enter unconstrained mode");
            Ok(Some(1))
        }
        SyscallCode::EXIT_UNCONSTRAINED => {
            ctx.exit_unconstrained();
            Ok(Some(0))
        }
        SyscallCode::HINT_LEN => unsafe { hint_len(ctx, arg1, arg2) },
        SyscallCode::HINT_READ => unsafe { hint_read(ctx, arg1, arg2) },
        SyscallCode::WRITE => unsafe { Ok(write(ctx, arg1, arg2)) },
        SyscallCode::UINT256_MUL_CARRY | SyscallCode::UINT256_ADD_CARRY => unsafe {
            uint256_ops(ctx, arg1, arg2)
        },
        SyscallCode::POSEIDON2 => unsafe { poseidon2(ctx, arg1, arg2) },
        SyscallCode::HALT => {
            ctx.set_exit_code(arg1 as u32);
            Ok(None)
        }
        SyscallCode::MPROTECT => mprotect_syscall(ctx, arg1, arg2),
        SyscallCode::HINT_MPROTECT_FLUSH => mprotect_flush_syscall(ctx, arg1, arg2),
        SyscallCode::SIG_RETURN => sig_return_syscall(ctx, arg1, arg2),
        SyscallCode::DUMP_ELF => Ok(dump_elf_syscall(ctx, arg1, arg2)),
        SyscallCode::INSERT_PROFILER_SYMBOLS => {
            Ok(insert_profile_symbols_syscall(ctx, arg1, arg2))
        }
        SyscallCode::DELETE_PROFILER_SYMBOLS => {
            Ok(delete_profile_symbols_syscall(ctx, arg1, arg2))
        }
        SyscallCode::VERIFY_SP1_PROOF
        | SyscallCode::COMMIT
        | SyscallCode::COMMIT_DEFERRED_PROOFS => Ok(None),
    }
    .map(|opt: Option<u64>| opt.unwrap_or(code as u64))
}
