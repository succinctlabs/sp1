use crate::{
    events::{
        MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, SyscallEvent,
    },
    ExecutionRecord, SyscallCode,
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

use super::CoreVM;

mod commit;
mod deferred;
mod halt;
mod hint;
mod poseidon2;
mod precompiles;
mod u256x2048_mul;
mod uint256;
mod uint256_ops;

pub trait SyscallRuntime<'a> {
    const TRACING: bool;

    fn core(&self) -> &CoreVM<'a>;

    fn core_mut(&mut self) -> &mut CoreVM<'a>;

    #[allow(clippy::too_many_arguments)]
    fn syscall_event(
        &self,
        _clk: u64,
        _syscall_code: SyscallCode,
        _arg1: u64,
        _arg2: u64,
        _op_a_0: bool,
        _next_pc: u64,
        _exit_code: u32,
    ) -> SyscallEvent {
        unreachable!("SyscallRuntime::syscall_event is not intended to be called by default.");
    }

    fn add_precompile_event(
        &mut self,
        _syscall_code: SyscallCode,
        _syscall_event: SyscallEvent,
        _event: PrecompileEvent,
    ) {
        unreachable!(
            "SyscallRuntime::add_precompile_event is not intended to be called by default."
        );
    }

    /// Increment the clock by 1, used for precompiles that access memory,
    /// that potentially overlap.
    fn increment_clk(&mut self) {
        let clk = self.core_mut().clk();

        self.core_mut().set_clk(clk + 1);
    }

    fn record_mut(&mut self) -> &mut ExecutionRecord {
        unreachable!("SyscallRuntime::record_mut is not intended to be called by default.");
    }

    /// Postprocess the precompile memory access.
    fn postprocess_precompile(&mut self) -> Vec<MemoryLocalEvent> {
        unreachable!(
            "SyscallRuntime::postprocess_precompile is not intended to be called by default."
        );
    }

    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        let core = self.core_mut();
        let clk = core.clk();

        #[allow(clippy::manual_let_else)]
        let record = match core.mem_reads.next() {
            Some(next) => next,
            None => {
                unreachable!("memory reads unexpectdely exhausted at {addr}, clk {}", clk);
            }
        };

        MemoryReadRecord {
            value: record.value,
            timestamp: clk,
            prev_timestamp: record.clk,
            prev_page_prot_record: None,
        }
    }

    fn mw(&mut self, _addr: u64) -> MemoryWriteRecord {
        let mem_writes = self.core_mut().mem_reads();

        let old = mem_writes.next().expect("Precompile memory read out of bounds");
        let new = mem_writes.next().expect("Precompile memory read out of bounds");

        let record = MemoryWriteRecord {
            prev_timestamp: old.clk,
            prev_value: old.value,
            timestamp: self.core().clk(),
            value: new.value,
            prev_page_prot_record: None,
        };

        record
    }

    fn mr_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryReadRecord> {
        self.core_mut().mr_slice(addr, len)
    }

    fn mw_slice(&mut self, addr: u64, len: usize) -> Vec<MemoryWriteRecord> {
        self.core_mut().mw_slice(addr, len)
    }

    fn mr_slice_unsafe(&mut self, len: usize) -> Vec<u64> {
        self.core_mut().mr_slice_unsafe(len)
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        self.core_mut().rr_precompile(register)
    }
}

impl<'a> SyscallRuntime<'a> for CoreVM<'a> {
    const TRACING: bool = false;

    fn core(&self) -> &CoreVM<'a> {
        self
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a> {
        self
    }
}

pub(crate) fn sp1_ecall_handler<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    code: SyscallCode,
    args1: u64,
    args2: u64,
) -> Option<u64> {
    // Precompiles may directly modify the clock, so we need to save the current clock
    // and reset it after the syscall.
    let clk = rt.core().clk();

    #[allow(clippy::match_same_arms)]
    let ret = match code {
        // Noop: This method just writes to uninitialized memory.
        // Since the tracing VM relies on oracled memory, this method is a no-op.
        SyscallCode::HINT_LEN => hint::hint_len_syscall(rt, code, args1, args2),
        SyscallCode::HALT => halt::halt_syscall(rt, code, args1, args2),
        SyscallCode::COMMIT => commit::commit_syscall(rt, code, args1, args2),
        SyscallCode::COMMIT_DEFERRED_PROOFS => {
            deferred::commit_deferred_proofs_syscall(rt, code, args1, args2)
        }
        // Weierstrass curve operations
        SyscallCode::SECP256K1_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Secp256k1>(rt, code, args1, args2)
        }
        SyscallCode::SECP256K1_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Secp256k1>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Bls12381>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Bls12381>(rt, code, args1, args2)
        }
        SyscallCode::BN254_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Bn254>(rt, code, args1, args2)
        }
        SyscallCode::BN254_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Bn254>(rt, code, args1, args2)
        }
        SyscallCode::SECP256R1_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Secp256r1>(rt, code, args1, args2)
        }
        SyscallCode::SECP256R1_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Secp256r1>(rt, code, args1, args2)
        }
        // Edwards curve operations
        SyscallCode::ED_ADD => {
            precompiles::edwards::edwards_add::<RT, Ed25519>(rt, code, args1, args2)
        }
        SyscallCode::ED_DECOMPRESS => {
            precompiles::edwards::edwards_decompress(rt, code, args1, args2)
        }
        SyscallCode::UINT256_MUL => uint256::uint256_mul(rt, code, args1, args2),
        SyscallCode::UINT256_MUL_CARRY | SyscallCode::UINT256_ADD_CARRY => {
            uint256_ops::uint256_ops(rt, code, args1, args2)
        }
        SyscallCode::U256XU2048_MUL => u256x2048_mul::u256xu2048_mul(rt, code, args1, args2),
        SyscallCode::SHA_COMPRESS => precompiles::sha256::sha256_compress(rt, code, args1, args2),
        SyscallCode::SHA_EXTEND => precompiles::sha256::sha256_extend(rt, code, args1, args2),
        SyscallCode::KECCAK_PERMUTE => {
            precompiles::keccak256::keccak256_permute(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
            precompiles::fptower::fp2_add::<_, Bls12381BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
            precompiles::fptower::fp2_add::<_, Bn254BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_FP2_MUL => {
            precompiles::fptower::fp2_mul::<_, Bls12381BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BN254_FP2_MUL => {
            precompiles::fptower::fp2_mul::<_, Bn254BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_FP_ADD
        | SyscallCode::BLS12381_FP_SUB
        | SyscallCode::BLS12381_FP_MUL => {
            precompiles::fptower::fp_op::<_, Bls12381BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BN254_FP_ADD | SyscallCode::BN254_FP_SUB | SyscallCode::BN254_FP_MUL => {
            precompiles::fptower::fp_op::<_, Bn254BaseField>(rt, code, args1, args2)
        }
        SyscallCode::POSEIDON2 => poseidon2::poseidon2(rt, code, args1, args2),
        SyscallCode::VERIFY_SP1_PROOF
        | SyscallCode::MPROTECT
        | SyscallCode::ENTER_UNCONSTRAINED
        | SyscallCode::EXIT_UNCONSTRAINED
        | SyscallCode::HINT_READ
        | SyscallCode::WRITE => None,
        code @ (SyscallCode::SECP256K1_DECOMPRESS
        | SyscallCode::BLS12381_DECOMPRESS
        | SyscallCode::SECP256R1_DECOMPRESS) => {
            unreachable!("{code} is not yet supported by the native executor.")
        }
    };

    rt.core_mut().set_clk(clk);

    ret
}
