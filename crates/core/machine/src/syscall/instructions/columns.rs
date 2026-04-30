use sp1_derive::AlignedBorrow;
use sp1_hypercube::{air::PV_DIGEST_NUM_WORDS, Word};
use std::mem::size_of;
use struct_reflection::{StructReflection, StructReflectionHelper};

use crate::{
    adapter::{register::r_type::RTypeReader, state::CPUState},
    operations::{IsZeroOperation, SP1FieldWordRangeChecker, U16toU8Operation},
};

pub const NUM_SYSCALL_INSTR_COLS: usize = size_of::<SyscallInstrColumns<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy, StructReflection)]
#[repr(C)]
pub struct SyscallInstrColumns<T> {
    /// The current shard, timestamp, program counter of the CPU.
    pub state: CPUState<T>,

    /// The adapter to read program and register information.
    pub adapter: RTypeReader<T>,

    /// The next program counter.
    pub next_pc: [T; 3],

    /// Whether the current instruction is a halt instruction. This is verified by the
    /// is_halt_check operation.
    pub is_halt: T,

    /// The result of register op_a.
    pub op_a_value: Word<T>,

    /// Lower byte of two limbs of `b`.
    pub a_low_bytes: U16toU8Operation<T>,

    /// Whether the current ecall is ENTER_UNCONSTRAINED.
    pub is_enter_unconstrained: IsZeroOperation<T>,

    /// Whether the current ecall is HINT_LEN.
    pub is_hint_len: IsZeroOperation<T>,

    /// Whether the current ecall is HALT.
    pub is_halt_check: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT.
    pub is_commit: IsZeroOperation<T>,

    /// Whether the current ecall is a COMMIT_DEFERRED_PROOFS.
    pub is_commit_deferred_proofs: IsZeroOperation<T>,

    /// Field to store the word index passed into the COMMIT ecall.  
    /// index_bitmap[word index] should be set to 1 and everything else set to 0.
    pub index_bitmap: [T; PV_DIGEST_NUM_WORDS],

    /// The expected public values digest.
    pub expected_public_values_digest: [T; 4],

    /// The check if `op_b` is a valid SP1Field.
    pub op_b_range_check: SP1FieldWordRangeChecker<T>,

    /// The check if `op_c` is a valid SP1Field.
    pub op_c_range_check: SP1FieldWordRangeChecker<T>,

    /// Whether the current instruction is a real instruction.
    pub is_real: T,
}
