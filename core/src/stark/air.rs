use crate::air::MachineAir;
pub use crate::air::SP1AirBuilder;
use crate::memory::MemoryChipKind;
use crate::runtime::ExecutionRecord;
use crate::syscall::precompiles::fri_fold::{self, FriFoldChip};
use p3_field::PrimeField32;
pub use riscv_chips::*;

/// A module for importing all the different RISC-V chips.
pub(crate) mod riscv_chips {
    pub use crate::alu::AddChip;
    pub use crate::alu::BitwiseChip;
    pub use crate::alu::DivRemChip;
    pub use crate::alu::LtChip;
    pub use crate::alu::MulChip;
    pub use crate::alu::ShiftLeft;
    pub use crate::alu::ShiftRightChip;
    pub use crate::alu::SubChip;
    pub use crate::bytes::ByteChip;
    pub use crate::cpu::CpuChip;
    pub use crate::field::FieldLTUChip;
    pub use crate::memory::MemoryGlobalChip;
    pub use crate::program::ProgramChip;
    pub use crate::syscall::precompiles::blake3::Blake3CompressInnerChip;
    pub use crate::syscall::precompiles::edwards::EdAddAssignChip;
    pub use crate::syscall::precompiles::edwards::EdDecompressChip;
    pub use crate::syscall::precompiles::k256::K256DecompressChip;
    pub use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
    pub use crate::syscall::precompiles::sha256::ShaCompressChip;
    pub use crate::syscall::precompiles::sha256::ShaExtendChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassAddAssignChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignChip;
    pub use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
    pub use crate::utils::ec::edwards::EdwardsCurve;
    pub use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
    pub use crate::utils::ec::weierstrass::SWCurve;
}

/// An AIR for encoding RISC-V execution.
///
/// This enum contains all the different AIRs that are used in the Sp1 RISC-V IOP. Each variant is
/// a different AIR that is used to encode a different part of the RISC-V execution, and the
/// different AIR variants have a joint lookup argument.
#[derive(MachineAir)]
pub enum RiscvAir<F: PrimeField32> {
    /// An AIR that containts a preprocessed program table and a lookup for the instructions.
    Program(ProgramChip),
    /// An AIR for the RISC-V CPU. Each row represents a cpu cycle.
    Cpu(CpuChip),
    /// An AIR for the RISC-V Add instruction.
    Add(AddChip),
    /// An AIR for the RISC-V Sub instruction.
    Sub(SubChip),
    /// An AIR for RISC-V Bitwise instructions.
    Bitwise(BitwiseChip),
    /// An AIR for RISC-V Mul instruction.
    Mul(MulChip),
    /// An AIR for RISC-V Div and Rem instructions.
    DivRem(DivRemChip),
    /// An AIR for RISC-V Lt instruction.
    Lt(LtChip),
    /// An AIR for RISC-V SLL instruction.
    ShiftLeft(ShiftLeft),
    /// An AIR for RISC-V SRL and SRA instruction.
    ShiftRight(ShiftRightChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// An table for `less than` operation on field elements.
    FieldLTU(FieldLTUChip),
    /// A table for initializing the memory state.
    MemoryInit(MemoryGlobalChip),
    /// A table for finalizing the memory state.
    MemoryFinal(MemoryGlobalChip),
    /// A table for initializing the program memory.
    ProgramMemory(MemoryGlobalChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),
    /// A precompile for decompressing a point on the K256 curve.
    K256Decompress(K256DecompressChip),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SWCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SWCurve<Secp256k1Parameters>>),
    /// A precompile for the Keccak permutation.
    KeccakP(KeccakPermuteChip),
    /// A precompile for the Blake3 compression function.
    Blake3Compress(Blake3CompressInnerChip),
    /// A precompile for the fri fold function.
    FriFold(FriFoldChip),
}

impl<F: PrimeField32> RiscvAir<F> {
    /// Get all the different RISC-V AIRs.
    pub fn get_all() -> Vec<Self> {
        // The order of the chips is important, as it is used to determine the order of trace
        // generation. In the future, we will detect that order automatically.
        let mut chips = vec![];
        let cpu = CpuChip::default();
        chips.push(RiscvAir::Cpu(cpu));
        let program = ProgramChip::default();
        chips.push(RiscvAir::Program(program));
        let sha_extend = ShaExtendChip::default();
        chips.push(RiscvAir::Sha256Extend(sha_extend));
        let sha_compress = ShaCompressChip::default();
        chips.push(RiscvAir::Sha256Compress(sha_compress));
        let ed_add_assign = EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>>::new();
        chips.push(RiscvAir::Ed25519Add(ed_add_assign));
        let ed_decompress = EdDecompressChip::<Ed25519Parameters>::default();
        chips.push(RiscvAir::Ed25519Decompress(ed_decompress));
        let k256_decompress = K256DecompressChip::default();
        chips.push(RiscvAir::K256Decompress(k256_decompress));
        let weierstrass_add_assign =
            WeierstrassAddAssignChip::<SWCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Add(weierstrass_add_assign));
        let weierstrass_double_assign =
            WeierstrassDoubleAssignChip::<SWCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Double(weierstrass_double_assign));
        let keccak_permute = KeccakPermuteChip::new();
        chips.push(RiscvAir::KeccakP(keccak_permute));
        let blake3_compress_inner = Blake3CompressInnerChip::new();
        chips.push(RiscvAir::Blake3Compress(blake3_compress_inner));
        let fri_fold = fri_fold::FriFoldChip::new();
        chips.push(RiscvAir::FriFold(fri_fold));
        let add = AddChip::default();
        chips.push(RiscvAir::Add(add));
        let sub = SubChip::default();
        chips.push(RiscvAir::Sub(sub));
        let bitwise = BitwiseChip::default();
        chips.push(RiscvAir::Bitwise(bitwise));
        let div_rem = DivRemChip::default();
        chips.push(RiscvAir::DivRem(div_rem));
        let mul = MulChip::default();
        chips.push(RiscvAir::Mul(mul));
        let shift_right = ShiftRightChip::default();
        chips.push(RiscvAir::ShiftRight(shift_right));
        let shift_left = ShiftLeft::default();
        chips.push(RiscvAir::ShiftLeft(shift_left));
        let lt = LtChip::default();
        chips.push(RiscvAir::Lt(lt));
        let memory_init = MemoryGlobalChip::new(MemoryChipKind::Init);
        chips.push(RiscvAir::MemoryInit(memory_init));
        let memory_finalize = MemoryGlobalChip::new(MemoryChipKind::Finalize);
        chips.push(RiscvAir::MemoryFinal(memory_finalize));
        let program_memory_init = MemoryGlobalChip::new(MemoryChipKind::Program);
        chips.push(RiscvAir::ProgramMemory(program_memory_init));
        let field_ltu = FieldLTUChip::default();
        chips.push(RiscvAir::FieldLTU(field_ltu));
        let byte = ByteChip::default();
        chips.push(RiscvAir::ByteLookup(byte));

        chips
    }

    /// Returns `true` if the given `shard` includes events for this AIR.
    pub fn included(&self, shard: &ExecutionRecord) -> bool {
        match self {
            RiscvAir::Program(_) => true,
            RiscvAir::Cpu(_) => true,
            RiscvAir::Add(_) => !shard.add_events.is_empty(),
            RiscvAir::Sub(_) => !shard.sub_events.is_empty(),
            RiscvAir::Bitwise(_) => !shard.bitwise_events.is_empty(),
            RiscvAir::Mul(_) => !shard.mul_events.is_empty(),
            RiscvAir::DivRem(_) => !shard.divrem_events.is_empty(),
            RiscvAir::Lt(_) => !shard.lt_events.is_empty(),
            RiscvAir::ShiftLeft(_) => !shard.shift_left_events.is_empty(),
            RiscvAir::ShiftRight(_) => !shard.shift_right_events.is_empty(),
            RiscvAir::ByteLookup(_) => !shard.byte_lookups.is_empty(),
            RiscvAir::FieldLTU(_) => !shard.field_events.is_empty(),
            RiscvAir::MemoryInit(_) => !shard.first_memory_record.is_empty(),
            RiscvAir::MemoryFinal(_) => !shard.last_memory_record.is_empty(),
            RiscvAir::ProgramMemory(_) => !shard.program_memory_record.is_empty(),
            RiscvAir::Sha256Extend(_) => !shard.sha_extend_events.is_empty(),
            RiscvAir::Sha256Compress(_) => !shard.sha_compress_events.is_empty(),
            RiscvAir::Ed25519Add(_) => !shard.ed_add_events.is_empty(),
            RiscvAir::Ed25519Decompress(_) => !shard.ed_decompress_events.is_empty(),
            RiscvAir::K256Decompress(_) => !shard.k256_decompress_events.is_empty(),
            RiscvAir::Secp256k1Add(_) => !shard.weierstrass_add_events.is_empty(),
            RiscvAir::Secp256k1Double(_) => !shard.weierstrass_double_events.is_empty(),
            RiscvAir::KeccakP(_) => !shard.keccak_permute_events.is_empty(),
            RiscvAir::Blake3Compress(_) => !shard.blake3_compress_inner_events.is_empty(),
            RiscvAir::FriFold(_) => !shard.fri_fold_events.is_empty(),
        }
    }
}

impl<F: PrimeField32> PartialEq for RiscvAir<F> {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl<F: PrimeField32> Eq for RiscvAir<F> {}

impl<F: PrimeField32> core::hash::Hash for RiscvAir<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}
