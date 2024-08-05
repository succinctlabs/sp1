use super::StarkMachine;
pub use crate::air::SP1AirBuilder;
use crate::air::{MachineAir, SP1_PROOF_NUM_PV_ELTS};
use crate::memory::{MemoryChipType, MemoryProgramChip};
use crate::operations::field::field_op::FieldOperation;
use crate::stark::Chip;
use crate::syscall::precompiles::fptower::Fp2AddSubAssignChip;
use crate::utils::ec::weierstrass::bls12_381::Bls12381BaseField;
use crate::utils::ec::weierstrass::bn254::Bn254BaseField;
use crate::StarkGenericConfig;
use p3_field::PrimeField32;
pub use riscv_chips::*;
use tracing::instrument;

/// A module for importing all the different RISC-V chips.
pub(crate) mod riscv_chips {
    pub use crate::alu::AddSubChip;
    pub use crate::alu::BitwiseChip;
    pub use crate::alu::DivRemChip;
    pub use crate::alu::LtChip;
    pub use crate::alu::MulChip;
    pub use crate::alu::ShiftLeft;
    pub use crate::alu::ShiftRightChip;
    pub use crate::bytes::ByteChip;
    pub use crate::cpu::CpuChip;
    pub use crate::memory::MemoryChip;
    pub use crate::program::ProgramChip;
    pub use crate::syscall::precompiles::edwards::EdAddAssignChip;
    pub use crate::syscall::precompiles::edwards::EdDecompressChip;
    pub use crate::syscall::precompiles::fptower::Fp2MulAssignChip;
    pub use crate::syscall::precompiles::fptower::FpOpChip;
    pub use crate::syscall::precompiles::keccak256::KeccakPermuteChip;
    pub use crate::syscall::precompiles::sha256::ShaCompressChip;
    pub use crate::syscall::precompiles::sha256::ShaExtendChip;
    pub use crate::syscall::precompiles::uint256::Uint256MulChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassAddAssignChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassDecompressChip;
    pub use crate::syscall::precompiles::weierstrass::WeierstrassDoubleAssignChip;
    pub use crate::utils::ec::edwards::ed25519::Ed25519Parameters;
    pub use crate::utils::ec::edwards::EdwardsCurve;
    pub use crate::utils::ec::weierstrass::bls12_381::Bls12381Parameters;
    pub use crate::utils::ec::weierstrass::bn254::Bn254Parameters;
    pub use crate::utils::ec::weierstrass::secp256k1::Secp256k1Parameters;
    pub use crate::utils::ec::weierstrass::SwCurve;
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
    /// An AIR for the RISC-V Add and SUB instruction.
    Add(AddSubChip),
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
    /// A table for initializing the memory state.
    MemoryInit(MemoryChip),
    /// A table for finalizing the memory state.
    MemoryFinal(MemoryChip),
    /// A table for initializing the program memory.
    ProgramMemory(MemoryProgramChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),
    /// A precompile for decompressing a point on the K256 curve.
    K256Decompress(WeierstrassDecompressChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for the Keccak permutation.
    KeccakP(KeccakPermuteChip),
    /// A precompile for addition on the Elliptic curve bn254.
    Bn254Add(WeierstrassAddAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bn254.
    Bn254Double(WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>>),
    /// A precompile for addition on the Elliptic curve bls12_381.
    Bls12381Add(WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve bls12_381.
    Bls12381Double(WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for uint256 mul.
    Uint256Mul(Uint256MulChip),
    /// A precompile for decompressing a point on the BLS12-381 curve.
    Bls12381Decompress(WeierstrassDecompressChip<SwCurve<Bls12381Parameters>>),
    /// A precompile for BLS12-381 fp operation.
    Bls12381Fp(FpOpChip<Bls12381BaseField>),
    /// A precompile for BLS12-381 fp2 multiplication.
    Bls12381Fp2Mul(Fp2MulAssignChip<Bls12381BaseField>),
    /// A precompile for BLS12-381 fp2 addition/subtraction.
    Bls12381Fp2AddSub(Fp2AddSubAssignChip<Bls12381BaseField>),
    /// A precompile for BN-254 fp operation.
    Bn254Fp(FpOpChip<Bn254BaseField>),
    /// A precompile for BN-254 fp2 multiplication.
    Bn254Fp2Mul(Fp2MulAssignChip<Bn254BaseField>),
    /// A precompile for BN-254 fp2 addition/subtraction.
    Bn254Fp2AddSub(Fp2AddSubAssignChip<Bn254BaseField>),
}

impl<F: PrimeField32> RiscvAir<F> {
    #[instrument("construct RiscvAir machine", level = "debug", skip_all)]
    pub fn machine<SC: StarkGenericConfig<Val = F>>(config: SC) -> StarkMachine<SC, Self> {
        let chips = Self::get_all()
            .into_iter()
            .map(Chip::new)
            .collect::<Vec<_>>();
        StarkMachine::new(config, chips, SP1_PROOF_NUM_PV_ELTS)
    }

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
        let k256_decompress =
            WeierstrassDecompressChip::<SwCurve<Secp256k1Parameters>>::with_lsb_rule();
        chips.push(RiscvAir::K256Decompress(k256_decompress));
        let secp256k1_add_assign = WeierstrassAddAssignChip::<SwCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Add(secp256k1_add_assign));
        let secp256k1_double_assign =
            WeierstrassDoubleAssignChip::<SwCurve<Secp256k1Parameters>>::new();
        chips.push(RiscvAir::Secp256k1Double(secp256k1_double_assign));
        let keccak_permute = KeccakPermuteChip::new();
        chips.push(RiscvAir::KeccakP(keccak_permute));
        let bn254_add_assign = WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>>::new();
        chips.push(RiscvAir::Bn254Add(bn254_add_assign));
        let bn254_double_assign = WeierstrassDoubleAssignChip::<SwCurve<Bn254Parameters>>::new();
        chips.push(RiscvAir::Bn254Double(bn254_double_assign));
        let bls12381_add = WeierstrassAddAssignChip::<SwCurve<Bls12381Parameters>>::new();
        chips.push(RiscvAir::Bls12381Add(bls12381_add));
        let bls12381_double = WeierstrassDoubleAssignChip::<SwCurve<Bls12381Parameters>>::new();
        chips.push(RiscvAir::Bls12381Double(bls12381_double));
        let uint256_mul = Uint256MulChip::default();
        chips.push(RiscvAir::Uint256Mul(uint256_mul));
        let bls12381_fp_add = FpOpChip::<Bls12381BaseField>::new(FieldOperation::Add);
        chips.push(RiscvAir::Bls12381Fp(bls12381_fp_add));
        let bls12381_fp_sub = FpOpChip::<Bls12381BaseField>::new(FieldOperation::Sub);
        chips.push(RiscvAir::Bls12381Fp(bls12381_fp_sub));
        let bls12381_fp2_add = Fp2AddSubAssignChip::<Bls12381BaseField>::new(FieldOperation::Add);
        chips.push(RiscvAir::Bls12381Fp2AddSub(bls12381_fp2_add));
        let bls12381_fp2_sub = Fp2AddSubAssignChip::<Bls12381BaseField>::new(FieldOperation::Sub);
        chips.push(RiscvAir::Bls12381Fp2AddSub(bls12381_fp2_sub));
        let bls12381_fp_mul = FpOpChip::<Bls12381BaseField>::new(FieldOperation::Mul);
        chips.push(RiscvAir::Bls12381Fp(bls12381_fp_mul));
        let bls12381_fp2_mul = Fp2MulAssignChip::<Bls12381BaseField>::new();
        chips.push(RiscvAir::Bls12381Fp2Mul(bls12381_fp2_mul));
        let bn254_fp_add = FpOpChip::<Bn254BaseField>::new(FieldOperation::Add);
        chips.push(RiscvAir::Bn254Fp(bn254_fp_add));
        let bn254_fp_sub = FpOpChip::<Bn254BaseField>::new(FieldOperation::Sub);
        chips.push(RiscvAir::Bn254Fp(bn254_fp_sub));
        let bn254_fp_mul = FpOpChip::<Bn254BaseField>::new(FieldOperation::Mul);
        chips.push(RiscvAir::Bn254Fp(bn254_fp_mul));
        let bn254_fp2_add = Fp2AddSubAssignChip::<Bn254BaseField>::new(FieldOperation::Add);
        chips.push(RiscvAir::Bn254Fp2AddSub(bn254_fp2_add));
        let bn254_fp2_sub = Fp2AddSubAssignChip::<Bn254BaseField>::new(FieldOperation::Sub);
        chips.push(RiscvAir::Bn254Fp2AddSub(bn254_fp2_sub));
        let bn254_fp2_mul = Fp2MulAssignChip::<Bn254BaseField>::new();
        chips.push(RiscvAir::Bn254Fp2Mul(bn254_fp2_mul));
        let bls12381_decompress =
            WeierstrassDecompressChip::<SwCurve<Bls12381Parameters>>::with_lexicographic_rule();
        chips.push(RiscvAir::Bls12381Decompress(bls12381_decompress));
        let div_rem = DivRemChip::default();
        chips.push(RiscvAir::DivRem(div_rem));
        let add = AddSubChip::default();
        chips.push(RiscvAir::Add(add));
        let bitwise = BitwiseChip::default();
        chips.push(RiscvAir::Bitwise(bitwise));
        let mul = MulChip::default();
        chips.push(RiscvAir::Mul(mul));
        let shift_right = ShiftRightChip::default();
        chips.push(RiscvAir::ShiftRight(shift_right));
        let shift_left = ShiftLeft::default();
        chips.push(RiscvAir::ShiftLeft(shift_left));
        let lt = LtChip::default();
        chips.push(RiscvAir::Lt(lt));
        let memory_init = MemoryChip::new(MemoryChipType::Initialize);
        chips.push(RiscvAir::MemoryInit(memory_init));
        let memory_finalize = MemoryChip::new(MemoryChipType::Finalize);
        chips.push(RiscvAir::MemoryFinal(memory_finalize));
        let program_memory_init = MemoryProgramChip::new();
        chips.push(RiscvAir::ProgramMemory(program_memory_init));
        let byte = ByteChip::default();
        chips.push(RiscvAir::ByteLookup(byte));

        chips
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
