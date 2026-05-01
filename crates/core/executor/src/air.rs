use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

use deepsize2::DeepSizeOf;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};
use sp1_hypercube::shape::Shape;
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};
use subenum::subenum;

/// RV64IM AIR Identifiers.
///
/// These identifiers are for the various chips in the rv64im prover. We need them in the
/// executor to compute the memory cost of the current shard of execution.
///
/// The [`CoreAirId`]s are the AIRs that are not part of precompile shards and not the program or
/// byte AIR.
#[subenum(CoreAirId)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    IntoStaticStr,
    PartialOrd,
    Ord,
    Enum,
    DeepSizeOf,
)]
pub enum RiscvAirId {
    /// The program chip.
    Program = 0,
    /// The SHA-256 extend chip.
    ShaExtend = 1,
    /// The sha extend control chip.
    ShaExtendControl = 2,
    /// The sha extend control chip for user mode.
    ShaExtendControlUser = 3,
    /// The SHA-256 compress chip.
    ShaCompress = 4,
    /// The sha compress control chip.
    ShaCompressControl = 5,
    /// The sha compress control chip for user mode.
    ShaCompressControlUser = 6,
    /// The Edwards add assign chip.
    EdAddAssign = 7,
    /// The Edwards add assign chip for user mode.
    EdAddAssignUser = 8,
    /// The Edwards decompress chip.
    EdDecompress = 9,
    /// The Edwards decompress chip for user mode.
    EdDecompressUser = 10,
    /// The secp256k1 add assign chip.
    Secp256k1AddAssign = 11,
    /// The secp256k1 add assign chip for user mode.
    Secp256k1AddAssignUser = 12,
    /// The secp256k1 double assign chip.
    Secp256k1DoubleAssign = 13,
    /// The secp256k1 double assign chip for user mode.
    Secp256k1DoubleAssignUser = 14,
    /// The secp256r1 add assign chip.
    Secp256r1AddAssign = 15,
    /// The secp256r1 add assign chip for user mode.
    Secp256r1AddAssignUser = 16,
    /// The secp256r1 double assign chip.
    Secp256r1DoubleAssign = 17,
    /// The secp256r1 double assign chip for user mode.
    Secp256r1DoubleAssignUser = 18,
    /// The Keccak permute chip.
    KeccakPermute = 19,
    /// The keccak permute control chip.
    KeccakPermuteControl = 20,
    /// The keccak permute control chip for user mode.
    KeccakPermuteControlUser = 21,
    /// The bn254 add assign chip.
    Bn254AddAssign = 22,
    /// The bn254 add assign chip for user mode.
    Bn254AddAssignUser = 23,
    /// The bn254 double assign chip.
    Bn254DoubleAssign = 24,
    /// The bn254 double assign chip for user mode.
    Bn254DoubleAssignUser = 25,
    /// The bls12-381 add assign chip.
    Bls12381AddAssign = 26,
    /// The bls12-381 add assign chip for user mode.
    Bls12381AddAssignUser = 27,
    /// The bls12-381 double assign chip.
    Bls12381DoubleAssign = 28,
    /// The bls12-381 double assign chip for user mode.
    Bls12381DoubleAssignUser = 29,
    /// The uint256 mul mod chip.
    Uint256MulMod = 30,
    /// The uint256 mul mod chip for user mode.
    Uint256MulModUser = 31,
    /// The uint256 ops chip.
    Uint256Ops = 32,
    /// The uint256 ops chip for user mode.
    Uint256OpsUser = 33,
    /// The bls12-381 fp op assign chip.
    Bls12381FpOpAssign = 34,
    /// The bls12-381 fp op assign chip for user mode.
    Bls12381FpOpAssignUser = 35,
    /// The bls12-381 fp2 add sub assign chip.
    Bls12381Fp2AddSubAssign = 36,
    /// The bls12-381 fp2 add sub assign chip for user mode.
    Bls12381Fp2AddSubAssignUser = 37,
    /// The bls12-381 fp2 mul assign chip.
    Bls12381Fp2MulAssign = 38,
    /// The bls12-381 fp2 mul assign chip for user mode.
    Bls12381Fp2MulAssignUser = 39,
    /// The bn254 fp op assign chip.
    Bn254FpOpAssign = 40,
    /// The bn254 fp op assign chip for user mode.
    Bn254FpOpAssignUser = 41,
    /// The bn254 fp2 add sub assign chip.
    Bn254Fp2AddSubAssign = 42,
    /// The bn254 fp2 add sub assign chip for user mode.
    Bn254Fp2AddSubAssignUser = 43,
    /// The bn254 fp2 mul assign chip.
    Bn254Fp2MulAssign = 44,
    /// The bn254 fp2 mul assign chip for user mode.
    Bn254Fp2MulAssignUser = 45,
    /// The poseidon2 chip.
    Poseidon2 = 46,
    /// The poseidon2 chip for user mode.
    Poseidon2User = 47,
    /// The syscall core chip.
    #[subenum(CoreAirId)]
    SyscallCore = 48,
    /// The syscall core chip for user mode.
    #[subenum(CoreAirId)]
    SyscallCoreUser = 49,
    /// The syscall precompile chip.
    SyscallPrecompile = 50,
    /// The syscall precompile chip for user mode.
    SyscallPrecompileUser = 51,
    /// The div rem chip.
    #[subenum(CoreAirId)]
    DivRem = 52,
    /// The div rem chip for user mode.
    #[subenum(CoreAirId)]
    DivRemUser = 53,
    /// The add chip.
    #[subenum(CoreAirId)]
    Add = 54,
    /// The add chip for user mode.
    #[subenum(CoreAirId)]
    AddUser = 55,
    /// The addi chip.
    #[subenum(CoreAirId)]
    Addi = 56,
    /// The addi chip for user mode.
    #[subenum(CoreAirId)]
    AddiUser = 57,
    /// The addw chip.
    #[subenum(CoreAirId)]
    Addw = 58,
    /// The addw chip for user mode.
    #[subenum(CoreAirId)]
    AddwUser = 59,
    /// The sub chip.
    #[subenum(CoreAirId)]
    Sub = 60,
    /// The sub chip for user mode.
    #[subenum(CoreAirId)]
    SubUser = 61,
    /// The subw chip.
    #[subenum(CoreAirId)]
    Subw = 62,
    /// The subw chip for user mode.
    #[subenum(CoreAirId)]
    SubwUser = 63,
    /// The bitwise chip.
    #[subenum(CoreAirId)]
    Bitwise = 64,
    /// The bitwise chip for user mode.
    #[subenum(CoreAirId)]
    BitwiseUser = 65,
    /// The mul chip.
    #[subenum(CoreAirId)]
    Mul = 66,
    /// The mul chip for user mode.
    #[subenum(CoreAirId)]
    MulUser = 67,
    /// The shift right chip.
    #[subenum(CoreAirId)]
    ShiftRight = 68,
    /// The shift right chip for user mode.
    #[subenum(CoreAirId)]
    ShiftRightUser = 69,
    /// The shift left chip.
    #[subenum(CoreAirId)]
    ShiftLeft = 70,
    /// The shift left chip for user mode.
    #[subenum(CoreAirId)]
    ShiftLeftUser = 71,
    /// The lt chip.
    #[subenum(CoreAirId)]
    Lt = 72,
    /// The lt chip for user mode.
    #[subenum(CoreAirId)]
    LtUser = 73,
    /// The load byte chip.
    #[subenum(CoreAirId)]
    LoadByte = 74,
    /// The load byte chip for user mode.
    #[subenum(CoreAirId)]
    LoadByteUser = 75,
    /// The load half chip.
    #[subenum(CoreAirId)]
    LoadHalf = 76,
    /// The load half chip for user mode.
    #[subenum(CoreAirId)]
    LoadHalfUser = 77,
    /// The load word chip.
    #[subenum(CoreAirId)]
    LoadWord = 78,
    /// The load word chip for user mode.
    #[subenum(CoreAirId)]
    LoadWordUser = 79,
    /// The load x0 chip.
    #[subenum(CoreAirId)]
    LoadX0 = 80,
    /// The load x0 chip for user mode.
    #[subenum(CoreAirId)]
    LoadX0User = 81,
    /// The load double chip.
    #[subenum(CoreAirId)]
    LoadDouble = 82,
    /// The load double chip for user mode.
    #[subenum(CoreAirId)]
    LoadDoubleUser = 83,
    /// The store byte chip.
    #[subenum(CoreAirId)]
    StoreByte = 84,
    /// The store byte chip for user mode.
    #[subenum(CoreAirId)]
    StoreByteUser = 85,
    /// The store half chip.
    #[subenum(CoreAirId)]
    StoreHalf = 86,
    /// The store half chip for user mode.
    #[subenum(CoreAirId)]
    StoreHalfUser = 87,
    /// The store word chip.
    #[subenum(CoreAirId)]
    StoreWord = 88,
    /// The store word chip for user mode.
    #[subenum(CoreAirId)]
    StoreWordUser = 89,
    /// The store double chip.
    #[subenum(CoreAirId)]
    StoreDouble = 90,
    /// The store double chip for user mode.
    #[subenum(CoreAirId)]
    StoreDoubleUser = 91,
    /// The utype chip.
    #[subenum(CoreAirId)]
    UType = 92,
    /// The utype chip for user mode.
    #[subenum(CoreAirId)]
    UTypeUser = 93,
    /// The branch chip.
    #[subenum(CoreAirId)]
    Branch = 94,
    /// The branch chip for user mode.
    #[subenum(CoreAirId)]
    BranchUser = 95,
    /// The jal chip.
    #[subenum(CoreAirId)]
    Jal = 96,
    /// The jal chip for user mode.
    #[subenum(CoreAirId)]
    JalUser = 97,
    /// The jalr chip.
    #[subenum(CoreAirId)]
    Jalr = 98,
    /// The jalr chip for user mode.
    #[subenum(CoreAirId)]
    JalrUser = 99,
    /// The syscall instructions chip.
    #[subenum(CoreAirId)]
    SyscallInstrs = 100,
    /// The syscall instructions chip for user mode.
    #[subenum(CoreAirId)]
    SyscallInstrsUser = 101,
    /// The memory bump chip.
    #[subenum(CoreAirId)]
    MemoryBump = 102,
    /// The state bump chip.
    #[subenum(CoreAirId)]
    StateBump = 103,
    /// The memory global init chip.
    MemoryGlobalInit = 104,
    /// The memory global finalize chip.
    MemoryGlobalFinalize = 105,
    /// The memory local chip.
    #[subenum(CoreAirId)]
    MemoryLocal = 106,
    /// The global chip.
    #[subenum(CoreAirId)]
    Global = 107,
    /// The byte chip.
    Byte = 108,
    /// The range chip.
    Range = 109,
    /// The ALU x0 chip (all ALU ops with rd = x0).
    #[subenum(CoreAirId)]
    AluX0 = 110,
    /// The ALU x0 chip (all ALU ops with rd = x0) for user mode.
    #[subenum(CoreAirId)]
    AluX0User = 111,
    /// The mprotect chip.
    #[subenum(CoreAirId)]
    Mprotect = 112,
    /// The sigreturn chip.
    SigReturn = 113,
    /// The instruction decode chip.
    #[subenum(CoreAirId)]
    InstructionDecode = 114,
    /// The instruction fetch chip.
    #[subenum(CoreAirId)]
    InstructionFetch = 115,
    /// The page prot chip.
    #[subenum(CoreAirId)]
    PageProt = 116,
    /// The page prot local chip.
    #[subenum(CoreAirId)]
    PageProtLocal = 117,
    /// The page prot global init chip.
    PageProtGlobalInit = 118,
    /// The page prot global finalize chip.
    PageProtGlobalFinalize = 119,
    /// The trap exec chip.
    #[subenum(CoreAirId)]
    TrapExec = 120,
    /// The trap memory chip.
    #[subenum(CoreAirId)]
    TrapMem = 121,
}

impl RiscvAirId {
    /// Returns the AIRs that are not part of precompile shards and not the program or byte AIR.
    #[must_use]
    pub fn core() -> Vec<RiscvAirId> {
        vec![
            RiscvAirId::Add,
            RiscvAirId::AddUser,
            RiscvAirId::Addi,
            RiscvAirId::AddiUser,
            RiscvAirId::Addw,
            RiscvAirId::AddwUser,
            RiscvAirId::Sub,
            RiscvAirId::SubUser,
            RiscvAirId::Subw,
            RiscvAirId::SubwUser,
            RiscvAirId::Mul,
            RiscvAirId::MulUser,
            RiscvAirId::Bitwise,
            RiscvAirId::BitwiseUser,
            RiscvAirId::ShiftLeft,
            RiscvAirId::ShiftLeftUser,
            RiscvAirId::ShiftRight,
            RiscvAirId::ShiftRightUser,
            RiscvAirId::DivRem,
            RiscvAirId::DivRemUser,
            RiscvAirId::Lt,
            RiscvAirId::LtUser,
            RiscvAirId::UType,
            RiscvAirId::UTypeUser,
            RiscvAirId::MemoryLocal,
            RiscvAirId::MemoryBump,
            RiscvAirId::StateBump,
            RiscvAirId::LoadByte,
            RiscvAirId::LoadByteUser,
            RiscvAirId::LoadHalf,
            RiscvAirId::LoadHalfUser,
            RiscvAirId::LoadWord,
            RiscvAirId::LoadWordUser,
            RiscvAirId::LoadDouble,
            RiscvAirId::LoadDoubleUser,
            RiscvAirId::LoadX0,
            RiscvAirId::LoadX0User,
            RiscvAirId::StoreByte,
            RiscvAirId::StoreByteUser,
            RiscvAirId::StoreHalf,
            RiscvAirId::StoreHalfUser,
            RiscvAirId::StoreWord,
            RiscvAirId::StoreWordUser,
            RiscvAirId::StoreDouble,
            RiscvAirId::StoreDoubleUser,
            RiscvAirId::Branch,
            RiscvAirId::BranchUser,
            RiscvAirId::Jal,
            RiscvAirId::JalUser,
            RiscvAirId::Jalr,
            RiscvAirId::JalrUser,
            RiscvAirId::SyscallCore,
            RiscvAirId::SyscallInstrs,
            RiscvAirId::SyscallInstrsUser,
            RiscvAirId::Global,
            RiscvAirId::AluX0,
            RiscvAirId::AluX0User,
            RiscvAirId::Mprotect,
            RiscvAirId::InstructionDecode,
            RiscvAirId::InstructionFetch,
            RiscvAirId::PageProt,
            RiscvAirId::PageProtLocal,
            RiscvAirId::TrapExec,
            RiscvAirId::TrapMem,
        ]
    }

    /// Whether the ID represents a core AIR.
    #[must_use]
    pub fn is_core(self) -> bool {
        CoreAirId::try_from(self).is_ok()
    }

    /// Whether the ID represents a memory AIR.
    #[must_use]
    pub fn is_memory(self) -> bool {
        matches!(
            self,
            RiscvAirId::MemoryGlobalInit
                | RiscvAirId::MemoryGlobalFinalize
                | RiscvAirId::PageProtGlobalInit
                | RiscvAirId::PageProtGlobalFinalize
                | RiscvAirId::Global
        )
    }

    /// Whether the ID represents a precompile AIR.
    #[must_use]
    pub fn is_precompile(self) -> bool {
        matches!(
            self,
            RiscvAirId::ShaExtend
                | RiscvAirId::ShaCompress
                | RiscvAirId::EdAddAssign
                | RiscvAirId::EdDecompress
                | RiscvAirId::Secp256k1AddAssign
                | RiscvAirId::Secp256k1DoubleAssign
                | RiscvAirId::Secp256r1AddAssign
                | RiscvAirId::Secp256r1DoubleAssign
                | RiscvAirId::KeccakPermute
                | RiscvAirId::Bn254AddAssign
                | RiscvAirId::Bn254DoubleAssign
                | RiscvAirId::Bls12381AddAssign
                | RiscvAirId::Bls12381DoubleAssign
                | RiscvAirId::Uint256MulMod
                | RiscvAirId::Uint256Ops
                | RiscvAirId::Bls12381FpOpAssign
                | RiscvAirId::Bls12381Fp2AddSubAssign
                | RiscvAirId::Bls12381Fp2MulAssign
                | RiscvAirId::Bn254FpOpAssign
                | RiscvAirId::Bn254Fp2AddSubAssign
                | RiscvAirId::Bn254Fp2MulAssign
                | RiscvAirId::Poseidon2
                | RiscvAirId::SigReturn
        )
    }

    /// The number of rows in the AIR produced by each event.
    #[must_use]
    pub fn rows_per_event(&self) -> usize {
        match self {
            Self::ShaCompress => 80,
            Self::ShaExtend => 48,
            Self::KeccakPermute => 24,
            _ => 1,
        }
    }

    /// Get the ID of the AIR used in the syscall control implementation.
    #[must_use]
    pub fn control_air_id(self, page_protect_enabled: bool) -> Option<RiscvAirId> {
        if page_protect_enabled {
            return match self {
                RiscvAirId::ShaCompress => Some(RiscvAirId::ShaCompressControlUser),
                RiscvAirId::ShaExtend => Some(RiscvAirId::ShaExtendControlUser),
                RiscvAirId::KeccakPermute => Some(RiscvAirId::KeccakPermuteControlUser),
                _ => None,
            };
        }
        match self {
            RiscvAirId::ShaCompress => Some(RiscvAirId::ShaCompressControl),
            RiscvAirId::ShaExtend => Some(RiscvAirId::ShaExtendControl),
            RiscvAirId::KeccakPermute => Some(RiscvAirId::KeccakPermuteControl),
            _ => None,
        }
    }

    /// Returns the string representation of the AIR.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl FromStr for RiscvAirId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let air = Self::iter().find(|chip| chip.as_str() == s);
        match air {
            Some(air) => Ok(air),
            None => Err(format!("Invalid RV64IMAir: {s}")),
        }
    }
}

impl Display for RiscvAirId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.as_str())
    }
}

/// Defines a set of maximal shapes for generating core proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaximalShapes {
    inner: Vec<EnumMap<CoreAirId, u32>>,
}

impl FromIterator<Shape<RiscvAirId>> for MaximalShapes {
    fn from_iter<T: IntoIterator<Item = Shape<RiscvAirId>>>(iter: T) -> Self {
        let mut maximal_shapes = Vec::new();
        for shape in iter {
            let mut maximal_shape = EnumMap::<CoreAirId, u32>::default();
            for (air, height) in shape {
                if let Ok(core_air) = CoreAirId::try_from(air) {
                    maximal_shape[core_air] = height as u32;
                } else if air != RiscvAirId::Program
                    && air != RiscvAirId::Byte
                    && air != RiscvAirId::Range
                {
                    tracing::warn!("Invalid core air: {air}");
                }
            }
            maximal_shapes.push(maximal_shape);
        }
        Self { inner: maximal_shapes }
    }
}

impl MaximalShapes {
    /// Returns an iterator over the maximal shapes.
    pub fn iter(&self) -> impl Iterator<Item = &EnumMap<CoreAirId, u32>> {
        self.inner.iter()
    }
}
