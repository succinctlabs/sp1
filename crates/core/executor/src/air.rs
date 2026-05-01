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
    /// The SHA-256 compress chip.
    ShaCompress = 3,
    /// The sha compress control chip.
    ShaCompressControl = 4,
    /// The Edwards add assign chip.
    EdAddAssign = 5,
    /// The Edwards decompress chip.
    EdDecompress = 6,
    /// The secp256k1 add assign chip.
    Secp256k1AddAssign = 7,
    /// The secp256k1 double assign chip.
    Secp256k1DoubleAssign = 8,
    /// The secp256r1 add assign chip.
    Secp256r1AddAssign = 9,
    /// The secp256r1 double assign chip.
    Secp256r1DoubleAssign = 10,
    /// The Keccak permute chip.
    KeccakPermute = 11,
    /// The keccak permute control chip.
    KeccakPermuteControl = 12,
    /// The bn254 add assign chip.
    Bn254AddAssign = 13,
    /// The bn254 double assign chip.
    Bn254DoubleAssign = 14,
    /// The bls12-381 add assign chip.
    Bls12381AddAssign = 15,
    /// The bls12-381 double assign chip.
    Bls12381DoubleAssign = 16,
    /// The uint256 mul mod chip.
    Uint256MulMod = 17,
    /// The uint256 ops chip.
    Uint256Ops = 18,
    /// The bls12-381 fp op assign chip.
    Bls12381FpOpAssign = 19,
    /// The bls12-831 fp2 add sub assign chip.
    Bls12381Fp2AddSubAssign = 20,
    /// The bls12-831 fp2 mul assign chip.
    Bls12381Fp2MulAssign = 21,
    /// The bn254 fp2 add sub assign chip.
    Bn254FpOpAssign = 22,
    /// The bn254 fp op assign chip.
    Bn254Fp2AddSubAssign = 23,
    /// The bn254 fp2 mul assign chip.
    Bn254Fp2MulAssign = 24,
    /// The syscall core chip.
    #[subenum(CoreAirId)]
    SyscallCore = 25,
    /// The syscall precompile chip.
    SyscallPrecompile = 26,
    /// The div rem chip.
    #[subenum(CoreAirId)]
    DivRem = 27,
    /// The add chip.
    #[subenum(CoreAirId)]
    Add = 28,
    /// The addi chip.
    #[subenum(CoreAirId)]
    Addi = 29,
    /// The addw chip.
    #[subenum(CoreAirId)]
    Addw = 30,
    /// The sub chip.
    #[subenum(CoreAirId)]
    Sub = 31,
    /// The subw chip.
    #[subenum(CoreAirId)]
    Subw = 32,
    /// The bitwise chip.
    #[subenum(CoreAirId)]
    Bitwise = 33,
    /// The mul chip.
    #[subenum(CoreAirId)]
    Mul = 34,
    /// The shift right chip.
    #[subenum(CoreAirId)]
    ShiftRight = 35,
    /// The shift left chip.
    #[subenum(CoreAirId)]
    ShiftLeft = 36,
    /// The lt chip.
    #[subenum(CoreAirId)]
    Lt = 37,
    /// The load byte chip.
    #[subenum(CoreAirId)]
    LoadByte = 38,
    /// The load half chip.
    #[subenum(CoreAirId)]
    LoadHalf = 39,
    /// The load word chip.
    #[subenum(CoreAirId)]
    LoadWord = 40,
    /// The load x0 chip.
    #[subenum(CoreAirId)]
    LoadX0 = 41,
    /// The load double chip.
    #[subenum(CoreAirId)]
    LoadDouble = 42,
    /// The store byte chip.
    #[subenum(CoreAirId)]
    StoreByte = 43,
    /// The store half chip.
    #[subenum(CoreAirId)]
    StoreHalf = 44,
    /// The store word chip.
    #[subenum(CoreAirId)]
    StoreWord = 45,
    /// The store double chip.
    #[subenum(CoreAirId)]
    StoreDouble = 46,
    /// The utype chip.
    #[subenum(CoreAirId)]
    UType = 47,
    /// The branch chip.
    #[subenum(CoreAirId)]
    Branch = 48,
    /// The jal chip.
    #[subenum(CoreAirId)]
    Jal = 49,
    /// The jalr chip.
    #[subenum(CoreAirId)]
    Jalr = 50,
    /// The syscall instructions chip.
    #[subenum(CoreAirId)]
    SyscallInstrs = 51,
    /// The memory bump chip.
    #[subenum(CoreAirId)]
    MemoryBump = 52,
    /// The state bump chip.
    #[subenum(CoreAirId)]
    StateBump = 53,
    /// The memory global init chip.
    MemoryGlobalInit = 54,
    /// The memory global finalize chip.
    MemoryGlobalFinalize = 55,
    /// The memory local chip.
    #[subenum(CoreAirId)]
    MemoryLocal = 56,
    /// The global chip.
    #[subenum(CoreAirId)]
    Global = 57,
    /// The byte chip.
    Byte = 58,
    /// The range chip.
    Range = 59,
    /// The poseidon2 chip.
    Poseidon2 = 60,
    /// The ALU x0 chip (all ALU ops with rd = x0).
    #[subenum(CoreAirId)]
    AluX0 = 61,
    /// The septic curve add assign chip.
    SepticAddAssign = 62,
    /// The septic curve double assign chip.
    SepticDoubleAssign = 63,
    /// The septic curve scalar mul assign chip.
    SepticScalarMulAssign = 64,
    /// The septic curve Schnorr verify chip (Shamir's trick).
    SepticVerify = 65,
}

impl RiscvAirId {
    /// Returns the AIRs that are not part of precompile shards and not the program or byte AIR.
    #[must_use]
    pub fn core() -> Vec<RiscvAirId> {
        vec![
            RiscvAirId::Add,
            RiscvAirId::Addi,
            RiscvAirId::Addw,
            RiscvAirId::Sub,
            RiscvAirId::Subw,
            RiscvAirId::Mul,
            RiscvAirId::Bitwise,
            RiscvAirId::ShiftLeft,
            RiscvAirId::ShiftRight,
            RiscvAirId::DivRem,
            RiscvAirId::Lt,
            RiscvAirId::UType,
            RiscvAirId::MemoryLocal,
            RiscvAirId::MemoryBump,
            RiscvAirId::StateBump,
            RiscvAirId::LoadByte,
            RiscvAirId::LoadHalf,
            RiscvAirId::LoadWord,
            RiscvAirId::LoadDouble,
            RiscvAirId::LoadX0,
            RiscvAirId::StoreByte,
            RiscvAirId::StoreHalf,
            RiscvAirId::StoreWord,
            RiscvAirId::StoreDouble,
            RiscvAirId::Branch,
            RiscvAirId::Jal,
            RiscvAirId::Jalr,
            RiscvAirId::SyscallCore,
            RiscvAirId::SyscallInstrs,
            RiscvAirId::Global,
            RiscvAirId::AluX0,
        ]
    }

    /// TODO replace these three with subenums or something
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
            RiscvAirId::MemoryGlobalInit | RiscvAirId::MemoryGlobalFinalize | RiscvAirId::Global
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
                | RiscvAirId::SepticAddAssign
                | RiscvAirId::SepticDoubleAssign
                | RiscvAirId::SepticScalarMulAssign
                | RiscvAirId::SepticVerify
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
    pub fn control_air_id(self) -> Option<RiscvAirId> {
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
