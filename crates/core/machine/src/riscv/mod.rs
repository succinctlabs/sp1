pub use riscv_chips::{ShiftLeft as ShiftLeftChip, *};
use strum::IntoEnumIterator;

use core::fmt;
use std::collections::BTreeSet;

use crate::{
    adapter::bump::StateBumpChip,
    control_flow::{BranchChip, JalChip, JalrChip},
    global::GlobalChip,
    memory::{
        load::{
            load_byte::LoadByteChip, load_double::LoadDoubleChip, load_half::LoadHalfChip,
            load_word::LoadWordChip, load_x0::LoadX0Chip,
        },
        store::{
            store_byte::StoreByteChip, store_double::StoreDoubleChip, store_half::StoreHalfChip,
            store_word::StoreWordChip,
        },
        MemoryBumpChip, MemoryChipType, MemoryLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW,
        NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW, NUM_PAGE_PROT_ENTRIES_PER_ROW,
    },
    range::RangeChip,
    syscall::{
        instructions::SyscallInstrsChip,
        precompiles::fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
    },
    utype::UTypeChip,
};
use hashbrown::HashMap;
use itertools::Itertools;
use slop_algebra::PrimeField32;
use sp1_core_executor::{ExecutionRecord, RiscvAirId};
use sp1_curves::weierstrass::{bls12_381::Bls12381BaseField, bn254::Bn254BaseField};
use sp1_hypercube::{
    air::{MachineAir, SP1_PROOF_NUM_PV_ELTS},
    Chip, Machine, MachineShape,
};
use std::mem::MaybeUninit;
use strum::{EnumDiscriminants, EnumIter};

/// A module for importing all the different RISC-V chips.
pub(crate) mod riscv_chips {
    pub use crate::{
        alu::{
            add::AddChip, addi::AddiChip, addw::AddwChip, sub::SubChip, subw::SubwChip,
            BitwiseChip, DivRemChip, LtChip, MulChip, ShiftLeft, ShiftRightChip,
        },
        bytes::ByteChip,
        memory::MemoryGlobalChip,
        program::ProgramChip,
        syscall::{
            chip::SyscallChip,
            precompiles::{
                edwards::{EdAddAssignChip, EdDecompressChip},
                keccak256::{KeccakPermuteChip, KeccakPermuteControlChip},
                mprotect::MProtectChip,
                poseidon2::Poseidon2Chip,
                blake3::{Blake3CompressChip, Blake3CompressControlChip},
                sha256::{
                    ShaCompressChip, ShaCompressControlChip, ShaExtendChip, ShaExtendControlChip,
                },
                u256x2048_mul::U256x2048MulChip,
                uint256::Uint256MulChip,
                uint256_ops::Uint256OpsChip,
                weierstrass::{
                    WeierstrassAddAssignChip, WeierstrassDecompressChip,
                    WeierstrassDoubleAssignChip,
                },
            },
        },
    };
    pub use sp1_curves::{
        edwards::{ed25519::Ed25519Parameters, EdwardsCurve},
        weierstrass::{
            bls12_381::Bls12381Parameters, bn254::Bn254Parameters, secp256k1::Secp256k1Parameters,
            secp256r1::Secp256r1Parameters, SwCurve,
        },
    };
}

/// The maximum log number of shards in core.
pub const MAX_LOG_NUMBER_OF_SHARDS: usize = 24;

/// The maximum number of shards in core.
pub const MAX_NUMBER_OF_SHARDS: usize = 1 << MAX_LOG_NUMBER_OF_SHARDS;

/// An AIR for encoding RISC-V execution.
///
/// This enum contains all the different AIRs that are used in the Sp1 RISC-V IOP. Each variant is
/// a different AIR that is used to encode a different part of the RISC-V execution, and the
/// different AIR variants have a joint lookup argument.
#[derive(sp1_derive::MachineAir, EnumDiscriminants)]
#[strum_discriminants(derive(Hash, EnumIter, PartialOrd, Ord))]
pub enum RiscvAir<F: PrimeField32> {
    /// An AIR that contains a preprocessed program table and a lookup for the instructions.
    Program(ProgramChip),
    /// An AIR for the RISC-V Add instruction.
    Add(AddChip),
    /// An AIR for the RISC-V Addw instruction.
    Addw(AddwChip),
    /// An AIR for the RISC-V Addi instruction.
    Addi(AddiChip),
    // An AIR for the RISC-V Sub instruction.
    Sub(SubChip),
    /// An AIR for the RISC-V Subw instruction.
    Subw(SubwChip),
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
    /// An AIR for RISC-V memory load byte instructions.
    LoadByte(LoadByteChip),
    /// An AIR for RISC-V memory load half instructions.
    LoadHalf(LoadHalfChip),
    /// An AIR for RISC-V memory load word instructions.
    LoadWord(LoadWordChip),
    /// An AIR for RISC-V memory load double instructions.
    LoadDouble(LoadDoubleChip),
    /// An AIR for RISC-V memory load x0 instructions.
    LoadX0(LoadX0Chip),
    /// An AIR for RISC-V memory store byte instructions.
    StoreByte(StoreByteChip),
    /// An AIR for RISC-V memory store half instructions.
    StoreHalf(StoreHalfChip),
    /// An AIR for RISC-V memory store word instructions.
    StoreWord(StoreWordChip),
    /// An AIR for RISC-V memory store double instructions.
    StoreDouble(StoreDoubleChip),
    /// An AIR for RISC-V UType instruction.
    UType(UTypeChip),
    /// An AIR for RISC-V branch instructions.
    Branch(BranchChip),
    /// An AIR for RISC-V jal instructions.
    Jal(JalChip),
    /// An AIR for RISC-V jalr instructions.
    Jalr(JalrChip),
    /// An AIR for RISC-V ecall instructions.
    SyscallInstrs(SyscallInstrsChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// A lookup table for range operations.
    RangeLookup(RangeChip<F>),
    /// A table for initializing the global memory state.
    MemoryGlobalInit(MemoryGlobalChip),
    /// A table for finalizing the global memory state.
    MemoryGlobalFinal(MemoryGlobalChip),
    /// A table for the local memory state.
    MemoryLocal(MemoryLocalChip),
    /// A table for bumping memory timestamps.
    MemoryBump(MemoryBumpChip),
    /// A table for bumping the state timestamps.
    StateBump(StateBumpChip),
    /// A table for all the syscall invocations.
    SyscallCore(SyscallChip),
    /// A table for all the precompile invocations.
    SyscallPrecompile(SyscallChip),
    /// A table for all the global interactions.
    Global(GlobalChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A controller for sha256 extend.
    Sha256ExtendControl(ShaExtendControlChip),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A controller for sha256 compress.
    Sha256CompressControl(ShaCompressControlChip),
    /// A precompile for blake3 compress.
    Blake3Compress(Blake3CompressChip),
    /// A controller for blake3 compress.
    Blake3CompressControl(Blake3CompressControlChip),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters>),
    /// A precompile for decompressing a point on the K256 curve.
    K256Decompress(WeierstrassDecompressChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for decompressing a point on the P256 curve.
    P256Decompress(WeierstrassDecompressChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>>),
    /// A precompile for addition on the Elliptic curve secp256r1.
    Secp256r1Add(WeierstrassAddAssignChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for doubling a point on the Elliptic curve secp256r1.
    Secp256r1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256r1Parameters>>),
    /// A precompile for the Keccak permutation.
    KeccakP(KeccakPermuteChip),
    /// A controller for the Keccak permutation.
    KeccakPControl(KeccakPermuteControlChip),
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
    /// A precompile for uint256 operations (add/mul with carry).
    Uint256Ops(Uint256OpsChip),
    /// A precompile for u256x2048 mul.
    U256x2048Mul(U256x2048MulChip),
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
    /// A precompile for mprotect syscalls.
    Mprotect(MProtectChip),
    /// A precompile for Poseidon2 permutation.
    Poseidon2(Poseidon2Chip),
}

impl<F: PrimeField32> RiscvAir<F> {
    pub fn id(&self) -> RiscvAirId {
        RiscvAirId::from(RiscvAirDiscriminants::from(self))
    }

    pub fn machine() -> Machine<F, Self> {
        use RiscvAirDiscriminants::*;

        // The order of the chips is used to determine the order of trace generation.
        let chips: Vec<Chip<F, RiscvAir<F>>> = [
            RiscvAir::Program(ProgramChip::default()),
            RiscvAir::Sha256Extend(ShaExtendChip::default()),
            RiscvAir::Sha256ExtendControl(ShaExtendControlChip::default()),
            RiscvAir::Sha256Compress(ShaCompressChip::default()),
            RiscvAir::Sha256CompressControl(ShaCompressControlChip::default()),
            RiscvAir::Blake3Compress(Blake3CompressChip::default()),
            RiscvAir::Blake3CompressControl(Blake3CompressControlChip::default()),
            RiscvAir::Ed25519Add(EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>>::new()),
            RiscvAir::Ed25519Decompress(EdDecompressChip::<Ed25519Parameters>::default()),
            RiscvAir::K256Decompress(
                WeierstrassDecompressChip::<SwCurve<Secp256k1Parameters>>::with_lsb_rule(),
            ),
            RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<SwCurve<Secp256k1Parameters>>::new()),
            RiscvAir::Secp256k1Double(
                WeierstrassDoubleAssignChip::<SwCurve<Secp256k1Parameters>>::new(),
            ),
            RiscvAir::P256Decompress(
                WeierstrassDecompressChip::<SwCurve<Secp256r1Parameters>>::with_lsb_rule(),
            ),
            RiscvAir::Secp256r1Add(WeierstrassAddAssignChip::<SwCurve<Secp256r1Parameters>>::new()),
            RiscvAir::Secp256r1Double(
                WeierstrassDoubleAssignChip::<SwCurve<Secp256r1Parameters>>::new(),
            ),
            RiscvAir::KeccakP(KeccakPermuteChip::new()),
            RiscvAir::KeccakPControl(KeccakPermuteControlChip::new()),
            RiscvAir::Bn254Add(WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>>::new()),
            RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<SwCurve<Bn254Parameters>>::new()),
            RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<SwCurve<Bls12381Parameters>>::new()),
            RiscvAir::Bls12381Double(
                WeierstrassDoubleAssignChip::<SwCurve<Bls12381Parameters>>::new(),
            ),
            RiscvAir::Uint256Mul(Uint256MulChip::default()),
            RiscvAir::Uint256Ops(Uint256OpsChip::default()),
            RiscvAir::U256x2048Mul(U256x2048MulChip::default()),
            RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()),
            RiscvAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<Bls12381BaseField>::new()),
            RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()),
            RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField>::new()),
            RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()),
            RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()),
            RiscvAir::Bls12381Decompress(
                WeierstrassDecompressChip::<SwCurve<Bls12381Parameters>>::with_lexicographic_rule(),
            ),
            RiscvAir::Mprotect(MProtectChip::default()),
            RiscvAir::Poseidon2(Poseidon2Chip::new()),
            RiscvAir::SyscallCore(SyscallChip::core()),
            RiscvAir::SyscallPrecompile(SyscallChip::precompile()),
            RiscvAir::DivRem(DivRemChip::default()),
            RiscvAir::Add(AddChip::default()),
            RiscvAir::Addi(AddiChip::default()),
            RiscvAir::Addw(AddwChip::default()),
            RiscvAir::Sub(SubChip::default()),
            RiscvAir::Subw(SubwChip::default()),
            RiscvAir::Bitwise(BitwiseChip::default()),
            RiscvAir::Mul(MulChip::default()),
            RiscvAir::ShiftRight(ShiftRightChip::default()),
            RiscvAir::ShiftLeft(ShiftLeftChip::default()),
            RiscvAir::Lt(LtChip::default()),
            RiscvAir::LoadByte(LoadByteChip::default()),
            RiscvAir::LoadHalf(LoadHalfChip::default()),
            RiscvAir::LoadWord(LoadWordChip::default()),
            RiscvAir::LoadDouble(LoadDoubleChip::default()),
            RiscvAir::LoadX0(LoadX0Chip::default()),
            RiscvAir::StoreByte(StoreByteChip::default()),
            RiscvAir::StoreHalf(StoreHalfChip::default()),
            RiscvAir::StoreWord(StoreWordChip::default()),
            RiscvAir::StoreDouble(StoreDoubleChip::default()),
            RiscvAir::UType(UTypeChip::default()),
            RiscvAir::Branch(BranchChip::default()),
            RiscvAir::Jal(JalChip::default()),
            RiscvAir::Jalr(JalrChip::default()),
            RiscvAir::SyscallInstrs(SyscallInstrsChip::default()),
            RiscvAir::MemoryBump(MemoryBumpChip::new()),
            RiscvAir::StateBump(StateBumpChip::new()),
            RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(MemoryChipType::Initialize)),
            RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)),
            RiscvAir::MemoryLocal(MemoryLocalChip::new()),
            RiscvAir::Global(GlobalChip),
            RiscvAir::ByteLookup(ByteChip::default()),
            RiscvAir::RangeLookup(RangeChip::default()),
        ]
        .into_iter()
        .map(Chip::new)
        .collect::<Vec<_>>();

        let chips_map = chips
            .iter()
            .map(|c| (c.air.as_ref().into(), c))
            .collect::<HashMap<RiscvAirDiscriminants, &Chip<F, RiscvAir<F>>>>();
        // Check that we listed all chips.
        assert_eq!(chips_map.len(), RiscvAirDiscriminants::iter().len());
        assert_eq!(chips_map.len(), chips.len());

        // Now that the chips are prepared, we can define clusters in terms of IDs.

        fn extend_base<T: Clone + Ord>(
            base: &BTreeSet<T>,
            elts: impl IntoIterator<Item = T>,
        ) -> BTreeSet<T> {
            let mut base = base.to_owned();
            base.extend(elts);
            base
        }

        let preprocessed_chips = BTreeSet::from([Program, ByteLookup, RangeLookup]);

        let base_precompile_cluster =
            extend_base(&preprocessed_chips, [SyscallPrecompile, MemoryLocal, Global]);

        let precompile_clusters = [
            [Sha256Extend, Sha256ExtendControl].as_slice(),
            [Sha256Compress, Sha256CompressControl].as_slice(),
            [Blake3Compress, Blake3CompressControl].as_slice(),
            [Ed25519Add].as_slice(),
            [Ed25519Decompress].as_slice(),
            [K256Decompress].as_slice(),
            [Secp256k1Add].as_slice(),
            [Secp256k1Double].as_slice(),
            [P256Decompress].as_slice(),
            [Secp256r1Add].as_slice(),
            [Secp256r1Double].as_slice(),
            [KeccakP, KeccakPControl].as_slice(),
            [Bn254Add].as_slice(),
            [Bn254Double].as_slice(),
            [Bls12381Add].as_slice(),
            [Bls12381Double].as_slice(),
            [Uint256Mul].as_slice(),
            [Uint256Ops].as_slice(),
            [U256x2048Mul].as_slice(),
            [Bls12381Fp].as_slice(),
            [Bls12381Fp2AddSub].as_slice(),
            [Bls12381Fp2Mul].as_slice(),
            [Bn254Fp].as_slice(),
            [Bn254Fp2AddSub].as_slice(),
            [Bn254Fp2Mul].as_slice(),
            [Bls12381Decompress].as_slice(),
            [Poseidon2].as_slice(),
        ]
        .into_iter()
        .map(|ids| extend_base(&base_precompile_cluster, ids.iter().cloned()));

        let core_cluster = extend_base(
            &preprocessed_chips,
            [
                SyscallCore,
                DivRem,
                Add,
                Addi,
                Addw,
                Sub,
                Subw,
                Bitwise,
                Mul,
                ShiftRight,
                ShiftLeft,
                Lt,
                LoadByte,
                LoadHalf,
                LoadWord,
                LoadDouble,
                LoadX0,
                StoreByte,
                StoreHalf,
                StoreWord,
                StoreDouble,
                UType,
                Branch,
                Jal,
                Jalr,
                SyscallInstrs,
                MemoryBump,
                StateBump,
                MemoryLocal,
                Global,
            ],
        );

        let memory_boundary_cluster =
            extend_base(&preprocessed_chips, [MemoryGlobalInit, MemoryGlobalFinal, Global]);

        // Chip sets that may be included in extended versions of the baseline core cluster.
        let core_cluster_exts = [
            [MemoryGlobalInit, MemoryGlobalFinal].as_slice(),
            [Bls12381Fp].as_slice(),
            [Bn254Fp].as_slice(),
            [Sha256Extend, Sha256ExtendControl, Sha256Compress, Sha256CompressControl].as_slice(),
            [Uint256Ops].as_slice(),
            [Mprotect].as_slice(),
            [Poseidon2].as_slice(),
        ];

        // These extended clusters support the AIR retainment setting in SP1Context.
        // Given E extensions, we include:
        // - the base core cluster (E choose 0);
        // - a core cluster with a single extension (E choose 1);
        // - the core cluster with all extensions (E choose E).
        let core_clusters = [0, 1, core_cluster_exts.len()]
            .into_iter()
            .flat_map(|k| core_cluster_exts.into_iter().combinations(k))
            .map(|ext_set| extend_base(&core_cluster, ext_set.into_iter().flatten().cloned()));

        // Collect all clusters and replace the IDs by chips.
        let chip_clusters = core_clusters
            .chain(core::iter::once(extend_base(
                &core_cluster,
                [
                    MemoryGlobalInit,
                    MemoryGlobalFinal,
                    Sha256Extend,
                    Sha256ExtendControl,
                    Sha256Compress,
                    Sha256CompressControl,
                    Uint256Ops,
                ],
            )))
            .chain(core::iter::once(memory_boundary_cluster))
            .chain(precompile_clusters)
            .map(|ids| ids.into_iter().map(|id| chips_map[&id].clone()).collect())
            .collect::<Vec<_>>();

        // Stop borrowing `chips`.
        drop(chips_map);

        let shape = MachineShape::new(chip_clusters);

        Machine::new(chips, SP1_PROOF_NUM_PV_ELTS, shape)
    }

    /// Get all the different RISC-V AIRs.
    pub fn chips() -> Vec<Chip<F, Self>> {
        let (chips, _) = Self::get_chips_and_costs();
        chips
    }

    /// Get all the costs of the different RISC-V AIRs.
    pub fn costs() -> HashMap<String, u64> {
        let (_, costs) = Self::get_chips_and_costs();
        costs
    }

    /// Get all the different RISC-V AIRs and their costs.
    pub fn get_airs_and_costs() -> (Vec<Self>, HashMap<String, u64>) {
        let (chips, costs) = Self::get_chips_and_costs();
        (chips.into_iter().map(|chip| chip.into_inner().unwrap()).collect(), costs)
    }

    /// Get all the different RISC-V chips and their costs.
    pub fn get_chips_and_costs() -> (Vec<Chip<F, Self>>, HashMap<String, u64>) {
        let mut costs: HashMap<String, u64> = HashMap::new();

        // The order of the chips is used to determine the order of trace generation.
        let mut chips = vec![];

        let program = Chip::new(RiscvAir::Program(ProgramChip::default()));
        costs.insert(program.name().to_string(), program.cost());
        chips.push(program);

        let sha_extend = Chip::new(RiscvAir::Sha256Extend(ShaExtendChip::default()));
        costs.insert(sha_extend.name().to_string(), sha_extend.cost());
        chips.push(sha_extend);

        let sha_extend_control =
            Chip::new(RiscvAir::Sha256ExtendControl(ShaExtendControlChip::default()));
        costs.insert(sha_extend_control.name().to_string(), sha_extend_control.cost());
        chips.push(sha_extend_control);

        let sha_compress = Chip::new(RiscvAir::Sha256Compress(ShaCompressChip::default()));
        costs.insert(sha_compress.name().to_string(), sha_compress.cost());
        chips.push(sha_compress);

        let sha_compress_control =
            Chip::new(RiscvAir::Sha256CompressControl(ShaCompressControlChip::default()));
        costs.insert(sha_compress_control.name().to_string(), sha_compress_control.cost());
        chips.push(sha_compress_control);

        let blake3_compress =
            Chip::new(RiscvAir::Blake3Compress(Blake3CompressChip::default()));
        costs.insert(blake3_compress.name().to_string(), blake3_compress.cost());
        chips.push(blake3_compress);

        let blake3_compress_control =
            Chip::new(RiscvAir::Blake3CompressControl(Blake3CompressControlChip::default()));
        costs.insert(blake3_compress_control.name().to_string(), blake3_compress_control.cost());
        chips.push(blake3_compress_control);

        let ed_add_assign = Chip::new(RiscvAir::Ed25519Add(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
        >::new()));
        costs.insert(ed_add_assign.name().to_string(), ed_add_assign.cost());
        chips.push(ed_add_assign);

        let ed_decompress = Chip::new(RiscvAir::Ed25519Decompress(EdDecompressChip::<
            Ed25519Parameters,
        >::default()));
        costs.insert(ed_decompress.name().to_string(), ed_decompress.cost());
        chips.push(ed_decompress);

        let k256_decompress = Chip::new(RiscvAir::K256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256k1Parameters>,
        >::with_lsb_rule()));
        costs.insert(k256_decompress.name().to_string(), k256_decompress.cost());
        chips.push(k256_decompress);

        let secp256k1_add_assign = Chip::new(RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256k1Parameters>,
        >::new()));
        costs.insert(secp256k1_add_assign.name().to_string(), secp256k1_add_assign.cost());
        chips.push(secp256k1_add_assign);

        let secp256k1_double_assign =
            Chip::new(RiscvAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
            >::new()));
        costs.insert(secp256k1_double_assign.name().to_string(), secp256k1_double_assign.cost());
        chips.push(secp256k1_double_assign);

        let p256_decompress = Chip::new(RiscvAir::P256Decompress(WeierstrassDecompressChip::<
            SwCurve<Secp256r1Parameters>,
        >::with_lsb_rule()));
        costs.insert(p256_decompress.name().to_string(), p256_decompress.cost());
        chips.push(p256_decompress);

        let secp256r1_add_assign = Chip::new(RiscvAir::Secp256r1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256r1Parameters>,
        >::new()));
        costs.insert(secp256r1_add_assign.name().to_string(), secp256r1_add_assign.cost());
        chips.push(secp256r1_add_assign);

        let secp256r1_double_assign =
            Chip::new(RiscvAir::Secp256r1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
            >::new()));
        costs.insert(secp256r1_double_assign.name().to_string(), secp256r1_double_assign.cost());
        chips.push(secp256r1_double_assign);

        let keccak_permute = Chip::new(RiscvAir::KeccakP(KeccakPermuteChip::new()));
        costs.insert(keccak_permute.name().to_string(), keccak_permute.cost());
        chips.push(keccak_permute);

        let keccak_control = Chip::new(RiscvAir::KeccakPControl(KeccakPermuteControlChip::new()));
        costs.insert(keccak_control.name().to_string(), keccak_control.cost());
        chips.push(keccak_control);

        let bn254_add_assign = Chip::new(RiscvAir::Bn254Add(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(bn254_add_assign.name().to_string(), bn254_add_assign.cost());
        chips.push(bn254_add_assign);

        let bn254_double_assign = Chip::new(RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bn254Parameters>,
        >::new()));
        costs.insert(bn254_double_assign.name().to_string(), bn254_double_assign.cost());
        chips.push(bn254_double_assign);

        let bls12381_add = Chip::new(RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(bls12381_add.name().to_string(), bls12381_add.cost());
        chips.push(bls12381_add);

        let bls12381_double = Chip::new(RiscvAir::Bls12381Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bls12381Parameters>,
        >::new()));
        costs.insert(bls12381_double.name().to_string(), bls12381_double.cost());
        chips.push(bls12381_double);

        let uint256_mul = Chip::new(RiscvAir::Uint256Mul(Uint256MulChip::default()));
        costs.insert(uint256_mul.name().to_string(), uint256_mul.cost());
        chips.push(uint256_mul);

        let u256x2048_mul = Chip::new(RiscvAir::U256x2048Mul(U256x2048MulChip::default()));
        costs.insert(u256x2048_mul.name().to_string(), u256x2048_mul.cost());
        chips.push(u256x2048_mul);

        let uint256_ops = Chip::new(RiscvAir::Uint256Ops(Uint256OpsChip::default()));
        costs.insert(uint256_ops.name().to_string(), uint256_ops.cost());
        chips.push(uint256_ops);

        let bls12381_fp = Chip::new(RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp.name().to_string(), bls12381_fp.cost());
        chips.push(bls12381_fp);

        let bls12381_fp2_addsub =
            Chip::new(RiscvAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp2_addsub.name().to_string(), bls12381_fp2_addsub.cost());
        chips.push(bls12381_fp2_addsub);

        let bls12381_fp2_mul =
            Chip::new(RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField>::new()));
        costs.insert(bls12381_fp2_mul.name().to_string(), bls12381_fp2_mul.cost());
        chips.push(bls12381_fp2_mul);

        let bn254_fp = Chip::new(RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp.name().to_string(), bn254_fp.cost());
        chips.push(bn254_fp);

        let bn254_fp2_addsub =
            Chip::new(RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp2_addsub.name().to_string(), bn254_fp2_addsub.cost());
        chips.push(bn254_fp2_addsub);

        let bn254_fp2_mul =
            Chip::new(RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField>::new()));
        costs.insert(bn254_fp2_mul.name().to_string(), bn254_fp2_mul.cost());
        chips.push(bn254_fp2_mul);

        let bls12381_decompress =
            Chip::new(RiscvAir::Bls12381Decompress(WeierstrassDecompressChip::<
                SwCurve<Bls12381Parameters>,
            >::with_lexicographic_rule()));
        costs.insert(bls12381_decompress.name().to_string(), bls12381_decompress.cost());
        chips.push(bls12381_decompress);

        let mprotect = Chip::new(RiscvAir::Mprotect(MProtectChip::default()));
        costs.insert(mprotect.name().to_string(), mprotect.cost());
        chips.push(mprotect);

        let syscall_core = Chip::new(RiscvAir::SyscallCore(SyscallChip::core()));
        costs.insert(syscall_core.name().to_string(), syscall_core.cost());
        chips.push(syscall_core);

        let syscall_precompile = Chip::new(RiscvAir::SyscallPrecompile(SyscallChip::precompile()));
        costs.insert(syscall_precompile.name().to_string(), syscall_precompile.cost());
        chips.push(syscall_precompile);

        let div_rem = Chip::new(RiscvAir::DivRem(DivRemChip::default()));
        costs.insert(div_rem.name().to_string(), div_rem.cost());
        chips.push(div_rem);

        let add = Chip::new(RiscvAir::Add(AddChip::default()));
        costs.insert(add.name().to_string(), add.cost());
        chips.push(add);

        let addw = Chip::new(RiscvAir::Addw(AddwChip::default()));
        costs.insert(addw.name().to_string(), addw.cost());
        chips.push(addw);

        let addi = Chip::new(RiscvAir::Addi(AddiChip::default()));
        costs.insert(addi.name().to_string(), addi.cost());
        chips.push(addi);

        let sub = Chip::new(RiscvAir::Sub(SubChip::default()));
        costs.insert(sub.name().to_string(), sub.cost());
        chips.push(sub);

        let subw = Chip::new(RiscvAir::Subw(SubwChip::default()));
        costs.insert(subw.name().to_string(), subw.cost());
        chips.push(subw);

        let bitwise = Chip::new(RiscvAir::Bitwise(BitwiseChip::default()));
        costs.insert(bitwise.name().to_string(), bitwise.cost());
        chips.push(bitwise);

        let mul = Chip::new(RiscvAir::Mul(MulChip::default()));
        costs.insert(mul.name().to_string(), mul.cost());
        chips.push(mul);

        let shift_right = Chip::new(RiscvAir::ShiftRight(ShiftRightChip::default()));
        costs.insert(shift_right.name().to_string(), shift_right.cost());
        chips.push(shift_right);

        let shift_left = Chip::new(RiscvAir::ShiftLeft(ShiftLeftChip::default()));
        costs.insert(shift_left.name().to_string(), shift_left.cost());
        chips.push(shift_left);

        let lt = Chip::new(RiscvAir::Lt(LtChip::default()));
        costs.insert(lt.name().to_string(), lt.cost());
        chips.push(lt);

        let load_byte = Chip::new(RiscvAir::LoadByte(LoadByteChip::default()));
        costs.insert(load_byte.name().to_string(), load_byte.cost());
        chips.push(load_byte);

        let load_half = Chip::new(RiscvAir::LoadHalf(LoadHalfChip::default()));
        costs.insert(load_half.name().to_string(), load_half.cost());
        chips.push(load_half);

        let load_word = Chip::new(RiscvAir::LoadWord(LoadWordChip::default()));
        costs.insert(load_word.name().to_string(), load_word.cost());
        chips.push(load_word);

        let load_x0 = Chip::new(RiscvAir::LoadX0(LoadX0Chip::default()));
        costs.insert(load_x0.name().to_string(), load_x0.cost());
        chips.push(load_x0);

        let load_double = Chip::new(RiscvAir::LoadDouble(LoadDoubleChip::default()));
        costs.insert(load_double.name().to_string(), load_double.cost());
        chips.push(load_double);

        let store_byte = Chip::new(RiscvAir::StoreByte(StoreByteChip::default()));
        costs.insert(store_byte.name().to_string(), store_byte.cost());
        chips.push(store_byte);

        let store_half = Chip::new(RiscvAir::StoreHalf(StoreHalfChip::default()));
        costs.insert(store_half.name().to_string(), store_half.cost());
        chips.push(store_half);

        let store_word = Chip::new(RiscvAir::StoreWord(StoreWordChip::default()));
        costs.insert(store_word.name().to_string(), store_word.cost());
        chips.push(store_word);

        let store_double = Chip::new(RiscvAir::StoreDouble(StoreDoubleChip::default()));
        costs.insert(store_double.name().to_string(), store_double.cost());
        chips.push(store_double);

        let utype = Chip::new(RiscvAir::UType(UTypeChip::default()));
        costs.insert(utype.name().to_string(), utype.cost());
        chips.push(utype);

        let branch = Chip::new(RiscvAir::Branch(BranchChip::default()));
        costs.insert(branch.name().to_string(), branch.cost());
        chips.push(branch);

        let jal = Chip::new(RiscvAir::Jal(JalChip::default()));
        costs.insert(jal.name().to_string(), jal.cost());
        chips.push(jal);

        let jalr = Chip::new(RiscvAir::Jalr(JalrChip::default()));
        costs.insert(jalr.name().to_string(), jalr.cost());
        chips.push(jalr);

        let syscall_instrs = Chip::new(RiscvAir::SyscallInstrs(SyscallInstrsChip::default()));
        costs.insert(syscall_instrs.name().to_string(), syscall_instrs.cost());
        chips.push(syscall_instrs);

        let memory_bump = Chip::new(RiscvAir::MemoryBump(MemoryBumpChip::new()));
        costs.insert(memory_bump.name().to_string(), memory_bump.cost());
        chips.push(memory_bump);

        let state_bump = Chip::new(RiscvAir::StateBump(StateBumpChip::new()));
        costs.insert(state_bump.name().to_string(), state_bump.cost());
        chips.push(state_bump);

        let memory_global_init = Chip::new(RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(
            MemoryChipType::Initialize,
        )));
        costs.insert(memory_global_init.name().to_string(), memory_global_init.cost());
        chips.push(memory_global_init);

        let memory_global_finalize =
            Chip::new(RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)));
        costs.insert(memory_global_finalize.name().to_string(), memory_global_finalize.cost());
        chips.push(memory_global_finalize);

        let memory_local = Chip::new(RiscvAir::MemoryLocal(MemoryLocalChip::new()));
        costs.insert(memory_local.name().to_string(), memory_local.cost());
        chips.push(memory_local);

        let global = Chip::new(RiscvAir::Global(GlobalChip));
        costs.insert(global.name().to_string(), global.cost());
        chips.push(global);

        let byte = Chip::new(RiscvAir::ByteLookup(ByteChip::default()));
        costs.insert(byte.name().to_string(), byte.cost());
        chips.push(byte);

        let range = Chip::new(RiscvAir::RangeLookup(RangeChip::default()));
        costs.insert(range.name().to_string(), range.cost());
        chips.push(range);

        let poseidon2 = Chip::new(RiscvAir::Poseidon2(Poseidon2Chip::new()));
        costs.insert(poseidon2.name().to_string(), poseidon2.cost());
        chips.push(poseidon2);

        assert_eq!(chips.len(), costs.len(), "chips and costs must have the same length",);

        (chips, costs)
    }

    /// Get the heights of the chips for a given execution record.
    pub fn core_heights(record: &ExecutionRecord) -> Vec<(RiscvAirId, usize)> {
        vec![
            (RiscvAirId::DivRem, record.divrem_events.len()),
            (RiscvAirId::Add, record.add_events.len()),
            (RiscvAirId::Addw, record.addw_events.len()),
            (RiscvAirId::Addi, record.addi_events.len()),
            (RiscvAirId::Sub, record.sub_events.len()),
            (RiscvAirId::Subw, record.subw_events.len()),
            (RiscvAirId::Bitwise, record.bitwise_events.len()),
            (RiscvAirId::Mul, record.mul_events.len()),
            (RiscvAirId::ShiftRight, record.shift_right_events.len()),
            (RiscvAirId::ShiftLeft, record.shift_left_events.len()),
            (RiscvAirId::Lt, record.lt_events.len()),
            (
                RiscvAirId::MemoryLocal,
                record
                    .get_local_mem_events()
                    .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (RiscvAirId::MemoryBump, record.bump_memory_events.len()),
            (
                RiscvAirId::PageProt,
                (record.memory_load_byte_events.len()
                    + record.memory_store_byte_events.len()
                    + record.memory_load_word_events.len()
                    + record.memory_store_word_events.len()
                    + record.memory_load_double_events.len()
                    + record.memory_store_double_events.len()
                    + record.memory_load_half_events.len()
                    + record.memory_store_half_events.len()
                    + record.memory_load_x0_events.len())
                .div_ceil(NUM_PAGE_PROT_ENTRIES_PER_ROW),
            ),
            (
                RiscvAirId::PageProtLocal,
                record
                    .get_local_page_prot_events()
                    .chunks(NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW)
                    .into_iter()
                    .count(),
            ),
            (RiscvAirId::StateBump, record.bump_state_events.len()),
            (RiscvAirId::LoadByte, record.memory_load_byte_events.len()),
            (RiscvAirId::LoadHalf, record.memory_load_half_events.len()),
            (RiscvAirId::LoadWord, record.memory_load_word_events.len()),
            (RiscvAirId::LoadDouble, record.memory_load_double_events.len()),
            (RiscvAirId::LoadX0, record.memory_load_x0_events.len()),
            (RiscvAirId::StoreByte, record.memory_store_byte_events.len()),
            (RiscvAirId::StoreHalf, record.memory_store_half_events.len()),
            (RiscvAirId::StoreWord, record.memory_store_word_events.len()),
            (RiscvAirId::StoreDouble, record.memory_store_double_events.len()),
            (RiscvAirId::UType, record.utype_events.len()),
            (RiscvAirId::Branch, record.branch_events.len()),
            (RiscvAirId::Jal, record.jal_events.len()),
            (RiscvAirId::Jalr, record.jalr_events.len()),
            (RiscvAirId::Global, record.global_interaction_events.len()),
            (RiscvAirId::SyscallCore, record.syscall_events.len()),
            (RiscvAirId::SyscallInstrs, record.syscall_events.len()),
            (RiscvAirId::InstructionDecode, record.instruction_fetch_events.len()),
            (RiscvAirId::InstructionFetch, record.instruction_fetch_events.len()),
        ]
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
        self.name().to_string().hash(state);
    }
}

impl<F: PrimeField32> fmt::Debug for RiscvAir<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl From<RiscvAirDiscriminants> for RiscvAirId {
    fn from(value: RiscvAirDiscriminants) -> Self {
        match value {
            RiscvAirDiscriminants::Program => RiscvAirId::Program,
            RiscvAirDiscriminants::Add => RiscvAirId::Add,
            RiscvAirDiscriminants::Addw => RiscvAirId::Addw,
            RiscvAirDiscriminants::Addi => RiscvAirId::Addi,
            RiscvAirDiscriminants::Sub => RiscvAirId::Sub,
            RiscvAirDiscriminants::Subw => RiscvAirId::Subw,
            RiscvAirDiscriminants::Bitwise => RiscvAirId::Bitwise,
            RiscvAirDiscriminants::Mul => RiscvAirId::Mul,
            RiscvAirDiscriminants::DivRem => RiscvAirId::DivRem,
            RiscvAirDiscriminants::Lt => RiscvAirId::Lt,
            RiscvAirDiscriminants::ShiftLeft => RiscvAirId::ShiftLeft,
            RiscvAirDiscriminants::ShiftRight => RiscvAirId::ShiftRight,
            RiscvAirDiscriminants::LoadByte => RiscvAirId::LoadByte,
            RiscvAirDiscriminants::LoadHalf => RiscvAirId::LoadHalf,
            RiscvAirDiscriminants::LoadWord => RiscvAirId::LoadWord,
            RiscvAirDiscriminants::LoadX0 => RiscvAirId::LoadX0,
            RiscvAirDiscriminants::LoadDouble => RiscvAirId::LoadDouble,
            RiscvAirDiscriminants::StoreByte => RiscvAirId::StoreByte,
            RiscvAirDiscriminants::StoreHalf => RiscvAirId::StoreHalf,
            RiscvAirDiscriminants::StoreWord => RiscvAirId::StoreWord,
            RiscvAirDiscriminants::StoreDouble => RiscvAirId::StoreDouble,
            RiscvAirDiscriminants::RangeLookup => RiscvAirId::Range,
            RiscvAirDiscriminants::MemoryBump => RiscvAirId::MemoryBump,
            RiscvAirDiscriminants::StateBump => RiscvAirId::StateBump,
            RiscvAirDiscriminants::UType => RiscvAirId::UType,
            RiscvAirDiscriminants::Branch => RiscvAirId::Branch,
            RiscvAirDiscriminants::Jal => RiscvAirId::Jal,
            RiscvAirDiscriminants::Jalr => RiscvAirId::Jalr,
            RiscvAirDiscriminants::SyscallInstrs => RiscvAirId::SyscallInstrs,
            RiscvAirDiscriminants::ByteLookup => RiscvAirId::Byte,
            RiscvAirDiscriminants::MemoryGlobalInit => RiscvAirId::MemoryGlobalInit,
            RiscvAirDiscriminants::MemoryGlobalFinal => RiscvAirId::MemoryGlobalFinalize,
            RiscvAirDiscriminants::MemoryLocal => RiscvAirId::MemoryLocal,
            RiscvAirDiscriminants::SyscallCore => RiscvAirId::SyscallCore,
            RiscvAirDiscriminants::SyscallPrecompile => RiscvAirId::SyscallPrecompile,
            RiscvAirDiscriminants::Global => RiscvAirId::Global,
            RiscvAirDiscriminants::Sha256Extend => RiscvAirId::ShaExtend,
            RiscvAirDiscriminants::Sha256Compress => RiscvAirId::ShaCompress,
            RiscvAirDiscriminants::Ed25519Add => RiscvAirId::EdAddAssign,
            RiscvAirDiscriminants::Ed25519Decompress => RiscvAirId::EdDecompress,
            RiscvAirDiscriminants::K256Decompress => RiscvAirId::Secp256k1Decompress,
            RiscvAirDiscriminants::P256Decompress => RiscvAirId::Secp256r1Decompress,
            RiscvAirDiscriminants::Secp256k1Add => RiscvAirId::Secp256k1AddAssign,
            RiscvAirDiscriminants::Secp256k1Double => RiscvAirId::Secp256k1DoubleAssign,
            RiscvAirDiscriminants::Secp256r1Add => RiscvAirId::Secp256r1AddAssign,
            RiscvAirDiscriminants::Secp256r1Double => RiscvAirId::Secp256r1DoubleAssign,
            RiscvAirDiscriminants::KeccakP => RiscvAirId::KeccakPermute,
            RiscvAirDiscriminants::Bn254Add => RiscvAirId::Bn254AddAssign,
            RiscvAirDiscriminants::Bn254Double => RiscvAirId::Bn254DoubleAssign,
            RiscvAirDiscriminants::Bls12381Add => RiscvAirId::Bls12381AddAssign,
            RiscvAirDiscriminants::Bls12381Double => RiscvAirId::Bls12381DoubleAssign,
            RiscvAirDiscriminants::Uint256Mul => RiscvAirId::Uint256MulMod,
            RiscvAirDiscriminants::Uint256Ops => RiscvAirId::Uint256Ops,
            RiscvAirDiscriminants::U256x2048Mul => RiscvAirId::U256XU2048Mul,
            RiscvAirDiscriminants::Bls12381Decompress => RiscvAirId::Bls12381Decompress,
            RiscvAirDiscriminants::Bls12381Fp => RiscvAirId::Bls12381FpOpAssign,
            RiscvAirDiscriminants::Bls12381Fp2Mul => RiscvAirId::Bls12381Fp2MulAssign,
            RiscvAirDiscriminants::Bls12381Fp2AddSub => RiscvAirId::Bls12381Fp2AddSubAssign,
            RiscvAirDiscriminants::Bn254Fp => RiscvAirId::Bn254FpOpAssign,
            RiscvAirDiscriminants::Bn254Fp2Mul => RiscvAirId::Bn254Fp2MulAssign,
            RiscvAirDiscriminants::Bn254Fp2AddSub => RiscvAirId::Bn254Fp2AddSubAssign,
            RiscvAirDiscriminants::Sha256ExtendControl => RiscvAirId::ShaExtendControl,
            RiscvAirDiscriminants::Sha256CompressControl => RiscvAirId::ShaCompressControl,
            RiscvAirDiscriminants::Blake3Compress => RiscvAirId::Blake3Compress,
            RiscvAirDiscriminants::Blake3CompressControl => RiscvAirId::Blake3CompressControl,
            RiscvAirDiscriminants::KeccakPControl => RiscvAirId::KeccakPermuteControl,
            RiscvAirDiscriminants::Mprotect => RiscvAirId::Mprotect,
            RiscvAirDiscriminants::Poseidon2 => RiscvAirId::Poseidon2,
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };

    use slop_air::BaseAir;
    use sp1_core_executor::{
        cost_and_height_per_syscall, rv64im_costs, Instruction, Opcode, Program, RiscvAirId,
        SyscallCode, MAXIMUM_CYCLE_AREA, MAXIMUM_PADDING_AREA,
    };
    use sp1_hypercube::{air::MachineAir, InteractionBuilder, MachineRecord};
    use sp1_primitives::SP1Field;

    use crate::{
        programs::tests::*,
        riscv::RiscvAir,
        utils::{run_test_small_trace, setup_logger},
    };
    use sp1_core_executor::add_halt;
    use sp1_hypercube::InteractionKind;
    use strum::IntoEnumIterator;
    //     use sp1_primitives::SP1Field;
    //     use sp1_core_executor::{Instruction, Opcode, Program, SP1Context};
    //     use sp1_hypercube::{
    //         koala_bear_poseidon2::SP1InnerPcs, CpuProver, MachineProver, SP1CoreOpts,
    //         StarkProvingKey, StarkVerifyingKey,
    //     };

    // #[test]
    // fn test_primitives_and_machine_air_names_match() {
    //     let chips = RiscvAir::<SP1Field>::chips();
    //     for (a, b) in chips.iter().zip_eq(RiscvAirId::iter()) {
    //         assert_eq!(a.name().to_string(), b.to_string());
    //     }
    // }

    use hashbrown::HashMap;
    #[test]
    fn core_air_cost_consistency() {
        // Load air costs from file
        let file = std::fs::File::open("../executor/src/artifacts/rv64im_costs.json").unwrap();
        let costs: HashMap<String, u64> = serde_json::from_reader(file).unwrap();
        // Compare with costs computed by machine
        let machine_costs = RiscvAir::<SP1Field>::costs();
        assert_eq!(costs, machine_costs);
    }

    #[test]
    fn core_air_complexity_consistency() {
        let complexity = sp1_core_executor::get_complexity_mapping();
        let machine = RiscvAir::<SP1Field>::machine();
        for chip in machine.chips() {
            let id = chip.air.id();
            let expected = complexity[id];
            assert_eq!(
                chip.num_constraints as u64, expected,
                "Complexity mismatch for {:?}: chip has {} constraints, expected {}",
                id, chip.num_constraints, expected
            );
        }
    }

    #[test]
    fn test_interaction_counts() {
        let interaction_sizes = RiscvAir::<SP1Field>::machine()
            .chips()
            .iter()
            .flat_map(|chip| {
                chip.sends()
                    .iter()
                    .chain(chip.receives().iter())
                    .map(|interaction| (interaction.kind, interaction.values.len() as usize))
            })
            .collect::<BTreeSet<(InteractionKind, usize)>>();

        for (kind, size) in interaction_sizes {
            assert_eq!(kind.num_values() as usize, size);
        }
    }

    #[test]
    fn test_eval_public_values_interactions() {
        let machine = RiscvAir::<SP1Field>::machine();
        let kinds_and_counts = machine.chips().iter().flat_map(|chip| {
            let mut builder = InteractionBuilder::<SP1Field>::new(chip.preprocessed_width(), chip.width());
            <<RiscvAir<SP1Field> as MachineAir<SP1Field>>::Record as MachineRecord>::eval_public_values(&mut builder);
            let (sends, receives) = builder.interactions();
            sends.iter().chain(receives.iter()).map(|interaction| (interaction.kind, interaction.values.len())).collect::<BTreeSet<(InteractionKind, usize)>>()
        }).collect::<BTreeMap<InteractionKind, usize>>();

        let expected_kinds = InteractionKind::all_kinds()
            .iter()
            .filter_map(|kind| {
                if kind.appears_in_eval_public_values() {
                    Some((*kind, kind.num_values()))
                } else {
                    None
                }
            })
            .collect::<BTreeMap<InteractionKind, usize>>();

        assert_eq!(kinds_and_counts, expected_kinds);
    }

    #[test]
    #[ignore = "should only be used to generate the artifact"]
    fn write_core_air_costs() {
        let costs = RiscvAir::<SP1Field>::costs();
        // write to file
        // Create directory if it doesn't exist
        let dir = std::path::Path::new("../executor/src/artifacts");
        if !dir.exists() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let file = std::fs::File::create(dir.join("rv64im_costs.json")).unwrap();
        serde_json::to_writer_pretty(file, &costs).unwrap();
    }

    #[test]
    fn test_maximum_padding() {
        let machine = RiscvAir::<SP1Field>::machine();
        let chip_clusters = &machine.shape().chip_clusters;

        for cluster in chip_clusters {
            let mut total_columns = 0;
            for chip in cluster {
                total_columns += chip.preprocessed_width();
                total_columns += chip.width();
            }
            assert!((32 * total_columns) as u64 <= MAXIMUM_PADDING_AREA);
        }
    }

    #[test]
    fn test_maximum_cycle() {
        // Assumes that the maximum possible single shard trace area comes from precompiles.
        let costs = rv64im_costs();
        for syscall_code in SyscallCode::iter() {
            if syscall_code.should_send() == 0 {
                continue;
            }
            // We turn off the page protection for now.
            let (mut cost_per_syscall, _) =
                cost_and_height_per_syscall(syscall_code, &costs, false);
            cost_per_syscall += costs[&RiscvAirId::SyscallInstrs];
            cost_per_syscall += costs[&RiscvAirId::MemoryBump] * 32;
            cost_per_syscall += costs[&RiscvAirId::StateBump];

            assert!(cost_per_syscall as u64 <= MAXIMUM_CYCLE_AREA);
        }
    }

    use crate::{io::SP1Stdin, utils::run_test};

    #[tokio::test]
    async fn test_simple_prove() {
        setup_logger();
        let program = simple_program();
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_shift_prove() {
        setup_logger();
        let shift_ops =
            [Opcode::SRL, Opcode::SRLW, Opcode::SRA, Opcode::SRAW, Opcode::SLL, Opcode::SLLW];
        let operands = [
            (0, 0),
            (1, 0),
            (1, 1),
            (0xff, 4),
            (0x123456789abcdef0, 31),
            (0x123456789abcdef0, 32),
            (0x123456789abcdef0, 63),
            (0x123456789abcdef0, 64),
            (0x8000000000000000u64 as i64 as u64, 1),
            (0x8000000000000000u64 as i64 as u64, 63),
            (0x80000000u64, 1),
            (0xffffffffffffffff, 1),
            (0xffffffffffffffff, 32),
            (u64::MAX, 0),
            (u64::MAX, 1),
            (u64::MAX - 1, 1),
            (1u64 << 63, 1),
            (1u64 << 31, 1),
            (0x5555555555555555, 1),
            (0xaaaaaaaaaaaaaaaa, 1),
            (0x123456789abcdef0, 4),
            (0x123456789abcdef0, 8),
            (0xffffffff00000000, 16),
            (0x00000000ffffffff, 16),
            (0x80000000, 31),
            (0xdeadbeef, 65),
            (0xdeadbeef, 128),
            (0xdeadbeef, 33),
            (1, 1),
            (1234, 5678),
            (0xffff, 0xffff - 1),
            (u64::MAX - 1, u64::MAX),
            (u64::MAX, 0),
        ];

        let mut instructions = vec![];
        for shift_op in shift_ops.iter() {
            for op in operands.iter() {
                instructions.push(Instruction::new(Opcode::ADDI, 29, 0, op.0 as u64, false, true));
                instructions.push(Instruction::new(Opcode::ADDI, 30, 0, op.1 as u64, false, true));
                instructions.push(Instruction::new(*shift_op, 31, 29, 3, false, false));
            }
        }
        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_sub_prove() {
        setup_logger();
        let mut instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 8, false, true),
            Instruction::new(Opcode::SUB, 31, 30, 29, false, false),
        ];
        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_add_prove() {
        setup_logger();
        let mut instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
            Instruction::new(Opcode::ADDI, 30, 0, 8, false, true),
            Instruction::new(Opcode::ADD, 31, 30, 29, false, false),
        ];
        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[test]
    fn test_chips_main_width_interaction_ratio() {
        let chips = RiscvAir::<SP1Field>::chips();
        for chip in chips.iter() {
            let main_width = chip.air.width();
            for kind in InteractionKind::all_kinds() {
                let interaction_count =
                    chip.num_sends_by_kind(kind) + chip.num_receives_by_kind(kind);
                assert!(interaction_count <= main_width);
            }
        }
    }

    #[tokio::test]
    async fn test_mul_prove() {
        let mul_ops = [Opcode::MUL, Opcode::MULH, Opcode::MULHU, Opcode::MULHSU];
        setup_logger();
        let operands = [
            (1, 1),
            (1234, 5678),
            (8765, 4321),
            (0xffff, 0xffff - 1),
            (u64::MAX - 1, u64::MAX),
            (1 << 31, u32::MAX as u64),
        ];
        let mut instructions = vec![];
        for mul_op in mul_ops.iter() {
            for operand in operands.iter() {
                instructions.push(Instruction::new(
                    Opcode::ADDI,
                    29,
                    0,
                    operand.0 as u64,
                    false,
                    true,
                ));
                instructions.push(Instruction::new(
                    Opcode::ADDI,
                    30,
                    0,
                    operand.1 as u64,
                    false,
                    true,
                ));
                instructions.push(Instruction::new(*mul_op, 31, 30, 29, false, false));
            }
        }
        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_lt_prove() {
        setup_logger();
        let less_than = [Opcode::SLT, Opcode::SLTU];
        for lt_op in less_than.iter() {
            let mut instructions = vec![
                Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADDI, 30, 0, 8, false, true),
                Instruction::new(*lt_op, 31, 30, 29, false, false),
            ];
            add_halt(&mut instructions);
            let program = Program::new(instructions, 0, 0);
            let stdin = SP1Stdin::new();
            run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
            run_test_small_trace(Arc::new(program), stdin).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_bitwise_prove() {
        setup_logger();
        let bitwise_opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];

        for bitwise_op in bitwise_opcodes.iter() {
            let mut instructions = vec![
                Instruction::new(Opcode::ADDI, 29, 0, 5, false, true),
                Instruction::new(Opcode::ADDI, 30, 0, 8, false, true),
                Instruction::new(*bitwise_op, 31, 30, 29, false, false),
            ];
            add_halt(&mut instructions);
            let program = Program::new(instructions, 0, 0);
            let stdin = SP1Stdin::new();
            run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
            run_test_small_trace(Arc::new(program), stdin).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_divrem_prove() {
        setup_logger();
        let div_rem_ops = [
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
            Opcode::DIVW,
            Opcode::DIVUW,
            Opcode::REMUW,
            Opcode::REMW,
        ];

        let mut operands = Vec::<u64>::new();
        for i in 0..5 {
            operands.push(i);
            operands.push(1 << i);
            operands.push(u64::MAX - (1 << i) + 1);
            operands.push(u64::MAX - i);
            operands.push((1 << 16) - i);
            operands.push((1 << 16) + i);
            operands.push((1 << 31) - i);
            operands.push((1 << 31) + i);
            operands.push((1 << 63) - i);
            operands.push((1 << 63) + i);
            operands.push((1 << 32) - i);
            operands.push((1 << 32) + i);
            operands.push((i32::MIN as u64) - i);
            operands.push((i32::MIN as u64) + i);
        }
        operands.append(&mut vec![
            123,
            456 * 789,
            123 * 456,
            789,
            0xffff * (0xffff - 1),
            0xffff,
            0xabcdef,
            0x12345678abcdef,
            0xffffffff,
            0x80000000,
            0x7fffffff,
            0xffff0000,
            0x0000ffff,
            0xffffffff,
        ]);

        let mut instructions = vec![];
        for div_rem_op in div_rem_ops.iter() {
            for op1 in operands.iter() {
                for op2 in operands.iter() {
                    instructions.push(Instruction::new(Opcode::ADDI, 29, 0, *op1, false, true));
                    instructions.push(Instruction::new(Opcode::ADDI, 30, 0, *op2, false, true));
                    instructions.push(Instruction::new(*div_rem_op, 31, 29, 30, false, false));
                }
            }
        }
        add_halt(&mut instructions);
        let program = Program::new(instructions.to_vec(), 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fibonacci_prove_simple() {
        setup_logger();
        let program = fibonacci_program();
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_keccak_permute_prove() {
        setup_logger();
        let program = keccak_permute_program();
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program), stdin).await.unwrap();
    }

    // #[tokio::test]
    // async fn test_fibonacci_prove_checkpoints() {
    //     setup_logger();

    //     let program = fibonacci_program();
    //     let stdin = SP1Stdin::new();
    //     let mut opts = SP1CoreOpts::default();
    //     opts.shard_size = 1024;
    //     opts.shard_batch_size = 2;

    //     let log_blowup = 1;
    //     let log_stacking_height = 21;
    //     let max_log_row_count = 21;
    //     let machine = RiscvAir::machine();
    //     let verifier = ShardVerifier::from_basefold_parameters(
    //         log_blowup,
    //         log_stacking_height,
    //         max_log_row_count,
    //         machine,
    //     );
    //     let prover = CpuProver::new(verifier.clone());
    //     let challenger = verifier.pcs_verifier.challenger();

    //     let program = Arc::new(program);
    //     let (pk, vk) = prover.setup(program.clone()).await;
    //     let (proof, _) = prove_core(
    //         Arc::new(prover),
    //         Arc::new(pk),
    //         program,
    //         &stdin,
    //         opts,
    //         SP1Context::default(),
    //         challenger,
    //     )
    //     .await
    //     .unwrap();

    //     let mut challenger = verifier.pcs_verifier.challenger();
    //     let machine_verifier = MachineVerifier::new(verifier);
    //     tracing::debug_span!("verify the proof")
    //         .in_scope(|| machine_verifier.verify(&vk, &proof, &mut challenger))
    //         .unwrap();
    // }

    // #[tokio::test]
    // async fn test_fibonacci_prove_batch() {
    //     setup_logger();
    //     let program = Arc::new(fibonacci_program());
    //     let stdin = SP1Stdin::new();

    //     let opts = SP1CoreOpts::default();
    //     let log_blowup = 1;
    //     let log_stacking_height = 21;
    //     let max_log_row_count = 21;
    //     let machine = RiscvAir::machine();
    //     let verifier = ShardVerifier::from_basefold_parameters(
    //         log_blowup,
    //         log_stacking_height,
    //         max_log_row_count,
    //         machine,
    //     );
    //     let prover = CpuProver::new(verifier.clone());
    //     let challenger = verifier.pcs_verifier.challenger();
    //     let (pk, vk) = prover.setup(program.clone()).await;
    //     let (proof, _) = prove_core(
    //         Arc::new(prover),
    //         Arc::new(pk),
    //         program,
    //         &stdin,
    //         opts,
    //         SP1Context::default(),
    //         challenger,
    //     )
    //     .await
    //     .unwrap();

    //     let mut challenger = verifier.pcs_verifier.challenger();
    //     let machine_verifier = MachineVerifier::new(verifier);
    //     tracing::debug_span!("verify the proof")
    //         .in_scope(|| machine_verifier.verify(&vk, &proof, &mut challenger))
    //         .unwrap();
    // }

    // #[tokio::test]
    // async fn test_simple_memory_program_prove() {
    //     setup_logger();
    //     let program = simple_memory_program();
    //     let stdin = SP1Stdin::new();
    //     run_test(Arc::new(program), stdin).await.unwrap();
    // }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_ssz_withdrawal() {
        setup_logger();
        let program = ssz_withdrawals_program();
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program), stdin).await.unwrap();
    }

    // #[test]
    // fn test_key_serde() {
    //     let program = ssz_withdrawals_program();
    //     let config = SP1InnerPcs::new();
    //     let machine = RiscvAir::machine(config);
    //     let (pk, vk) = machine.setup(&program);

    //     let serialized_pk = bincode::serialize(&pk).unwrap();
    //     let deserialized_pk: StarkProvingKey<SP1InnerPcs> =
    //         bincode::deserialize(&serialized_pk).unwrap();
    //     assert_eq!(pk.preprocessed_commit, deserialized_pk.preprocessed_commit);
    //     assert_eq!(pk.pc_start_rel, deserialized_pk.pc_start_rel);
    //     assert_eq!(pk.traces, deserialized_pk.traces);
    //     // assert_eq!(pk.data, deserialized_pk.data);
    //     assert_eq!(pk.chip_ordering, deserialized_pk.chip_ordering);

    //     let serialized_vk = bincode::serialize(&vk).unwrap();
    //     let deserialized_vk: StarkVerifyingKey<SP1InnerPcs> =
    //         bincode::deserialize(&serialized_vk).unwrap();
    //     assert_eq!(vk.pc_start_rel, deserialized_vk.pc_start_rel);
    //     assert_eq!(vk.chip_information.len(), deserialized_vk.chip_information.len());
    //     for (a, b) in vk.chip_information.iter().zip(deserialized_vk.chip_information.iter()) {
    //         assert_eq!(a.0, b.0);
    //         assert_eq!(a.1.height, b.1.height);
    //         assert_eq!(a.1.width, b.1.width);
    //     }
    //     assert_eq!(vk.chip_ordering, deserialized_vk.chip_ordering);
    // }
}
