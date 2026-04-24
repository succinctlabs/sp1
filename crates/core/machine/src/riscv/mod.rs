pub use riscv_chips::*;
use strum::IntoEnumIterator;

use core::fmt;
use std::collections::BTreeSet;

use crate::{
    adapter::bump::StateBumpChip,
    control_flow::{BranchChip, JalChip, JalrChip, TrapExecChip, TrapMemChip},
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
        MemoryBumpChip, MemoryChipType, MemoryLocalChip, PageProtChip, PageProtGlobalChip,
        PageProtLocalChip, NUM_LOCAL_MEMORY_ENTRIES_PER_ROW, NUM_LOCAL_PAGE_PROT_ENTRIES_PER_ROW,
        NUM_PAGE_PROT_ENTRIES_PER_ROW,
    },
    program::{InstructionDecodeChip, InstructionFetchChip},
    range::RangeChip,
    syscall::{
        instructions::SyscallInstrsChip,
        precompiles::{
            fptower::{Fp2AddSubAssignChip, Fp2MulAssignChip, FpOpChip},
            sigreturn::SigReturnChip,
        },
    },
    utype::UTypeChip,
    SupervisorMode, UserMode,
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
            add::AddChip, addi::AddiChip, addw::AddwChip, alu_x0::AluX0Chip, sub::SubChip,
            subw::SubwChip, BitwiseChip, DivRemChip, LtChip, MulChip, ShiftLeftChip,
            ShiftRightChip,
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
                sha256::{
                    ShaCompressChip, ShaCompressControlChip, ShaExtendChip, ShaExtendControlChip,
                },
                uint256::Uint256MulChip,
                uint256_ops::Uint256OpsChip,
                weierstrass::{WeierstrassAddAssignChip, WeierstrassDoubleAssignChip},
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
    /// An AIR for decoding untrusted program instructions.
    InstructionDecode(InstructionDecodeChip),
    /// An AIR for fetching untrusted program instructions.
    InstructionFetch(InstructionFetchChip),
    /// An AIR for the RISC-V Add instruction.
    Add(AddChip<SupervisorMode>),
    /// An AIR for the RISC-V Add instruction (user mode).
    AddUser(AddChip<UserMode>),
    /// An AIR for the RISC-V Addw instruction.
    Addw(AddwChip<SupervisorMode>),
    /// An AIR for the RISC-V Addw instruction (user mode).
    AddwUser(AddwChip<UserMode>),
    /// An AIR for the RISC-V Addi instruction.
    Addi(AddiChip<SupervisorMode>),
    /// An AIR for the RISC-V Addi instruction (user mode).
    AddiUser(AddiChip<UserMode>),
    /// An AIR for the RISC-V Sub instruction.
    Sub(SubChip<SupervisorMode>),
    /// An AIR for the RISC-V Sub instruction (user mode).
    SubUser(SubChip<UserMode>),
    /// An AIR for the RISC-V Subw instruction.
    Subw(SubwChip<SupervisorMode>),
    /// An AIR for the RISC-V Subw instruction (user mode).
    SubwUser(SubwChip<UserMode>),
    /// An AIR for RISC-V Bitwise instructions.
    Bitwise(BitwiseChip<SupervisorMode>),
    /// An AIR for RISC-V Bitwise instructions (user mode).
    BitwiseUser(BitwiseChip<UserMode>),
    /// An AIR for RISC-V Mul instruction.
    Mul(MulChip<SupervisorMode>),
    /// An AIR for RISC-V Mul instruction (User mode).
    MulUser(MulChip<UserMode>),
    /// An AIR for RISC-V Div and Rem instructions.
    DivRem(DivRemChip<SupervisorMode>),
    /// An AIR for RISC-V Div and Rem instructions (User mode).
    DivRemUser(DivRemChip<UserMode>),
    /// An AIR for RISC-V Lt instruction.
    Lt(LtChip<SupervisorMode>),
    /// An AIR for RISC-V Lt instruction (User mode).
    LtUser(LtChip<UserMode>),
    /// An AIR for all RISC-V ALU instructions with rd = x0.
    AluX0(AluX0Chip<SupervisorMode>),
    /// An AIR for all RISC-V ALU instructions with rd = x0 (User mode).
    AluX0User(AluX0Chip<UserMode>),
    /// An AIR for RISC-V SLL instruction.
    ShiftLeft(ShiftLeftChip<SupervisorMode>),
    /// An AIR for RISC-V SLL instruction (User mode).
    ShiftLeftUser(ShiftLeftChip<UserMode>),
    /// An AIR for RISC-V SRL and SRA instruction.
    ShiftRight(ShiftRightChip<SupervisorMode>),
    /// An AIR for RISC-V SRL and SRA instruction (User mode).
    ShiftRightUser(ShiftRightChip<UserMode>),
    /// An AIR for RISC-V memory load byte instructions.
    LoadByte(LoadByteChip<SupervisorMode>),
    /// An AIR for RISC-V memory load byte instructions (User mode).
    LoadByteUser(LoadByteChip<UserMode>),
    /// An AIR for RISC-V memory load half instructions.
    LoadHalf(LoadHalfChip<SupervisorMode>),
    /// An AIR for RISC-V memory load half instructions (User mode).
    LoadHalfUser(LoadHalfChip<UserMode>),
    /// An AIR for RISC-V memory load word instructions.
    LoadWord(LoadWordChip<SupervisorMode>),
    /// An AIR for RISC-V memory load word instructions (User mode).
    LoadWordUser(LoadWordChip<UserMode>),
    /// An AIR for RISC-V memory load double instructions.
    LoadDouble(LoadDoubleChip<SupervisorMode>),
    /// An AIR for RISC-V memory load double instructions (User mode).
    LoadDoubleUser(LoadDoubleChip<UserMode>),
    /// An AIR for RISC-V memory load x0 instructions.
    LoadX0(LoadX0Chip<SupervisorMode>),
    /// An AIR for RISC-V memory load x0 instructions (User mode).
    LoadX0User(LoadX0Chip<UserMode>),
    /// An AIR for RISC-V memory store byte instructions.
    StoreByte(StoreByteChip<SupervisorMode>),
    /// An AIR for RISC-V memory store byte instructions (User mode).
    StoreByteUser(StoreByteChip<UserMode>),
    /// An AIR for RISC-V memory store half instructions.
    StoreHalf(StoreHalfChip<SupervisorMode>),
    /// An AIR for RISC-V memory store half instructions (User mode).
    StoreHalfUser(StoreHalfChip<UserMode>),
    /// An AIR for RISC-V memory store word instructions.
    StoreWord(StoreWordChip<SupervisorMode>),
    /// An AIR for RISC-V memory store word instructions (User mode).
    StoreWordUser(StoreWordChip<UserMode>),
    /// An AIR for RISC-V memory store double instructions.
    StoreDouble(StoreDoubleChip<SupervisorMode>),
    /// An AIR for RISC-V memory store double instructions (User mode).
    StoreDoubleUser(StoreDoubleChip<UserMode>),
    /// An AIR for RISC-V UType instruction.
    UType(UTypeChip<SupervisorMode>),
    /// An AIR for RISC-V UType instruction (User mode).
    UTypeUser(UTypeChip<UserMode>),
    /// An AIR for RISC-V branch instructions.
    Branch(BranchChip<SupervisorMode>),
    /// An AIR for RISC-V branch instructions (User mode).
    BranchUser(BranchChip<UserMode>),
    /// An AIR for RISC-V jal instructions.
    Jal(JalChip<SupervisorMode>),
    /// An AIR for RISC-V jal instructions (User mode).
    JalUser(JalChip<UserMode>),
    /// An AIR for RISC-V jalr instructions.
    Jalr(JalrChip<SupervisorMode>),
    /// An AIR for RISC-V jalr instructions (User mode).
    JalrUser(JalrChip<UserMode>),
    /// An AIR for RISC-V ecall instructions.
    SyscallInstrs(SyscallInstrsChip<SupervisorMode>),
    /// An AIR for RISC-V ecall instructions (User mode).
    SyscallInstrsUser(SyscallInstrsChip<UserMode>),
    /// An AIR for traps due to untrusted instruction not having correct permission.
    TrapExec(TrapExecChip),
    /// An AIR for traps due to load, store operations not having correct permission.
    TrapMem(TrapMemChip),
    /// A lookup table for byte operations.
    ByteLookup(ByteChip<F>),
    /// A lookup table for range operations.
    RangeLookup(RangeChip<F>),
    /// A table for initializing the global memory state.
    MemoryGlobalInit(MemoryGlobalChip),
    /// A table for finalizing the global memory state.
    MemoryGlobalFinal(MemoryGlobalChip),
    /// A table for initializing the global page prot state.
    PageProtGlobalInit(PageProtGlobalChip),
    /// A table for finalizing the global page prot state.
    PageProtGlobalFinal(PageProtGlobalChip),
    /// A table for the local memory state.
    MemoryLocal(MemoryLocalChip),
    /// A table for bumping memory timestamps.
    MemoryBump(MemoryBumpChip),
    /// A table for page prot access.
    PageProt(PageProtChip),
    /// A table for the local page prot state.
    PageProtLocal(PageProtLocalChip),
    /// A table for bumping the state timestamps.
    StateBump(StateBumpChip),
    /// A table for all the syscall invocations.
    SyscallCore(SyscallChip<SupervisorMode>),
    /// A table for all the syscall invocations (user mode).
    SyscallCoreUser(SyscallChip<UserMode>),
    /// A table for all the precompile invocations.
    SyscallPrecompile(SyscallChip<SupervisorMode>),
    /// A table for all the precompile invocations (user mode).
    SyscallPrecompileUser(SyscallChip<UserMode>),
    /// A table for all the global interactions.
    Global(GlobalChip),
    /// A precompile for sha256 extend.
    Sha256Extend(ShaExtendChip),
    /// A controller for sha256 extend.
    Sha256ExtendControl(ShaExtendControlChip<SupervisorMode>),
    /// A controller for sha256 extend (user mode).
    Sha256ExtendControlUser(ShaExtendControlChip<UserMode>),
    /// A precompile for sha256 compress.
    Sha256Compress(ShaCompressChip),
    /// A controller for sha256 compress.
    Sha256CompressControl(ShaCompressControlChip<SupervisorMode>),
    /// A controller for sha256 compress (user mode).
    Sha256CompressControlUser(ShaCompressControlChip<UserMode>),
    /// A precompile for addition on the Elliptic curve ed25519.
    Ed25519Add(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>, SupervisorMode>),
    /// A precompile for addition on the Elliptic curve ed25519 (user mode).
    Ed25519AddUser(EdAddAssignChip<EdwardsCurve<Ed25519Parameters>, UserMode>),
    /// A precompile for decompressing a point on the Edwards curve ed25519.
    Ed25519Decompress(EdDecompressChip<Ed25519Parameters, SupervisorMode>),
    /// A precompile for decompressing a point on the Edwards curve ed25519 (user mode).
    Ed25519DecompressUser(EdDecompressChip<Ed25519Parameters, UserMode>),
    /// A precompile for addition on the Elliptic curve secp256k1.
    Secp256k1Add(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>, SupervisorMode>),
    /// A precompile for addition on the Elliptic curve secp256k1 (user mode).
    Secp256k1AddUser(WeierstrassAddAssignChip<SwCurve<Secp256k1Parameters>, UserMode>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1.
    Secp256k1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>, SupervisorMode>),
    /// A precompile for doubling a point on the Elliptic curve secp256k1 (user mode).
    Secp256k1DoubleUser(WeierstrassDoubleAssignChip<SwCurve<Secp256k1Parameters>, UserMode>),
    /// A precompile for addition on the Elliptic curve secp256r1.
    Secp256r1Add(WeierstrassAddAssignChip<SwCurve<Secp256r1Parameters>, SupervisorMode>),
    /// A precompile for addition on the Elliptic curve secp256r1 (user mode).
    Secp256r1AddUser(WeierstrassAddAssignChip<SwCurve<Secp256r1Parameters>, UserMode>),
    /// A precompile for doubling a point on the Elliptic curve secp256r1.
    Secp256r1Double(WeierstrassDoubleAssignChip<SwCurve<Secp256r1Parameters>, SupervisorMode>),
    /// A precompile for doubling a point on the Elliptic curve secp256r1 (user mode).
    Secp256r1DoubleUser(WeierstrassDoubleAssignChip<SwCurve<Secp256r1Parameters>, UserMode>),
    /// A precompile for the Keccak permutation.
    KeccakP(KeccakPermuteChip),
    /// A controller for the Keccak permutation.
    KeccakPControl(KeccakPermuteControlChip<SupervisorMode>),
    /// A controller for the Keccak permutation (user mode).
    KeccakPControlUser(KeccakPermuteControlChip<UserMode>),
    /// A precompile for addition on the Elliptic curve bn254.
    Bn254Add(WeierstrassAddAssignChip<SwCurve<Bn254Parameters>, SupervisorMode>),
    /// A precompile for addition on the Elliptic curve bn254 (user mode).
    Bn254AddUser(WeierstrassAddAssignChip<SwCurve<Bn254Parameters>, UserMode>),
    /// A precompile for doubling a point on the Elliptic curve bn254.
    Bn254Double(WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>, SupervisorMode>),
    /// A precompile for doubling a point on the Elliptic curve bn254 (user mode).
    Bn254DoubleUser(WeierstrassDoubleAssignChip<SwCurve<Bn254Parameters>, UserMode>),
    /// A precompile for addition on the Elliptic curve bls12_381.
    Bls12381Add(WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>, SupervisorMode>),
    /// A precompile for addition on the Elliptic curve bls12_381 (user mode).
    Bls12381AddUser(WeierstrassAddAssignChip<SwCurve<Bls12381Parameters>, UserMode>),
    /// A precompile for doubling a point on the Elliptic curve bls12_381.
    Bls12381Double(WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>, SupervisorMode>),
    /// A precompile for doubling a point on the Elliptic curve bls12_381 (user mode).
    Bls12381DoubleUser(WeierstrassDoubleAssignChip<SwCurve<Bls12381Parameters>, UserMode>),
    /// A precompile for uint256 mul.
    Uint256Mul(Uint256MulChip<SupervisorMode>),
    /// A precompile for uint256 mul (user mode).
    Uint256MulUser(Uint256MulChip<UserMode>),
    /// A precompile for uint256 operations (add/mul with carry).
    Uint256Ops(Uint256OpsChip<SupervisorMode>),
    /// A precompile for uint256 operations (add/mul with carry) (user mode).
    Uint256OpsUser(Uint256OpsChip<UserMode>),
    /// A precompile for BLS12-381 fp operation.
    Bls12381Fp(FpOpChip<Bls12381BaseField, SupervisorMode>),
    /// A precompile for BLS12-381 fp operation (user mode).
    Bls12381FpUser(FpOpChip<Bls12381BaseField, UserMode>),
    /// A precompile for BLS12-381 fp2 multiplication.
    Bls12381Fp2Mul(Fp2MulAssignChip<Bls12381BaseField, SupervisorMode>),
    /// A precompile for BLS12-381 fp2 multiplication (user mode).
    Bls12381Fp2MulUser(Fp2MulAssignChip<Bls12381BaseField, UserMode>),
    /// A precompile for BLS12-381 fp2 addition/subtraction.
    Bls12381Fp2AddSub(Fp2AddSubAssignChip<Bls12381BaseField, SupervisorMode>),
    /// A precompile for BLS12-381 fp2 addition/subtraction (user mode).
    Bls12381Fp2AddSubUser(Fp2AddSubAssignChip<Bls12381BaseField, UserMode>),
    /// A precompile for BN-254 fp operation.
    Bn254Fp(FpOpChip<Bn254BaseField, SupervisorMode>),
    /// A precompile for BN-254 fp operation (user mode).
    Bn254FpUser(FpOpChip<Bn254BaseField, UserMode>),
    /// A precompile for BN-254 fp2 multiplication.
    Bn254Fp2Mul(Fp2MulAssignChip<Bn254BaseField, SupervisorMode>),
    /// A precompile for BN-254 fp2 multiplication (user mode).
    Bn254Fp2MulUser(Fp2MulAssignChip<Bn254BaseField, UserMode>),
    /// A precompile for BN-254 fp2 addition/subtraction.
    Bn254Fp2AddSub(Fp2AddSubAssignChip<Bn254BaseField, SupervisorMode>),
    /// A precompile for BN-254 fp2 addition/subtraction (user mode).
    Bn254Fp2AddSubUser(Fp2AddSubAssignChip<Bn254BaseField, UserMode>),
    /// A precompile for mprotect syscalls.
    Mprotect(MProtectChip),
    /// A precompile for sigreturn syscall.
    SigReturn(SigReturnChip),
    /// A precompile for Poseidon2 permutation.
    Poseidon2(Poseidon2Chip<SupervisorMode>),
    /// A precompile for Poseidon2 permutation (user mode).
    Poseidon2User(Poseidon2Chip<UserMode>),
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
            RiscvAir::Sha256ExtendControl(ShaExtendControlChip::<SupervisorMode>::new()),
            RiscvAir::Sha256ExtendControlUser(ShaExtendControlChip::<UserMode>::new()),
            RiscvAir::Sha256Compress(ShaCompressChip::default()),
            RiscvAir::Sha256CompressControl(ShaCompressControlChip::<SupervisorMode>::new()),
            RiscvAir::Sha256CompressControlUser(ShaCompressControlChip::<UserMode>::new()),
            RiscvAir::Ed25519Add(
                EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>, SupervisorMode>::new(),
            ),
            RiscvAir::Ed25519AddUser(
                EdAddAssignChip::<EdwardsCurve<Ed25519Parameters>, UserMode>::new(),
            ),
            RiscvAir::Ed25519Decompress(
                EdDecompressChip::<Ed25519Parameters, SupervisorMode>::default(),
            ),
            RiscvAir::Ed25519DecompressUser(
                EdDecompressChip::<Ed25519Parameters, UserMode>::default(),
            ),
            RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<
                SwCurve<Secp256k1Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Secp256k1AddUser(WeierstrassAddAssignChip::<
                SwCurve<Secp256k1Parameters>,
                UserMode,
            >::new()),
            RiscvAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Secp256k1DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
                UserMode,
            >::new()),
            RiscvAir::Secp256r1Add(WeierstrassAddAssignChip::<
                SwCurve<Secp256r1Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Secp256r1AddUser(WeierstrassAddAssignChip::<
                SwCurve<Secp256r1Parameters>,
                UserMode,
            >::new()),
            RiscvAir::Secp256r1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Secp256r1DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
                UserMode,
            >::new()),
            RiscvAir::KeccakP(KeccakPermuteChip::new()),
            RiscvAir::KeccakPControl(KeccakPermuteControlChip::<SupervisorMode>::new()),
            RiscvAir::KeccakPControlUser(KeccakPermuteControlChip::<UserMode>::new()),
            RiscvAir::Bn254Add(
                WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>, SupervisorMode>::new(),
            ),
            RiscvAir::Bn254AddUser(
                WeierstrassAddAssignChip::<SwCurve<Bn254Parameters>, UserMode>::new(),
            ),
            RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<
                SwCurve<Bn254Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Bn254DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Bn254Parameters>,
                UserMode,
            >::new()),
            RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<
                SwCurve<Bls12381Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Bls12381AddUser(WeierstrassAddAssignChip::<
                SwCurve<Bls12381Parameters>,
                UserMode,
            >::new()),
            RiscvAir::Bls12381Double(WeierstrassDoubleAssignChip::<
                SwCurve<Bls12381Parameters>,
                SupervisorMode,
            >::new()),
            RiscvAir::Bls12381DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Bls12381Parameters>,
                UserMode,
            >::new()),
            RiscvAir::Uint256Mul(Uint256MulChip::<SupervisorMode>::new()),
            RiscvAir::Uint256MulUser(Uint256MulChip::<UserMode>::new()),
            RiscvAir::Uint256Ops(Uint256OpsChip::<SupervisorMode>::new()),
            RiscvAir::Uint256OpsUser(Uint256OpsChip::<UserMode>::new()),
            RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField, SupervisorMode>::new()),
            RiscvAir::Bls12381FpUser(FpOpChip::<Bls12381BaseField, UserMode>::new()),
            RiscvAir::Bls12381Fp2AddSub(
                Fp2AddSubAssignChip::<Bls12381BaseField, SupervisorMode>::new(),
            ),
            RiscvAir::Bls12381Fp2AddSubUser(
                Fp2AddSubAssignChip::<Bls12381BaseField, UserMode>::new(),
            ),
            RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<Bls12381BaseField, SupervisorMode>::new()),
            RiscvAir::Bls12381Fp2MulUser(Fp2MulAssignChip::<Bls12381BaseField, UserMode>::new()),
            RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField, SupervisorMode>::new()),
            RiscvAir::Bn254FpUser(FpOpChip::<Bn254BaseField, UserMode>::new()),
            RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<Bn254BaseField, SupervisorMode>::new()),
            RiscvAir::Bn254Fp2AddSubUser(Fp2AddSubAssignChip::<Bn254BaseField, UserMode>::new()),
            RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<Bn254BaseField, SupervisorMode>::new()),
            RiscvAir::Bn254Fp2MulUser(Fp2MulAssignChip::<Bn254BaseField, UserMode>::new()),
            RiscvAir::Mprotect(MProtectChip::default()),
            RiscvAir::SigReturn(SigReturnChip::default()),
            RiscvAir::Poseidon2(Poseidon2Chip::<SupervisorMode>::new()),
            RiscvAir::Poseidon2User(Poseidon2Chip::<UserMode>::new()),
            RiscvAir::SyscallCore(SyscallChip::<SupervisorMode>::core()),
            RiscvAir::SyscallCoreUser(SyscallChip::<UserMode>::core()),
            RiscvAir::SyscallPrecompile(SyscallChip::<SupervisorMode>::precompile()),
            RiscvAir::SyscallPrecompileUser(SyscallChip::<UserMode>::precompile()),
            RiscvAir::DivRem(DivRemChip::<SupervisorMode>::default()),
            RiscvAir::DivRemUser(DivRemChip::<UserMode>::default()),
            RiscvAir::Add(AddChip::<SupervisorMode>::default()),
            RiscvAir::AddUser(AddChip::<UserMode>::default()),
            RiscvAir::Addi(AddiChip::<SupervisorMode>::default()),
            RiscvAir::AddiUser(AddiChip::<UserMode>::default()),
            RiscvAir::Addw(AddwChip::<SupervisorMode>::default()),
            RiscvAir::AddwUser(AddwChip::<UserMode>::default()),
            RiscvAir::Sub(SubChip::<SupervisorMode>::default()),
            RiscvAir::SubUser(SubChip::<UserMode>::default()),
            RiscvAir::Subw(SubwChip::<SupervisorMode>::default()),
            RiscvAir::SubwUser(SubwChip::<UserMode>::default()),
            RiscvAir::Bitwise(BitwiseChip::<SupervisorMode>::default()),
            RiscvAir::BitwiseUser(BitwiseChip::<UserMode>::default()),
            RiscvAir::Mul(MulChip::<SupervisorMode>::default()),
            RiscvAir::MulUser(MulChip::<UserMode>::default()),
            RiscvAir::ShiftRight(ShiftRightChip::<SupervisorMode>::default()),
            RiscvAir::ShiftRightUser(ShiftRightChip::<UserMode>::default()),
            RiscvAir::ShiftLeft(ShiftLeftChip::<SupervisorMode>::default()),
            RiscvAir::ShiftLeftUser(ShiftLeftChip::<UserMode>::default()),
            RiscvAir::Lt(LtChip::<SupervisorMode>::default()),
            RiscvAir::LtUser(LtChip::<UserMode>::default()),
            RiscvAir::AluX0(AluX0Chip::<SupervisorMode>::default()),
            RiscvAir::AluX0User(AluX0Chip::<UserMode>::default()),
            RiscvAir::LoadByte(LoadByteChip::<SupervisorMode>::default()),
            RiscvAir::LoadByteUser(LoadByteChip::<UserMode>::default()),
            RiscvAir::LoadHalf(LoadHalfChip::<SupervisorMode>::default()),
            RiscvAir::LoadHalfUser(LoadHalfChip::<UserMode>::default()),
            RiscvAir::LoadWord(LoadWordChip::<SupervisorMode>::default()),
            RiscvAir::LoadWordUser(LoadWordChip::<UserMode>::default()),
            RiscvAir::LoadDouble(LoadDoubleChip::<SupervisorMode>::default()),
            RiscvAir::LoadDoubleUser(LoadDoubleChip::<UserMode>::default()),
            RiscvAir::LoadX0(LoadX0Chip::<SupervisorMode>::default()),
            RiscvAir::LoadX0User(LoadX0Chip::<UserMode>::default()),
            RiscvAir::StoreByte(StoreByteChip::<SupervisorMode>::default()),
            RiscvAir::StoreByteUser(StoreByteChip::<UserMode>::default()),
            RiscvAir::StoreHalf(StoreHalfChip::<SupervisorMode>::default()),
            RiscvAir::StoreHalfUser(StoreHalfChip::<UserMode>::default()),
            RiscvAir::StoreWord(StoreWordChip::<SupervisorMode>::default()),
            RiscvAir::StoreWordUser(StoreWordChip::<UserMode>::default()),
            RiscvAir::StoreDouble(StoreDoubleChip::<SupervisorMode>::default()),
            RiscvAir::StoreDoubleUser(StoreDoubleChip::<UserMode>::default()),
            RiscvAir::UType(UTypeChip::<SupervisorMode>::default()),
            RiscvAir::UTypeUser(UTypeChip::<UserMode>::default()),
            RiscvAir::Branch(BranchChip::<SupervisorMode>::default()),
            RiscvAir::BranchUser(BranchChip::<UserMode>::default()),
            RiscvAir::Jal(JalChip::<SupervisorMode>::default()),
            RiscvAir::JalUser(JalChip::<UserMode>::default()),
            RiscvAir::Jalr(JalrChip::<SupervisorMode>::default()),
            RiscvAir::JalrUser(JalrChip::<UserMode>::default()),
            RiscvAir::InstructionDecode(InstructionDecodeChip::default()),
            RiscvAir::InstructionFetch(InstructionFetchChip::default()),
            RiscvAir::SyscallInstrs(SyscallInstrsChip::<SupervisorMode>::default()),
            RiscvAir::SyscallInstrsUser(SyscallInstrsChip::<UserMode>::default()),
            RiscvAir::TrapExec(TrapExecChip::default()),
            RiscvAir::TrapMem(TrapMemChip::default()),
            RiscvAir::MemoryBump(MemoryBumpChip::new()),
            RiscvAir::PageProt(PageProtChip::default()),
            RiscvAir::PageProtLocal(PageProtLocalChip::default()),
            RiscvAir::StateBump(StateBumpChip::new()),
            RiscvAir::MemoryGlobalInit(MemoryGlobalChip::new(MemoryChipType::Initialize)),
            RiscvAir::MemoryGlobalFinal(MemoryGlobalChip::new(MemoryChipType::Finalize)),
            RiscvAir::PageProtGlobalInit(PageProtGlobalChip::new(MemoryChipType::Initialize)),
            RiscvAir::PageProtGlobalFinal(PageProtGlobalChip::new(MemoryChipType::Finalize)),
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

        #[cfg(feature = "mprotect")]
        let base_precompile_cluster_user = extend_base(
            &preprocessed_chips,
            [SyscallPrecompileUser, MemoryLocal, PageProtLocal, Global],
        );

        let precompile_clusters = [
            [Sha256Extend, Sha256ExtendControl].as_slice(),
            [Sha256Compress, Sha256CompressControl].as_slice(),
            [Ed25519Add].as_slice(),
            [Ed25519Decompress].as_slice(),
            [Secp256k1Add].as_slice(),
            [Secp256k1Double].as_slice(),
            [Secp256r1Add].as_slice(),
            [Secp256r1Double].as_slice(),
            [KeccakP, KeccakPControl].as_slice(),
            [Bn254Add].as_slice(),
            [Bn254Double].as_slice(),
            [Bls12381Add].as_slice(),
            [Bls12381Double].as_slice(),
            [Uint256Mul].as_slice(),
            [Uint256Ops].as_slice(),
            [Bls12381Fp].as_slice(),
            [Bls12381Fp2AddSub].as_slice(),
            [Bls12381Fp2Mul].as_slice(),
            [Bn254Fp].as_slice(),
            [Bn254Fp2AddSub].as_slice(),
            [Bn254Fp2Mul].as_slice(),
            [Poseidon2].as_slice(),
        ]
        .into_iter()
        .map(|ids| extend_base(&base_precompile_cluster, ids.iter().cloned()));

        #[cfg(feature = "mprotect")]
        let precompile_clusters_user = [
            [Sha256Extend, Sha256ExtendControlUser].as_slice(),
            [Sha256Compress, Sha256CompressControlUser].as_slice(),
            [Ed25519AddUser].as_slice(),
            [Ed25519DecompressUser].as_slice(),
            [Secp256k1AddUser].as_slice(),
            [Secp256k1DoubleUser].as_slice(),
            [Secp256r1AddUser].as_slice(),
            [Secp256r1DoubleUser].as_slice(),
            [KeccakP, KeccakPControlUser].as_slice(),
            [Bn254AddUser].as_slice(),
            [Bn254DoubleUser].as_slice(),
            [Bls12381AddUser].as_slice(),
            [Bls12381DoubleUser].as_slice(),
            [Uint256MulUser].as_slice(),
            [Uint256OpsUser].as_slice(),
            [Bls12381FpUser].as_slice(),
            [Bls12381Fp2AddSubUser].as_slice(),
            [Bls12381Fp2MulUser].as_slice(),
            [Bn254FpUser].as_slice(),
            [Bn254Fp2AddSubUser].as_slice(),
            [Bn254Fp2MulUser].as_slice(),
            [Poseidon2User].as_slice(),
            [Mprotect].as_slice(),
            [SigReturn].as_slice(),
        ]
        .into_iter()
        .map(|ids| extend_base(&base_precompile_cluster_user, ids.iter().cloned()));

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
                AluX0,
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

        #[cfg(feature = "mprotect")]
        let core_cluster_user = extend_base(
            &preprocessed_chips,
            [
                SyscallCoreUser,
                DivRemUser,
                AddUser,
                AddiUser,
                AddwUser,
                SubUser,
                SubwUser,
                BitwiseUser,
                MulUser,
                ShiftRightUser,
                ShiftLeftUser,
                LtUser,
                AluX0User,
                LoadByteUser,
                LoadHalfUser,
                LoadWordUser,
                LoadDoubleUser,
                LoadX0User,
                StoreByteUser,
                StoreHalfUser,
                StoreWordUser,
                StoreDoubleUser,
                UTypeUser,
                BranchUser,
                JalUser,
                JalrUser,
                SyscallInstrsUser,
                TrapExec,
                TrapMem,
                MemoryBump,
                StateBump,
                MemoryLocal,
                PageProt,
                PageProtLocal,
                InstructionFetch,
                InstructionDecode,
                Global,
            ],
        );

        let memory_boundary_cluster =
            extend_base(&preprocessed_chips, [MemoryGlobalInit, MemoryGlobalFinal, Global]);

        #[cfg(feature = "mprotect")]
        let memory_boundary_cluster_user = extend_base(
            &preprocessed_chips,
            [MemoryGlobalInit, MemoryGlobalFinal, PageProtGlobalInit, PageProtGlobalFinal, Global],
        );

        // Chip sets that may be included in extended versions of the baseline core cluster.
        let core_cluster_exts = [
            [MemoryGlobalInit, MemoryGlobalFinal].as_slice(),
            [Bls12381Fp].as_slice(),
            [Bn254Fp].as_slice(),
            [Sha256Extend, Sha256ExtendControl, Sha256Compress, Sha256CompressControl].as_slice(),
            [Uint256Ops].as_slice(),
            [Poseidon2].as_slice(),
        ];

        #[cfg(feature = "mprotect")]
        let core_cluster_exts_user = [
            [MemoryGlobalInit, MemoryGlobalFinal, PageProtGlobalInit, PageProtGlobalFinal]
                .as_slice(),
            [Bls12381FpUser].as_slice(),
            [Bn254FpUser].as_slice(),
            [Sha256Extend, Sha256ExtendControlUser, Sha256Compress, Sha256CompressControlUser]
                .as_slice(),
            [Uint256OpsUser].as_slice(),
            [Poseidon2User].as_slice(),
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

        let core_cluster_special = extend_base(
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
        );

        #[cfg(feature = "mprotect")]
        let core_clusters_user = [0, 1, core_cluster_exts_user.len()]
            .into_iter()
            .flat_map(|k| core_cluster_exts_user.into_iter().combinations(k))
            .map(|ext_set| extend_base(&core_cluster_user, ext_set.into_iter().flatten().cloned()));

        #[cfg(feature = "mprotect")]
        let core_cluster_special_user = extend_base(
            &core_cluster_user,
            [
                MemoryGlobalInit,
                MemoryGlobalFinal,
                PageProtGlobalInit,
                PageProtGlobalFinal,
                Sha256Extend,
                Sha256ExtendControlUser,
                Sha256Compress,
                Sha256CompressControlUser,
                Uint256OpsUser,
            ],
        );

        // Collect all clusters and replace the IDs by chips.
        let chip_clusters = core_clusters
            .chain(core::iter::once(core_cluster_special))
            .chain(core::iter::once(memory_boundary_cluster))
            .chain(precompile_clusters);

        #[cfg(feature = "mprotect")]
        let chip_clusters = chip_clusters
            .chain(core_clusters_user)
            .chain(core::iter::once(core_cluster_special_user))
            .chain(core::iter::once(memory_boundary_cluster_user))
            .chain(precompile_clusters_user);

        let chip_clusters = chip_clusters
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

        let instruction_decode =
            Chip::new(RiscvAir::InstructionDecode(InstructionDecodeChip::default()));
        costs.insert(instruction_decode.name().to_string(), instruction_decode.cost());
        chips.push(instruction_decode);

        let instruction_fetch =
            Chip::new(RiscvAir::InstructionFetch(InstructionFetchChip::default()));
        costs.insert(instruction_fetch.name().to_string(), instruction_fetch.cost());
        chips.push(instruction_fetch);

        let program = Chip::new(RiscvAir::Program(ProgramChip::default()));
        costs.insert(program.name().to_string(), program.cost());
        chips.push(program);

        let sha_extend = Chip::new(RiscvAir::Sha256Extend(ShaExtendChip::default()));
        costs.insert(sha_extend.name().to_string(), sha_extend.cost());
        chips.push(sha_extend);

        let sha_extend_control =
            Chip::new(RiscvAir::Sha256ExtendControl(ShaExtendControlChip::<SupervisorMode>::new()));
        costs.insert(sha_extend_control.name().to_string(), sha_extend_control.cost());
        chips.push(sha_extend_control);

        let sha_extend_control_user =
            Chip::new(RiscvAir::Sha256ExtendControlUser(ShaExtendControlChip::<UserMode>::new()));
        costs.insert(sha_extend_control_user.name().to_string(), sha_extend_control_user.cost());
        chips.push(sha_extend_control_user);

        let sha_compress = Chip::new(RiscvAir::Sha256Compress(ShaCompressChip::default()));
        costs.insert(sha_compress.name().to_string(), sha_compress.cost());
        chips.push(sha_compress);

        let sha_compress_control = Chip::new(RiscvAir::Sha256CompressControl(
            ShaCompressControlChip::<SupervisorMode>::new(),
        ));
        costs.insert(sha_compress_control.name().to_string(), sha_compress_control.cost());
        chips.push(sha_compress_control);

        let sha_compress_control_user = Chip::new(RiscvAir::Sha256CompressControlUser(
            ShaCompressControlChip::<UserMode>::new(),
        ));
        costs
            .insert(sha_compress_control_user.name().to_string(), sha_compress_control_user.cost());
        chips.push(sha_compress_control_user);

        let ed_add_assign = Chip::new(RiscvAir::Ed25519Add(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(ed_add_assign.name().to_string(), ed_add_assign.cost());
        chips.push(ed_add_assign);

        let ed_add_assign = Chip::new(RiscvAir::Ed25519AddUser(EdAddAssignChip::<
            EdwardsCurve<Ed25519Parameters>,
            UserMode,
        >::new()));
        costs.insert(ed_add_assign.name().to_string(), ed_add_assign.cost());
        chips.push(ed_add_assign);

        let ed_decompress = Chip::new(RiscvAir::Ed25519Decompress(EdDecompressChip::<
            Ed25519Parameters,
            SupervisorMode,
        >::default()));
        costs.insert(ed_decompress.name().to_string(), ed_decompress.cost());
        chips.push(ed_decompress);

        let ed_decompress_user = Chip::new(RiscvAir::Ed25519DecompressUser(EdDecompressChip::<
            Ed25519Parameters,
            UserMode,
        >::default()));
        costs.insert(ed_decompress_user.name().to_string(), ed_decompress_user.cost());
        chips.push(ed_decompress_user);

        let secp256k1_add_assign = Chip::new(RiscvAir::Secp256k1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256k1Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(secp256k1_add_assign.name().to_string(), secp256k1_add_assign.cost());
        chips.push(secp256k1_add_assign);

        let secp256k1_add_assign_user =
            Chip::new(RiscvAir::Secp256k1AddUser(WeierstrassAddAssignChip::<
                SwCurve<Secp256k1Parameters>,
                UserMode,
            >::new()));
        costs
            .insert(secp256k1_add_assign_user.name().to_string(), secp256k1_add_assign_user.cost());
        chips.push(secp256k1_add_assign_user);

        let secp256k1_double_assign =
            Chip::new(RiscvAir::Secp256k1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
                SupervisorMode,
            >::new()));
        costs.insert(secp256k1_double_assign.name().to_string(), secp256k1_double_assign.cost());
        chips.push(secp256k1_double_assign);

        let secp256k1_double_assign_user =
            Chip::new(RiscvAir::Secp256k1DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256k1Parameters>,
                UserMode,
            >::new()));
        costs.insert(
            secp256k1_double_assign_user.name().to_string(),
            secp256k1_double_assign_user.cost(),
        );
        chips.push(secp256k1_double_assign_user);

        let secp256r1_add_assign = Chip::new(RiscvAir::Secp256r1Add(WeierstrassAddAssignChip::<
            SwCurve<Secp256r1Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(secp256r1_add_assign.name().to_string(), secp256r1_add_assign.cost());
        chips.push(secp256r1_add_assign);

        let secp256r1_add_assign_user =
            Chip::new(RiscvAir::Secp256r1AddUser(WeierstrassAddAssignChip::<
                SwCurve<Secp256r1Parameters>,
                UserMode,
            >::new()));
        costs
            .insert(secp256r1_add_assign_user.name().to_string(), secp256r1_add_assign_user.cost());
        chips.push(secp256r1_add_assign_user);

        let secp256r1_double_assign =
            Chip::new(RiscvAir::Secp256r1Double(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
                SupervisorMode,
            >::new()));
        costs.insert(secp256r1_double_assign.name().to_string(), secp256r1_double_assign.cost());
        chips.push(secp256r1_double_assign);

        let secp256r1_double_assign_user =
            Chip::new(RiscvAir::Secp256r1DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Secp256r1Parameters>,
                UserMode,
            >::new()));
        costs.insert(
            secp256r1_double_assign_user.name().to_string(),
            secp256r1_double_assign_user.cost(),
        );
        chips.push(secp256r1_double_assign_user);

        let keccak_permute = Chip::new(RiscvAir::KeccakP(KeccakPermuteChip::new()));
        costs.insert(keccak_permute.name().to_string(), keccak_permute.cost());
        chips.push(keccak_permute);

        let keccak_control =
            Chip::new(RiscvAir::KeccakPControl(KeccakPermuteControlChip::<SupervisorMode>::new()));
        costs.insert(keccak_control.name().to_string(), keccak_control.cost());
        chips.push(keccak_control);

        let keccak_control_user =
            Chip::new(RiscvAir::KeccakPControlUser(KeccakPermuteControlChip::<UserMode>::new()));
        costs.insert(keccak_control_user.name().to_string(), keccak_control_user.cost());
        chips.push(keccak_control_user);

        let bn254_add_assign = Chip::new(RiscvAir::Bn254Add(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(bn254_add_assign.name().to_string(), bn254_add_assign.cost());
        chips.push(bn254_add_assign);

        let bn254_add_assign_user = Chip::new(RiscvAir::Bn254AddUser(WeierstrassAddAssignChip::<
            SwCurve<Bn254Parameters>,
            UserMode,
        >::new()));
        costs.insert(bn254_add_assign_user.name().to_string(), bn254_add_assign_user.cost());
        chips.push(bn254_add_assign_user);

        let bn254_double_assign = Chip::new(RiscvAir::Bn254Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bn254Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(bn254_double_assign.name().to_string(), bn254_double_assign.cost());
        chips.push(bn254_double_assign);

        let bn254_double_assign_user =
            Chip::new(RiscvAir::Bn254DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Bn254Parameters>,
                UserMode,
            >::new()));
        costs.insert(bn254_double_assign_user.name().to_string(), bn254_double_assign_user.cost());
        chips.push(bn254_double_assign_user);

        let bls12381_add = Chip::new(RiscvAir::Bls12381Add(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(bls12381_add.name().to_string(), bls12381_add.cost());
        chips.push(bls12381_add);

        let bls12381_add_user = Chip::new(RiscvAir::Bls12381AddUser(WeierstrassAddAssignChip::<
            SwCurve<Bls12381Parameters>,
            UserMode,
        >::new()));
        costs.insert(bls12381_add_user.name().to_string(), bls12381_add_user.cost());
        chips.push(bls12381_add_user);

        let bls12381_double = Chip::new(RiscvAir::Bls12381Double(WeierstrassDoubleAssignChip::<
            SwCurve<Bls12381Parameters>,
            SupervisorMode,
        >::new()));
        costs.insert(bls12381_double.name().to_string(), bls12381_double.cost());
        chips.push(bls12381_double);

        let bls12381_double_user =
            Chip::new(RiscvAir::Bls12381DoubleUser(WeierstrassDoubleAssignChip::<
                SwCurve<Bls12381Parameters>,
                UserMode,
            >::new()));
        costs.insert(bls12381_double_user.name().to_string(), bls12381_double_user.cost());
        chips.push(bls12381_double_user);

        let uint256_mul = Chip::new(RiscvAir::Uint256Mul(Uint256MulChip::<SupervisorMode>::new()));
        costs.insert(uint256_mul.name().to_string(), uint256_mul.cost());
        chips.push(uint256_mul);

        let uint256_mul_user =
            Chip::new(RiscvAir::Uint256MulUser(Uint256MulChip::<UserMode>::new()));
        costs.insert(uint256_mul_user.name().to_string(), uint256_mul_user.cost());
        chips.push(uint256_mul_user);

        let uint256_ops = Chip::new(RiscvAir::Uint256Ops(Uint256OpsChip::<SupervisorMode>::new()));
        costs.insert(uint256_ops.name().to_string(), uint256_ops.cost());
        chips.push(uint256_ops);

        let uint256_ops_user =
            Chip::new(RiscvAir::Uint256OpsUser(Uint256OpsChip::<UserMode>::new()));
        costs.insert(uint256_ops_user.name().to_string(), uint256_ops_user.cost());
        chips.push(uint256_ops_user);

        let bls12381_fp =
            Chip::new(RiscvAir::Bls12381Fp(FpOpChip::<Bls12381BaseField, SupervisorMode>::new()));
        costs.insert(bls12381_fp.name().to_string(), bls12381_fp.cost());
        chips.push(bls12381_fp);

        let bls12381_fp_user =
            Chip::new(RiscvAir::Bls12381FpUser(FpOpChip::<Bls12381BaseField, UserMode>::new()));
        costs.insert(bls12381_fp_user.name().to_string(), bls12381_fp_user.cost());
        chips.push(bls12381_fp_user);

        let bls12381_fp2_addsub = Chip::new(RiscvAir::Bls12381Fp2AddSub(Fp2AddSubAssignChip::<
            Bls12381BaseField,
            SupervisorMode,
        >::new()));
        costs.insert(bls12381_fp2_addsub.name().to_string(), bls12381_fp2_addsub.cost());
        chips.push(bls12381_fp2_addsub);

        let bls12381_fp2_addsub_user =
            Chip::new(RiscvAir::Bls12381Fp2AddSubUser(Fp2AddSubAssignChip::<
                Bls12381BaseField,
                UserMode,
            >::new()));
        costs.insert(bls12381_fp2_addsub_user.name().to_string(), bls12381_fp2_addsub_user.cost());
        chips.push(bls12381_fp2_addsub_user);

        let bls12381_fp2_mul = Chip::new(RiscvAir::Bls12381Fp2Mul(Fp2MulAssignChip::<
            Bls12381BaseField,
            SupervisorMode,
        >::new()));
        costs.insert(bls12381_fp2_mul.name().to_string(), bls12381_fp2_mul.cost());
        chips.push(bls12381_fp2_mul);

        let bls12381_fp2_mul_user = Chip::new(RiscvAir::Bls12381Fp2MulUser(Fp2MulAssignChip::<
            Bls12381BaseField,
            UserMode,
        >::new()));
        costs.insert(bls12381_fp2_mul_user.name().to_string(), bls12381_fp2_mul_user.cost());
        chips.push(bls12381_fp2_mul_user);

        let bn254_fp =
            Chip::new(RiscvAir::Bn254Fp(FpOpChip::<Bn254BaseField, SupervisorMode>::new()));
        costs.insert(bn254_fp.name().to_string(), bn254_fp.cost());
        chips.push(bn254_fp);

        let bn254_fp_user =
            Chip::new(RiscvAir::Bn254FpUser(FpOpChip::<Bn254BaseField, UserMode>::new()));
        costs.insert(bn254_fp_user.name().to_string(), bn254_fp_user.cost());
        chips.push(bn254_fp_user);

        let bn254_fp2_addsub = Chip::new(RiscvAir::Bn254Fp2AddSub(Fp2AddSubAssignChip::<
            Bn254BaseField,
            SupervisorMode,
        >::new()));
        costs.insert(bn254_fp2_addsub.name().to_string(), bn254_fp2_addsub.cost());
        chips.push(bn254_fp2_addsub);

        let bn254_fp2_addsub_user = Chip::new(RiscvAir::Bn254Fp2AddSubUser(Fp2AddSubAssignChip::<
            Bn254BaseField,
            UserMode,
        >::new()));
        costs.insert(bn254_fp2_addsub_user.name().to_string(), bn254_fp2_addsub_user.cost());
        chips.push(bn254_fp2_addsub_user);

        let bn254_fp2_mul = Chip::new(RiscvAir::Bn254Fp2Mul(Fp2MulAssignChip::<
            Bn254BaseField,
            SupervisorMode,
        >::new()));
        costs.insert(bn254_fp2_mul.name().to_string(), bn254_fp2_mul.cost());
        chips.push(bn254_fp2_mul);

        let bn254_fp2_mul_user = Chip::new(RiscvAir::Bn254Fp2MulUser(Fp2MulAssignChip::<
            Bn254BaseField,
            UserMode,
        >::new()));
        costs.insert(bn254_fp2_mul_user.name().to_string(), bn254_fp2_mul_user.cost());
        chips.push(bn254_fp2_mul_user);

        let mprotect = Chip::new(RiscvAir::Mprotect(MProtectChip::default()));
        costs.insert(mprotect.name().to_string(), mprotect.cost());
        chips.push(mprotect);

        let sig_return = Chip::new(RiscvAir::SigReturn(SigReturnChip::default()));
        costs.insert(sig_return.name().to_string(), sig_return.cost());
        chips.push(sig_return);

        let syscall_core = Chip::new(RiscvAir::SyscallCore(SyscallChip::<SupervisorMode>::core()));
        costs.insert(syscall_core.name().to_string(), syscall_core.cost());
        chips.push(syscall_core);

        let syscall_core = Chip::new(RiscvAir::SyscallCoreUser(SyscallChip::<UserMode>::core()));
        costs.insert(syscall_core.name().to_string(), syscall_core.cost());
        chips.push(syscall_core);

        let syscall_precompile =
            Chip::new(RiscvAir::SyscallPrecompile(SyscallChip::<SupervisorMode>::precompile()));
        costs.insert(syscall_precompile.name().to_string(), syscall_precompile.cost());
        chips.push(syscall_precompile);

        let syscall_precompile =
            Chip::new(RiscvAir::SyscallPrecompileUser(SyscallChip::<UserMode>::precompile()));
        costs.insert(syscall_precompile.name().to_string(), syscall_precompile.cost());
        chips.push(syscall_precompile);

        let div_rem = Chip::new(RiscvAir::DivRem(DivRemChip::<SupervisorMode>::default()));
        costs.insert(div_rem.name().to_string(), div_rem.cost());
        chips.push(div_rem);

        let div_rem = Chip::new(RiscvAir::DivRemUser(DivRemChip::<UserMode>::default()));
        costs.insert(div_rem.name().to_string(), div_rem.cost());
        chips.push(div_rem);

        let add = Chip::new(RiscvAir::Add(AddChip::<SupervisorMode>::default()));
        costs.insert(add.name().to_string(), add.cost());
        chips.push(add);

        let add = Chip::new(RiscvAir::AddUser(AddChip::<UserMode>::default()));
        costs.insert(add.name().to_string(), add.cost());
        chips.push(add);

        let addw = Chip::new(RiscvAir::Addw(AddwChip::<SupervisorMode>::default()));
        costs.insert(addw.name().to_string(), addw.cost());
        chips.push(addw);

        let addw = Chip::new(RiscvAir::AddwUser(AddwChip::<UserMode>::default()));
        costs.insert(addw.name().to_string(), addw.cost());
        chips.push(addw);

        let addi = Chip::new(RiscvAir::Addi(AddiChip::<SupervisorMode>::default()));
        costs.insert(addi.name().to_string(), addi.cost());
        chips.push(addi);

        let addi = Chip::new(RiscvAir::AddiUser(AddiChip::<UserMode>::default()));
        costs.insert(addi.name().to_string(), addi.cost());
        chips.push(addi);

        let sub = Chip::new(RiscvAir::Sub(SubChip::<SupervisorMode>::default()));
        costs.insert(sub.name().to_string(), sub.cost());
        chips.push(sub);

        let sub = Chip::new(RiscvAir::SubUser(SubChip::<UserMode>::default()));
        costs.insert(sub.name().to_string(), sub.cost());
        chips.push(sub);

        let subw = Chip::new(RiscvAir::Subw(SubwChip::<SupervisorMode>::default()));
        costs.insert(subw.name().to_string(), subw.cost());
        chips.push(subw);

        let subw = Chip::new(RiscvAir::SubwUser(SubwChip::<UserMode>::default()));
        costs.insert(subw.name().to_string(), subw.cost());
        chips.push(subw);

        let bitwise = Chip::new(RiscvAir::Bitwise(BitwiseChip::<SupervisorMode>::default()));
        costs.insert(bitwise.name().to_string(), bitwise.cost());
        chips.push(bitwise);

        let bitwise = Chip::new(RiscvAir::BitwiseUser(BitwiseChip::<UserMode>::default()));
        costs.insert(bitwise.name().to_string(), bitwise.cost());
        chips.push(bitwise);

        let mul = Chip::new(RiscvAir::Mul(MulChip::<SupervisorMode>::default()));
        costs.insert(mul.name().to_string(), mul.cost());
        chips.push(mul);

        let mul = Chip::new(RiscvAir::MulUser(MulChip::<UserMode>::default()));
        costs.insert(mul.name().to_string(), mul.cost());
        chips.push(mul);

        let shift_right =
            Chip::new(RiscvAir::ShiftRight(ShiftRightChip::<SupervisorMode>::default()));
        costs.insert(shift_right.name().to_string(), shift_right.cost());
        chips.push(shift_right);

        let shift_right =
            Chip::new(RiscvAir::ShiftRightUser(ShiftRightChip::<UserMode>::default()));
        costs.insert(shift_right.name().to_string(), shift_right.cost());
        chips.push(shift_right);

        let shift_left = Chip::new(RiscvAir::ShiftLeft(ShiftLeftChip::<SupervisorMode>::default()));
        costs.insert(shift_left.name().to_string(), shift_left.cost());
        chips.push(shift_left);

        let shift_left = Chip::new(RiscvAir::ShiftLeftUser(ShiftLeftChip::<UserMode>::default()));
        costs.insert(shift_left.name().to_string(), shift_left.cost());
        chips.push(shift_left);

        let lt = Chip::new(RiscvAir::Lt(LtChip::<SupervisorMode>::default()));
        costs.insert(lt.name().to_string(), lt.cost());
        chips.push(lt);

        let lt = Chip::new(RiscvAir::LtUser(LtChip::<UserMode>::default()));
        costs.insert(lt.name().to_string(), lt.cost());
        chips.push(lt);

        let alu_x0 = Chip::new(RiscvAir::AluX0(AluX0Chip::<SupervisorMode>::default()));
        costs.insert(alu_x0.name().to_string(), alu_x0.cost());
        chips.push(alu_x0);

        let alu_x0 = Chip::new(RiscvAir::AluX0User(AluX0Chip::<UserMode>::default()));
        costs.insert(alu_x0.name().to_string(), alu_x0.cost());
        chips.push(alu_x0);

        let load_byte = Chip::new(RiscvAir::LoadByte(LoadByteChip::<SupervisorMode>::default()));
        costs.insert(load_byte.name().to_string(), load_byte.cost());
        chips.push(load_byte);

        let load_byte = Chip::new(RiscvAir::LoadByteUser(LoadByteChip::<UserMode>::default()));
        costs.insert(load_byte.name().to_string(), load_byte.cost());
        chips.push(load_byte);

        let load_half = Chip::new(RiscvAir::LoadHalf(LoadHalfChip::<SupervisorMode>::default()));
        costs.insert(load_half.name().to_string(), load_half.cost());
        chips.push(load_half);

        let load_half = Chip::new(RiscvAir::LoadHalfUser(LoadHalfChip::<UserMode>::default()));
        costs.insert(load_half.name().to_string(), load_half.cost());
        chips.push(load_half);

        let load_word = Chip::new(RiscvAir::LoadWord(LoadWordChip::<SupervisorMode>::default()));
        costs.insert(load_word.name().to_string(), load_word.cost());
        chips.push(load_word);

        let load_word = Chip::new(RiscvAir::LoadWordUser(LoadWordChip::<UserMode>::default()));
        costs.insert(load_word.name().to_string(), load_word.cost());
        chips.push(load_word);

        let load_x0 = Chip::new(RiscvAir::LoadX0(LoadX0Chip::<SupervisorMode>::default()));
        costs.insert(load_x0.name().to_string(), load_x0.cost());
        chips.push(load_x0);

        let load_x0 = Chip::new(RiscvAir::LoadX0User(LoadX0Chip::<UserMode>::default()));
        costs.insert(load_x0.name().to_string(), load_x0.cost());
        chips.push(load_x0);

        let load_double =
            Chip::new(RiscvAir::LoadDouble(LoadDoubleChip::<SupervisorMode>::default()));
        costs.insert(load_double.name().to_string(), load_double.cost());
        chips.push(load_double);

        let load_double =
            Chip::new(RiscvAir::LoadDoubleUser(LoadDoubleChip::<UserMode>::default()));
        costs.insert(load_double.name().to_string(), load_double.cost());
        chips.push(load_double);

        let store_byte = Chip::new(RiscvAir::StoreByte(StoreByteChip::<SupervisorMode>::default()));
        costs.insert(store_byte.name().to_string(), store_byte.cost());
        chips.push(store_byte);

        let store_byte = Chip::new(RiscvAir::StoreByteUser(StoreByteChip::<UserMode>::default()));
        costs.insert(store_byte.name().to_string(), store_byte.cost());
        chips.push(store_byte);

        let store_half = Chip::new(RiscvAir::StoreHalf(StoreHalfChip::<SupervisorMode>::default()));
        costs.insert(store_half.name().to_string(), store_half.cost());
        chips.push(store_half);

        let store_half = Chip::new(RiscvAir::StoreHalfUser(StoreHalfChip::<UserMode>::default()));
        costs.insert(store_half.name().to_string(), store_half.cost());
        chips.push(store_half);

        let store_word = Chip::new(RiscvAir::StoreWord(StoreWordChip::<SupervisorMode>::default()));
        costs.insert(store_word.name().to_string(), store_word.cost());
        chips.push(store_word);

        let store_word = Chip::new(RiscvAir::StoreWordUser(StoreWordChip::<UserMode>::default()));
        costs.insert(store_word.name().to_string(), store_word.cost());
        chips.push(store_word);

        let store_double =
            Chip::new(RiscvAir::StoreDouble(StoreDoubleChip::<SupervisorMode>::default()));
        costs.insert(store_double.name().to_string(), store_double.cost());
        chips.push(store_double);

        let store_double =
            Chip::new(RiscvAir::StoreDoubleUser(StoreDoubleChip::<UserMode>::default()));
        costs.insert(store_double.name().to_string(), store_double.cost());
        chips.push(store_double);

        let utype = Chip::new(RiscvAir::UType(UTypeChip::<SupervisorMode>::default()));
        costs.insert(utype.name().to_string(), utype.cost());
        chips.push(utype);

        let utype = Chip::new(RiscvAir::UTypeUser(UTypeChip::<UserMode>::default()));
        costs.insert(utype.name().to_string(), utype.cost());
        chips.push(utype);

        let branch = Chip::new(RiscvAir::Branch(BranchChip::<SupervisorMode>::default()));
        costs.insert(branch.name().to_string(), branch.cost());
        chips.push(branch);

        let branch = Chip::new(RiscvAir::BranchUser(BranchChip::<UserMode>::default()));
        costs.insert(branch.name().to_string(), branch.cost());
        chips.push(branch);

        let jal = Chip::new(RiscvAir::Jal(JalChip::<SupervisorMode>::default()));
        costs.insert(jal.name().to_string(), jal.cost());
        chips.push(jal);

        let jal = Chip::new(RiscvAir::JalUser(JalChip::<UserMode>::default()));
        costs.insert(jal.name().to_string(), jal.cost());
        chips.push(jal);

        let jalr = Chip::new(RiscvAir::Jalr(JalrChip::<SupervisorMode>::default()));
        costs.insert(jalr.name().to_string(), jalr.cost());
        chips.push(jalr);

        let jalr = Chip::new(RiscvAir::JalrUser(JalrChip::<UserMode>::default()));
        costs.insert(jalr.name().to_string(), jalr.cost());
        chips.push(jalr);

        let syscall_instrs =
            Chip::new(RiscvAir::SyscallInstrs(SyscallInstrsChip::<SupervisorMode>::default()));
        costs.insert(syscall_instrs.name().to_string(), syscall_instrs.cost());
        chips.push(syscall_instrs);

        let syscall_instrs =
            Chip::new(RiscvAir::SyscallInstrsUser(SyscallInstrsChip::<UserMode>::default()));
        costs.insert(syscall_instrs.name().to_string(), syscall_instrs.cost());
        chips.push(syscall_instrs);

        let trap_exec = Chip::new(RiscvAir::TrapExec(TrapExecChip::default()));
        costs.insert(trap_exec.name().to_string(), trap_exec.cost());
        chips.push(trap_exec);

        let trap_mem = Chip::new(RiscvAir::TrapMem(TrapMemChip::default()));
        costs.insert(trap_mem.name().to_string(), trap_mem.cost());
        chips.push(trap_mem);

        let memory_bump = Chip::new(RiscvAir::MemoryBump(MemoryBumpChip::new()));
        costs.insert(memory_bump.name().to_string(), memory_bump.cost());
        chips.push(memory_bump);

        let page_prot = Chip::new(RiscvAir::PageProt(PageProtChip::default()));
        costs.insert(page_prot.name().to_string(), page_prot.cost());
        chips.push(page_prot);

        let page_prot_local = Chip::new(RiscvAir::PageProtLocal(PageProtLocalChip::default()));
        costs.insert(page_prot_local.name().to_string(), page_prot_local.cost());
        chips.push(page_prot_local);

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

        let page_prot_global_init = Chip::new(RiscvAir::PageProtGlobalInit(
            PageProtGlobalChip::new(MemoryChipType::Initialize),
        ));
        costs.insert(page_prot_global_init.name().to_string(), page_prot_global_init.cost());
        chips.push(page_prot_global_init);

        let page_prot_global_finalize = Chip::new(RiscvAir::PageProtGlobalFinal(
            PageProtGlobalChip::new(MemoryChipType::Finalize),
        ));
        costs
            .insert(page_prot_global_finalize.name().to_string(), page_prot_global_finalize.cost());
        chips.push(page_prot_global_finalize);

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

        let poseidon2 = Chip::new(RiscvAir::Poseidon2(Poseidon2Chip::<SupervisorMode>::new()));
        costs.insert(poseidon2.name().to_string(), poseidon2.cost());
        chips.push(poseidon2);

        let poseidon2_user = Chip::new(RiscvAir::Poseidon2User(Poseidon2Chip::<UserMode>::new()));
        costs.insert(poseidon2_user.name().to_string(), poseidon2_user.cost());
        chips.push(poseidon2_user);

        assert_eq!(chips.len(), costs.len(), "chips and costs must have the same length",);

        (chips, costs)
    }

    /// Get the heights of the chips for a given execution record.
    pub fn core_heights(record: &ExecutionRecord) -> Vec<(RiscvAirId, usize)> {
        if record.program.enable_untrusted_programs {
            vec![
                (RiscvAirId::DivRemUser, record.divrem_events.len()),
                (RiscvAirId::AddUser, record.add_events.len()),
                (RiscvAirId::AddwUser, record.addw_events.len()),
                (RiscvAirId::AddiUser, record.addi_events.len()),
                (RiscvAirId::SubUser, record.sub_events.len()),
                (RiscvAirId::SubwUser, record.subw_events.len()),
                (RiscvAirId::BitwiseUser, record.bitwise_events.len()),
                (RiscvAirId::MulUser, record.mul_events.len()),
                (RiscvAirId::ShiftRightUser, record.shift_right_events.len()),
                (RiscvAirId::ShiftLeftUser, record.shift_left_events.len()),
                (RiscvAirId::LtUser, record.lt_events.len()),
                (RiscvAirId::AluX0User, record.alu_x0_events.len()),
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
                (RiscvAirId::LoadByteUser, record.memory_load_byte_events.len()),
                (RiscvAirId::LoadHalfUser, record.memory_load_half_events.len()),
                (RiscvAirId::LoadWordUser, record.memory_load_word_events.len()),
                (RiscvAirId::LoadDoubleUser, record.memory_load_double_events.len()),
                (RiscvAirId::LoadX0User, record.memory_load_x0_events.len()),
                (RiscvAirId::StoreByteUser, record.memory_store_byte_events.len()),
                (RiscvAirId::StoreHalfUser, record.memory_store_half_events.len()),
                (RiscvAirId::StoreWordUser, record.memory_store_word_events.len()),
                (RiscvAirId::StoreDoubleUser, record.memory_store_double_events.len()),
                (RiscvAirId::UTypeUser, record.utype_events.len()),
                (RiscvAirId::BranchUser, record.branch_events.len()),
                (RiscvAirId::JalUser, record.jal_events.len()),
                (RiscvAirId::JalrUser, record.jalr_events.len()),
                (RiscvAirId::Global, record.global_interaction_events.len()),
                (RiscvAirId::SyscallCore, record.syscall_events.len()),
                (RiscvAirId::SyscallInstrsUser, record.syscall_events.len()),
                (RiscvAirId::InstructionDecode, record.instruction_fetch_events.len()),
                (RiscvAirId::InstructionFetch, record.instruction_fetch_events.len()),
            ]
        } else {
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
                (RiscvAirId::AluX0, record.alu_x0_events.len()),
                (
                    RiscvAirId::MemoryLocal,
                    record
                        .get_local_mem_events()
                        .chunks(NUM_LOCAL_MEMORY_ENTRIES_PER_ROW)
                        .into_iter()
                        .count(),
                ),
                (RiscvAirId::MemoryBump, record.bump_memory_events.len()),
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
            ]
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
            RiscvAirDiscriminants::InstructionDecode => RiscvAirId::InstructionDecode,
            RiscvAirDiscriminants::InstructionFetch => RiscvAirId::InstructionFetch,
            RiscvAirDiscriminants::Add => RiscvAirId::Add,
            RiscvAirDiscriminants::AddUser => RiscvAirId::AddUser,
            RiscvAirDiscriminants::Addw => RiscvAirId::Addw,
            RiscvAirDiscriminants::AddwUser => RiscvAirId::AddwUser,
            RiscvAirDiscriminants::Addi => RiscvAirId::Addi,
            RiscvAirDiscriminants::AddiUser => RiscvAirId::AddiUser,
            RiscvAirDiscriminants::Sub => RiscvAirId::Sub,
            RiscvAirDiscriminants::SubUser => RiscvAirId::SubUser,
            RiscvAirDiscriminants::Subw => RiscvAirId::Subw,
            RiscvAirDiscriminants::SubwUser => RiscvAirId::SubwUser,
            RiscvAirDiscriminants::Bitwise => RiscvAirId::Bitwise,
            RiscvAirDiscriminants::BitwiseUser => RiscvAirId::BitwiseUser,
            RiscvAirDiscriminants::Mul => RiscvAirId::Mul,
            RiscvAirDiscriminants::MulUser => RiscvAirId::MulUser,
            RiscvAirDiscriminants::DivRem => RiscvAirId::DivRem,
            RiscvAirDiscriminants::DivRemUser => RiscvAirId::DivRemUser,
            RiscvAirDiscriminants::Lt => RiscvAirId::Lt,
            RiscvAirDiscriminants::LtUser => RiscvAirId::LtUser,
            RiscvAirDiscriminants::ShiftLeft => RiscvAirId::ShiftLeft,
            RiscvAirDiscriminants::ShiftLeftUser => RiscvAirId::ShiftLeftUser,
            RiscvAirDiscriminants::ShiftRight => RiscvAirId::ShiftRight,
            RiscvAirDiscriminants::ShiftRightUser => RiscvAirId::ShiftRightUser,
            RiscvAirDiscriminants::LoadByte => RiscvAirId::LoadByte,
            RiscvAirDiscriminants::LoadByteUser => RiscvAirId::LoadByteUser,
            RiscvAirDiscriminants::LoadHalf => RiscvAirId::LoadHalf,
            RiscvAirDiscriminants::LoadHalfUser => RiscvAirId::LoadHalfUser,
            RiscvAirDiscriminants::LoadWord => RiscvAirId::LoadWord,
            RiscvAirDiscriminants::LoadWordUser => RiscvAirId::LoadWordUser,
            RiscvAirDiscriminants::LoadX0 => RiscvAirId::LoadX0,
            RiscvAirDiscriminants::LoadX0User => RiscvAirId::LoadX0User,
            RiscvAirDiscriminants::LoadDouble => RiscvAirId::LoadDouble,
            RiscvAirDiscriminants::LoadDoubleUser => RiscvAirId::LoadDoubleUser,
            RiscvAirDiscriminants::StoreByte => RiscvAirId::StoreByte,
            RiscvAirDiscriminants::StoreByteUser => RiscvAirId::StoreByteUser,
            RiscvAirDiscriminants::StoreHalf => RiscvAirId::StoreHalf,
            RiscvAirDiscriminants::StoreHalfUser => RiscvAirId::StoreHalfUser,
            RiscvAirDiscriminants::StoreWord => RiscvAirId::StoreWord,
            RiscvAirDiscriminants::StoreWordUser => RiscvAirId::StoreWordUser,
            RiscvAirDiscriminants::StoreDouble => RiscvAirId::StoreDouble,
            RiscvAirDiscriminants::StoreDoubleUser => RiscvAirId::StoreDoubleUser,
            RiscvAirDiscriminants::RangeLookup => RiscvAirId::Range,
            RiscvAirDiscriminants::MemoryBump => RiscvAirId::MemoryBump,
            RiscvAirDiscriminants::PageProt => RiscvAirId::PageProt,
            RiscvAirDiscriminants::PageProtLocal => RiscvAirId::PageProtLocal,
            RiscvAirDiscriminants::StateBump => RiscvAirId::StateBump,
            RiscvAirDiscriminants::UType => RiscvAirId::UType,
            RiscvAirDiscriminants::UTypeUser => RiscvAirId::UTypeUser,
            RiscvAirDiscriminants::Branch => RiscvAirId::Branch,
            RiscvAirDiscriminants::BranchUser => RiscvAirId::BranchUser,
            RiscvAirDiscriminants::Jal => RiscvAirId::Jal,
            RiscvAirDiscriminants::JalUser => RiscvAirId::JalUser,
            RiscvAirDiscriminants::Jalr => RiscvAirId::Jalr,
            RiscvAirDiscriminants::JalrUser => RiscvAirId::JalrUser,
            RiscvAirDiscriminants::SyscallInstrs => RiscvAirId::SyscallInstrs,
            RiscvAirDiscriminants::SyscallInstrsUser => RiscvAirId::SyscallInstrsUser,
            RiscvAirDiscriminants::TrapExec => RiscvAirId::TrapExec,
            RiscvAirDiscriminants::TrapMem => RiscvAirId::TrapMem,
            RiscvAirDiscriminants::ByteLookup => RiscvAirId::Byte,
            RiscvAirDiscriminants::MemoryGlobalInit => RiscvAirId::MemoryGlobalInit,
            RiscvAirDiscriminants::MemoryGlobalFinal => RiscvAirId::MemoryGlobalFinalize,
            RiscvAirDiscriminants::PageProtGlobalInit => RiscvAirId::PageProtGlobalInit,
            RiscvAirDiscriminants::PageProtGlobalFinal => RiscvAirId::PageProtGlobalFinalize,
            RiscvAirDiscriminants::MemoryLocal => RiscvAirId::MemoryLocal,
            RiscvAirDiscriminants::SyscallCore => RiscvAirId::SyscallCore,
            RiscvAirDiscriminants::SyscallCoreUser => RiscvAirId::SyscallCoreUser,
            RiscvAirDiscriminants::SyscallPrecompile => RiscvAirId::SyscallPrecompile,
            RiscvAirDiscriminants::SyscallPrecompileUser => RiscvAirId::SyscallPrecompileUser,
            RiscvAirDiscriminants::Global => RiscvAirId::Global,
            RiscvAirDiscriminants::Sha256Extend => RiscvAirId::ShaExtend,
            RiscvAirDiscriminants::Sha256Compress => RiscvAirId::ShaCompress,
            RiscvAirDiscriminants::Ed25519Add => RiscvAirId::EdAddAssign,
            RiscvAirDiscriminants::Ed25519AddUser => RiscvAirId::EdAddAssignUser,
            RiscvAirDiscriminants::Ed25519Decompress => RiscvAirId::EdDecompress,
            RiscvAirDiscriminants::Ed25519DecompressUser => RiscvAirId::EdDecompressUser,
            RiscvAirDiscriminants::Secp256k1Add => RiscvAirId::Secp256k1AddAssign,
            RiscvAirDiscriminants::Secp256k1AddUser => RiscvAirId::Secp256k1AddAssignUser,
            RiscvAirDiscriminants::Secp256k1Double => RiscvAirId::Secp256k1DoubleAssign,
            RiscvAirDiscriminants::Secp256k1DoubleUser => RiscvAirId::Secp256k1DoubleAssignUser,
            RiscvAirDiscriminants::Secp256r1Add => RiscvAirId::Secp256r1AddAssign,
            RiscvAirDiscriminants::Secp256r1AddUser => RiscvAirId::Secp256r1AddAssignUser,
            RiscvAirDiscriminants::Secp256r1Double => RiscvAirId::Secp256r1DoubleAssign,
            RiscvAirDiscriminants::Secp256r1DoubleUser => RiscvAirId::Secp256r1DoubleAssignUser,
            RiscvAirDiscriminants::KeccakP => RiscvAirId::KeccakPermute,
            RiscvAirDiscriminants::Bn254Add => RiscvAirId::Bn254AddAssign,
            RiscvAirDiscriminants::Bn254AddUser => RiscvAirId::Bn254AddAssignUser,
            RiscvAirDiscriminants::Bn254Double => RiscvAirId::Bn254DoubleAssign,
            RiscvAirDiscriminants::Bn254DoubleUser => RiscvAirId::Bn254DoubleAssignUser,
            RiscvAirDiscriminants::Bls12381Add => RiscvAirId::Bls12381AddAssign,
            RiscvAirDiscriminants::Bls12381AddUser => RiscvAirId::Bls12381AddAssignUser,
            RiscvAirDiscriminants::Bls12381Double => RiscvAirId::Bls12381DoubleAssign,
            RiscvAirDiscriminants::Bls12381DoubleUser => RiscvAirId::Bls12381DoubleAssignUser,
            RiscvAirDiscriminants::Uint256Mul => RiscvAirId::Uint256MulMod,
            RiscvAirDiscriminants::Uint256MulUser => RiscvAirId::Uint256MulModUser,
            RiscvAirDiscriminants::Uint256Ops => RiscvAirId::Uint256Ops,
            RiscvAirDiscriminants::Uint256OpsUser => RiscvAirId::Uint256OpsUser,
            RiscvAirDiscriminants::Bls12381Fp => RiscvAirId::Bls12381FpOpAssign,
            RiscvAirDiscriminants::Bls12381FpUser => RiscvAirId::Bls12381FpOpAssignUser,
            RiscvAirDiscriminants::Bls12381Fp2Mul => RiscvAirId::Bls12381Fp2MulAssign,
            RiscvAirDiscriminants::Bls12381Fp2MulUser => RiscvAirId::Bls12381Fp2MulAssignUser,
            RiscvAirDiscriminants::Bls12381Fp2AddSub => RiscvAirId::Bls12381Fp2AddSubAssign,
            RiscvAirDiscriminants::Bls12381Fp2AddSubUser => RiscvAirId::Bls12381Fp2AddSubAssignUser,
            RiscvAirDiscriminants::Bn254Fp => RiscvAirId::Bn254FpOpAssign,
            RiscvAirDiscriminants::Bn254FpUser => RiscvAirId::Bn254FpOpAssignUser,
            RiscvAirDiscriminants::Bn254Fp2Mul => RiscvAirId::Bn254Fp2MulAssign,
            RiscvAirDiscriminants::Bn254Fp2MulUser => RiscvAirId::Bn254Fp2MulAssignUser,
            RiscvAirDiscriminants::Bn254Fp2AddSub => RiscvAirId::Bn254Fp2AddSubAssign,
            RiscvAirDiscriminants::Bn254Fp2AddSubUser => RiscvAirId::Bn254Fp2AddSubAssignUser,
            RiscvAirDiscriminants::Sha256ExtendControl => RiscvAirId::ShaExtendControl,
            RiscvAirDiscriminants::Sha256ExtendControlUser => RiscvAirId::ShaExtendControlUser,
            RiscvAirDiscriminants::Sha256CompressControl => RiscvAirId::ShaCompressControl,
            RiscvAirDiscriminants::Sha256CompressControlUser => RiscvAirId::ShaCompressControlUser,
            RiscvAirDiscriminants::KeccakPControl => RiscvAirId::KeccakPermuteControl,
            RiscvAirDiscriminants::KeccakPControlUser => RiscvAirId::KeccakPermuteControlUser,
            RiscvAirDiscriminants::Mprotect => RiscvAirId::Mprotect,
            RiscvAirDiscriminants::SigReturn => RiscvAirId::SigReturn,
            RiscvAirDiscriminants::Poseidon2 => RiscvAirId::Poseidon2,
            RiscvAirDiscriminants::Poseidon2User => RiscvAirId::Poseidon2User,
            RiscvAirDiscriminants::AluX0 => RiscvAirId::AluX0,
            RiscvAirDiscriminants::AluX0User => RiscvAirId::AluX0User,
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
                    .map(|interaction| (interaction.kind, interaction.values.len()))
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
    #[ignore = "should only be used to generate the artifact"]
    fn write_core_air_complexity() {
        let complexity: HashMap<String, u64> = RiscvAir::<SP1Field>::machine()
            .chips()
            .iter()
            .map(|chip| (chip.name().to_string(), chip.num_constraints as u64))
            .collect();

        let dir = std::path::Path::new("../executor/src/artifacts");
        if !dir.exists() {
            std::fs::create_dir_all(dir).unwrap();
        }

        #[cfg(feature = "mprotect")]
        let filename = "rv64im_complexity_mprotect.json";
        #[cfg(not(feature = "mprotect"))]
        let filename = "rv64im_complexity.json";

        let file = std::fs::File::create(dir.join(filename)).unwrap();
        serde_json::to_writer_pretty(file, &complexity).unwrap();
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
            if syscall_code.should_send() == 0 || syscall_code.as_air_id().is_none() {
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

    #[tokio::test]
    async fn test_jalr_lsb_prove() {
        setup_logger();
        let mut instructions = vec![
            Instruction::new(Opcode::ADDI, 29, 0, 9, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 0, false, true),
            Instruction::new(Opcode::JALR, 27, 29, 8, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 0xFF, false, true),
            Instruction::new(Opcode::ADDI, 28, 0, 0x42, false, true),
        ];

        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_alu_x0_prove() {
        setup_logger();

        let reg_reg_ops = [
            // AddChip (RTypeReader)
            Opcode::ADD,
            // SubChip (RTypeReader)
            Opcode::SUB,
            // SubwChip (RTypeReader)
            Opcode::SUBW,
            // AddwChip (ALUTypeReader)
            Opcode::ADDW,
            // MulChip (RTypeReader)
            Opcode::MUL,
            Opcode::MULH,
            Opcode::MULHU,
            Opcode::MULHSU,
            Opcode::MULW,
            // DivRemChip (RTypeReader)
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
            Opcode::DIVW,
            Opcode::DIVUW,
            Opcode::REMW,
            Opcode::REMUW,
            // BitwiseChip (ALUTypeReader)
            Opcode::XOR,
            Opcode::OR,
            Opcode::AND,
            // ShiftLeftChip (ALUTypeReader)
            Opcode::SLL,
            Opcode::SLLW,
            // ShiftRightChip (ALUTypeReader)
            Opcode::SRL,
            Opcode::SRA,
            Opcode::SRLW,
            Opcode::SRAW,
            // LtChip (ALUTypeReader)
            Opcode::SLT,
            Opcode::SLTU,
        ];

        let reg_imm_ops = [
            // AddiChip (ITypeReader)
            Opcode::ADDI,
        ];

        let mut instructions = vec![];
        instructions.push(Instruction::new(Opcode::ADDI, 29, 0, 65, false, true));
        instructions.push(Instruction::new(Opcode::ADDI, 30, 0, 7, false, true));

        for op in reg_reg_ops {
            instructions.push(Instruction::new(op, 0, 29, 30, false, false));
        }

        for op in reg_imm_ops {
            instructions.push(Instruction::new(op, 0, 29, 7, false, true));
        }

        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
        let stdin = SP1Stdin::new();
        run_test(Arc::new(program.clone()), stdin.clone()).await.unwrap();
        run_test_small_trace(Arc::new(program), stdin).await.unwrap();
    }

    #[tokio::test]
    async fn test_non_alu_x0_prove() {
        setup_logger();

        let mut instructions = vec![];

        instructions.push(Instruction::new(Opcode::ADDI, 29, 0, 0x42, false, true));
        instructions.push(Instruction::new(Opcode::ADDI, 30, 0, 0x10, false, true));

        instructions.push(Instruction::new(Opcode::SW, 29, 0, 0x27654320, false, true));
        let load_ops =
            [Opcode::LB, Opcode::LH, Opcode::LW, Opcode::LBU, Opcode::LHU, Opcode::LWU, Opcode::LD];
        for op in load_ops {
            instructions.push(Instruction::new(op, 0, 0, 0x27654320, false, true));
        }

        instructions.push(Instruction::new(Opcode::BEQ, 0, 0, 8, false, true));
        instructions.push(Instruction::new(Opcode::ADDI, 28, 0, 0xFF, false, true));
        instructions.push(Instruction::new(Opcode::BNE, 0, 29, 8, false, true));
        instructions.push(Instruction::new(Opcode::ADDI, 28, 0, 0xFF, false, true));

        instructions.push(Instruction::new(Opcode::JAL, 0, 8, 0, true, true));
        instructions.push(Instruction::new(Opcode::ADDI, 28, 0, 0xFF, false, true));

        instructions.push(Instruction::new(Opcode::JAL, 27, 4, 0, true, true));
        instructions.push(Instruction::new(Opcode::JALR, 0, 27, 8, false, true));
        instructions.push(Instruction::new(Opcode::ADDI, 28, 0, 0xFF, false, true));

        instructions.push(Instruction::new(Opcode::LUI, 0, 0x12345000, 0x12345000, true, true));
        instructions.push(Instruction::new(Opcode::AUIPC, 0, 0x1000, 0x1000, true, true));

        add_halt(&mut instructions);
        let program = Program::new(instructions, 0, 0);
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
